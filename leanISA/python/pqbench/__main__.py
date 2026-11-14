from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

from Crypto.Hash import keccak

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "target" / "release" / "pq-leanbench"
MODULES = {"ethfalcon": "falcon", "ethdilithium": "dilithium", "fors": "fors"}


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def fixture(scheme, count):
    module = importlib.import_module("pqbench." + MODULES[scheme])
    started = time.perf_counter()
    data = module.build(count)
    metadata = data.setdefault("metadata", {})
    for key in ("count", "parameters", "signature_bytes", "public_key_bytes", "security_note"):
        if key in data:
            metadata.setdefault(key, data[key])
    metadata.setdefault("count", count)
    metadata["fixture_generation_s"] = time.perf_counter() - started
    return data


def check_sources():
    pins = json.loads((ROOT / "upstream.lock.json").read_text())
    for name, pin in pins.items():
        repo = str(ROOT / "vendor" / name)
        actual = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", repo, "status", "--porcelain"], text=True).strip()
        if actual != pin["rev"] or dirty:
            raise RuntimeError(f"{name}: need clean pinned source {pin['rev']}; run scripts/bootstrap.py")
    return pins


def dependency(statement, proof, expected_guest=None, expected_public_input=None):
    """Verify first, then encode this project's explicitly experimental dependency."""
    command = [str(RUNNER), "verify", "--input", str(statement), "--proof", str(proof)]
    if expected_guest:
        command.extend(["--expect-guest-hash", expected_guest])
    if expected_public_input:
        command.extend(["--expect-public-input", expected_public_input])
    checked = subprocess.run(command,
                             check=True, capture_output=True, text=True)
    verified = json.loads(checked.stdout)
    public = bytes.fromhex(verified["public_input_hex"])
    data_hash = keccak.new(data=public, digest_bits=256).digest()
    key_hash = bytes.fromhex(verified["guest_hash"])
    triple = bytes(31) + b"\x11" + data_hash + key_hash
    return {"kind": "experimental_eip_8288_variant", "requires_client_extension": True,
            "statement_pinned": verified["statement_pinned"],
            "draft_eip_8288_valid": False,
            "reason": "scheme 0x11 is reserved in the current draft; this is a local codec experiment",
            "backend_revision": verified["leanvm_revision"], "scheme_name": verified["scheme"],
            "scheme": "0x11", "data_hash": data_hash.hex(), "verification_key_hash": key_hash.hex(),
            "public_input_hex": public.hex(), "proof_file": str(Path(proof).resolve()),
            "statement_file": str(Path(statement).resolve()),
            "data_hash_definition": "Keccak256(public_input_bytes32)",
            "verification_key_hash_definition": "leanVM fs_seed(program), protocol tag and stacked bytecode commitment",
            "frame": {"mode": 4, "flags": 0, "target": None, "value": 0,
                      "limits": {"execution": 30000, "state": 0}, "data_hex": triple.hex()}}


def command(args):
    if args.command == "fixture":
        if args.replay:
            if args.scheme != "ethdilithium":
                raise ValueError("--replay currently accepts randomized ethDilithium measurements; other fixtures are deterministic")
            module = importlib.import_module("pqbench.dilithium")
            data = module.replay(json.loads(Path(args.replay).read_text()))
            if data["metadata"]["count"] != args.count:
                raise ValueError("--count must match the replayed measurement")
        else:
            data = fixture(args.scheme, args.count)
        write(args.out, data)
        print(args.out)
    elif args.command == "bench":
        out = Path(args.out)
        if out.exists() and any(out.iterdir()):
            raise ValueError("benchmark output directory must be empty; choose a fresh --out")
        out.mkdir(parents=True, exist_ok=True)
        pins = check_sources()
        host = {"platform": platform.platform(), "uname": list(platform.uname()),
                "logical_cpus": os.cpu_count(), "python": sys.version,
                "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "threads_env": os.environ.get("LEANVM_NUM_THREADS"),
                "upstream": pins}
        write(out / "environment.json", host)
        for scheme in args.schemes:
            for count in args.counts:
                label = f"{scheme}-{count}"
                input_path = ROOT / "artifacts" / args.name / (label + ".json")
                report_path = out / (label + ".json")
                proof_path = input_path.with_suffix(".proof")
                print(f"{args.mode}: {label}", flush=True)
                write(input_path, fixture(scheme, count))
                cmd = [str(RUNNER), args.mode, "--input", str(input_path), "--report", str(report_path),
                       "--repeat", str(args.repeat), "--warmup", str(args.warmup), "--rate", str(args.rate)]
                if args.mode == "prove":
                    cmd.extend(["--proof", str(proof_path)])
                # Separate processes give each workload its own memory high-water mark.
                completed = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout)
                (out / (label + ".log")).write_text(completed.stdout + completed.stderr)
                if completed.returncode:
                    write(out / (label + ".failed.json"), {"status": "failed", "scheme": scheme, "count": count,
                                                           "action": args.mode, "returncode": completed.returncode,
                                                           "error": completed.stderr.strip()})
                    if args.continue_on_error:
                        continue
                    if any(out.glob("*-*.json")):
                        report(out)
                    raise RuntimeError(f"{label} failed; inspect {out / (label + '.log')}")
                data = json.loads(report_path.read_text())
                print(f"  {data['cycles']:,} VM steps", flush=True)
        report(out)
    elif args.command == "report":
        report(Path(args.directory))
    elif args.command == "dependency":
        data = dependency(args.statement, args.proof, args.expect_guest_hash, args.expect_public_input)
        write(args.out, data)
        print(args.out)
    elif args.command == "project":
        data = json.loads(Path(args.measurement).read_text())
        count = data["metadata"]["count"]
        if "prove_s" not in data:
            raise ValueError("projection requires measured proving times")
        leaves = (args.total + count - 1) // count
        leaf_s = statistics.median(data["prove_s"])
        result = {"kind": "projection_not_measurement", "signatures": args.total,
                  "leaf_capacity": count, "leaves": leaves,
                  "leaf_prover_work_s": leaves * leaf_s,
                  "assumption": "all leaves cost the measured full batch, including the last partial batch; excludes networking and scheduling"}
        if args.merge_seconds is not None:
            result.update({"assumed_binary_merges": max(0, leaves - 1),
                           "assumed_merge_s": args.merge_seconds,
                           "projected_total_prover_work_s": leaves * leaf_s + max(0, leaves - 1) * args.merge_seconds,
                           "warning": "projection uses a user-assumed binary merge cost, not measured tree aggregation; actual bounded-tree experiments are recorded separately under results/article",
                           "actual_experiment_workflow": "scripts/article_bench.py trees; docs/tree-format.md"})
        print(json.dumps(result, indent=2))


def report(directory):
    rows = []
    failures = []
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text())
        if data.get("status") == "failed":
            failures.append(data)
        if "cycles" not in data:
            continue
        count = data.get("metadata", {}).get("count", 1)
        times = data.get("prove_s", [])
        duration = statistics.median(times) if times else None
        sizes = data.get("proof_bytes_samples", [])
        cached_path = path.with_suffix(".verify.json")
        cached = json.loads(cached_path.read_text()) if cached_path.exists() else {}
        if cached and (cached["guest_hash"] != data["guest_hash"] or cached["public_input_hex"] != data["public_input_hex"]):
            raise ValueError("cached verification report belongs to another statement: " + str(cached_path))
        rows.append({"scheme": data["scheme"], "count": count, "cycles": data["cycles"],
                     "prove_s": duration, "prove_min_s": min(times) if times else None,
                     "prove_max_s": max(times) if times else None,
                     "verify_ms": statistics.median(data["verify_s"]) * 1000 if "verify_s" in data else None,
                     "verify_cached_ms": statistics.median(cached["verify_cached_s"]) * 1000 if cached else None,
                     "bytecode_prepare_ms": cached.get("bytecode_prepare_s", 0) * 1000 if cached else None,
                     "proof_bytes": statistics.median(sizes) if sizes else data.get("proof_bytes"),
                     "rss_gib": data["process_peak_rss_bytes"] / 2 ** 30,
                     "signatures_per_s": count / duration if duration else None})
    rows.sort(key=lambda r: (r["scheme"], r["count"]))
    if not rows:
        raise ValueError("no successful measurements")
    write(directory / "summary.json", {"rows": rows, "failures": failures})
    lines = ["# Measured signature verification in leanVM", "",
             "Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.", "",
             "| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda x, digits=3: f"{x:.{digits}f}" if x is not None else "unmeasured"
    for r in rows:
        lines.append(f"| {r['scheme']} | {r['count']} | {r['cycles']:,} | {fmt(r['prove_s'])} | {fmt(r['verify_ms'])}/{fmt(r['verify_cached_ms'])} | {fmt(r['proof_bytes'] / 1024 if r['proof_bytes'] else None, 1)} | {fmt(r['rss_gib'], 2)} | {fmt(r['signatures_per_s'], 1)} |")
    lines += ["", "Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.", ""]
    if failures:
        lines += ["Unsupported or failed workloads:", ""]
        lines += [f"- {failure['scheme']}, N={failure['count']}: {failure['error']}" for failure in failures]
        lines.append("")
    (directory / "REPORT.md").write_text("\n".join(lines))
    print(directory / "REPORT.md")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("fixture")
    p.add_argument("--scheme", choices=MODULES, required=True)
    p.add_argument("--count", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--replay", help="rebuild exact ethDilithium inputs from saved benchmark JSON")
    p = sub.add_parser("bench")
    p.add_argument("--schemes", nargs="+", choices=MODULES, default=list(MODULES))
    p.add_argument("--counts", nargs="+", type=int, default=[1])
    p.add_argument("--mode", choices=["execute", "prove"], default="prove")
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--warmup", type=int, default=1)
    p.add_argument("--rate", type=int, choices=range(1, 5), default=1)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--continue-on-error", action="store_true")
    p.add_argument("--name", default="benchmark")
    p.add_argument("--out", default="results/local")
    p = sub.add_parser("report")
    p.add_argument("directory")
    p = sub.add_parser("dependency")
    p.add_argument("--statement", required=True)
    p.add_argument("--proof", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--expect-guest-hash")
    p.add_argument("--expect-public-input")
    p = sub.add_parser("project")
    p.add_argument("measurement")
    p.add_argument("--total", type=int, required=True)
    p.add_argument("--merge-seconds", type=float)
    args = parser.parse_args()
    if args.command in ("bench", "fixture"):
        if any(n < 1 for n in (args.counts if args.command == "bench" else [args.count])):
            parser.error("signature counts must be positive")
    if args.command == "project" and (args.total < 1 or (args.merge_seconds is not None and args.merge_seconds < 0)):
        parser.error("total must be positive and merge time nonnegative")
    command(args)


if __name__ == "__main__":
    main()
