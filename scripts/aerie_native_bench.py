#!/usr/bin/env python3
"""Measure the pinned, unmodified native Aerie harness. This is not leanVM proving."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/aerie"
RESULTS = ROOT / "results/aerie/native"
ARTIFACTS = ROOT / "artifacts/aerie"
COUNTS = [1, 10, 30, 70, 100, 1024, 8192, 32768]
REVISION = "49b6c212c209286c536196f53618823ffdf0e899"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def git(*args):
    return subprocess.run(["git", *args], cwd=VENDOR, text=True, capture_output=True, check=True).stdout.strip()


def parse(stdout, stderr):
    """Parse schema8 TSV and independent stderr byte buckets without guessing units."""
    metadata, rows, shapes, columns = {}, [], [], None
    for line in stdout.splitlines():
        if line.startswith("# batch_shape\t"):
            shapes.append(dict(item.split("=", 1) for item in line.split("\t")[1:]))
        elif line.startswith("# ") and "\t" in line:
            name, value = line[2:].split("\t", 1)
            metadata[name] = value
        elif line.startswith("records\t"):
            columns = line.split("\t")
        elif line and not line.startswith("#"):
            if columns is None:
                raise ValueError("numeric row precedes TSV header")
            fields = line.split("\t")
            if len(fields) != len(columns):
                raise ValueError("TSV row/header length mismatch")
            row = {}
            for name, value in zip(columns, fields):
                row[name] = (value if name == "commit_groups_ms" else
                             float(value) if name.endswith("_ms") else int(value))
            rows.append(row)
    buckets = [dict(re.findall(r"(records|salt_mode|salts_bytes|header_piop_bytes|pcs_bytes)=([^ ]+)", line))
               for line in stderr.splitlines() if line.startswith("# byte_breakdown records=")]
    if metadata.get("benchmark_schema") != "8" or len(rows) != len(shapes) or len(rows) != len(buckets):
        raise ValueError("unexpected benchmark schema or incomplete outputs")
    for row, shape, bucket in zip(rows, shapes, buckets):
        assert row["records"] == int(shape["live"]) == int(bucket["records"])
        row["padded_records"] = int(shape["padded"])
        for name in ("salts_bytes", "header_piop_bytes", "pcs_bytes"):
            row[name] = int(bucket[name])
        assert row["envelope_bytes"] == sum(row[name] for name in ("salts_bytes", "header_piop_bytes", "pcs_bytes"))
        assert row["salts_bytes"] == 40 * row["records"]
        assert row["pcs_bytes"] == row["commitment_bytes"] + 8 + row["pcs_proof_bytes"]
    rss = re.search(r"# process_peak_rss_bytes\t(\d+)", stderr)
    return metadata, rows, int(rss.group(1)) if rss else None


def run(binary, args, name, threads):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    log = RESULTS / f"{name}.stdout.tsv"
    err = RESULTS / f"{name}.stderr.log"
    RESULTS.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "AERIE_HONEST_FIXTURE_DIR": str(ARTIFACTS / "honest-fixtures"),
           "RAYON_NUM_THREADS": str(threads)}
    # A fresh wrapper resets RUSAGE_CHILDREN per case. macOS /usr/bin/time -l
    # tries a sandbox-denied kern.clockrate sysctl after the child succeeds.
    wrapper = """import resource, subprocess, sys
result = subprocess.run(sys.argv[1:])
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != 'darwin': rss *= 1024
print('# process_peak_rss_bytes\\t' + str(rss), file=sys.stderr)
sys.exit(result.returncode)
"""
    command = [sys.executable, "-c", wrapper, str(binary), *map(str, args)]
    started = time.perf_counter()
    with log.open("w") as out, err.open("w") as errors:
        done = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=errors, timeout=7200)
    wall = time.perf_counter() - started
    if done.returncode:
        raise RuntimeError(f"native Aerie process failed ({done.returncode}); see {err}")
    return command, log, err, wall


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["generate", "bench", "all"])
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--counts", nargs="+", type=int, default=COUNTS)
    parser.add_argument("--threads", nargs="+", type=int, default=[1, 12])
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=1)
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), "build the pinned upstream native bench first"
    assert git("rev-parse", "HEAD") == REVISION, "unexpected Aerie revision"
    assert not git("status", "--porcelain"), "preserve a clean upstream checkout"
    if args.action in ("generate", "all"):
        print("Generating deterministic public benchmark fixtures (outside timing)", flush=True)
        command, stdout, stderr, wall = run(binary, [*args.counts, "--generate-honest-fixtures-only"],
                                             "fixture-generation", max(args.threads))
        save(RESULTS / "fixture-generation.json", {"command": command, "process_elapsed_s": wall,
             "generation_performed": "# generated honest fixture:" in stderr.read_text(),
             "scope": "Fixture acquisition/cache check, with reference FN-DSA keygen/sign and validation only for missing fixtures; excluded from prove/verify times; benchmark keys only",
             "stdout_sha256": sha256(stdout), "stderr_sha256": sha256(stderr)})
    if args.action not in ("bench", "all"):
        return
    for threads in args.threads:
        for count in args.counts:
            name = f"falcon512-n{count}-t{threads}"
            report = RESULTS / f"{name}.json"
            if report.exists() and json.loads(report.read_text()).get("all_roundtrips_passed"):
                continue
            print(f"NATIVE Aerie Falcon512 N={count} threads={threads}", flush=True)
            command, stdout, stderr, wall = run(binary, [count] * (args.warmup + args.repeat), name, threads)
            metadata, rows, rss = parse(stdout.read_text(), stderr.read_text())
            assert len(rows) == args.warmup + args.repeat
            assert rss is not None
            assert int(metadata["rayon_threads"]) == threads
            samples = rows[args.warmup:]
            summary = {name: {"median": statistics.median(row[name] for row in samples),
                              "min": min(row[name] for row in samples),
                              "max": max(row[name] for row in samples)}
                       for name in samples[0] if name.endswith("_ms") and name != "commit_groups_ms"}
            save(report, {"schema_version": 1, "kind": "native Aerie, not leanVM",
                 "all_roundtrips_passed": True, "aerie_revision": REVISION, "metadata": metadata,
                 "actual_records": count, "padded_records": samples[0]["padded_records"],
                 "worker_threads": threads, "warmup_passes": args.warmup, "measured_passes": args.repeat,
                 "warmups": rows[:args.warmup], "samples": samples, "summary_ms": summary,
                 "process_peak_rss_bytes": rss, "process_elapsed_s": wall, "command": command,
                 "rss_measurement": "Fresh Python wrapper getrusage(RUSAGE_CHILDREN), macOS reports bytes; whole native process including setup/warmup",
                 "source_sha256": {str(stdout.relative_to(ROOT)): sha256(stdout),
                                   str(stderr.relative_to(ROOT)): sha256(stderr),
                                   str(binary.relative_to(ROOT)): sha256(binary)},
                 "timing_scope": "Upstream unmodified harness: prove starts from canonical records and includes native checking, witness construction and wire encoding; fixture acquisition and reusable setup excluded. Verification starts with an already canonical-parsed public statement; includes proof decoding, hashed-key derivation, streamed key/target evaluation, binding, stages and Akita; canonical public-statement parse and setup excluded. HashToPoint timer also includes target field contraction, not SHAKE alone. Prover phase intervals can overlap; use total prove_ms rather than their sum. Upstream timing fields rounded to0.1ms.",
                 "sample_scope": "Requested warmup rows followed by measured fresh proof roundtrips in a fresh process per N/thread setting; per-pass shape setup timed separately. Verification uses selected Rayon pool and a dedicated one-thread pool. RSS is whole process including setup/warmup.",
                 "relation": "Falcon v1.2 padded, fn-dsa0.3.0, empty context/raw mode, key-prefixed SHAKE256 framing; not the earlier round3/ETH corpus.",
                 "fixture_scope": "Deterministic fn-dsa test keypairs; distinct keys, signatures, salts and ASCII messages validated by upstream harness; not production secret material. Sizes exclude public keys/messages."})
            print(f"  prove={summary['prove_ms']['median']:.1f}ms; verify1={summary['verify_single_thread_ms']['median']:.1f}ms; wire={samples[0]['envelope_bytes']}B", flush=True)


if __name__ == "__main__":
    main()
