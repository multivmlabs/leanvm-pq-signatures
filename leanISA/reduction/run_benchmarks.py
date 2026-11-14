#!/usr/bin/env python3
"""Fresh reduced leanISA FORS trees, sequential proving and isolated public receivers."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "leanISA/reduction"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", nargs="+", type=int, default=[10, 30, 70, 100])
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path, default=HERE / "results/trees")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.samples < 1 or any(n not in (10, 30, 70, 100) for n in args.counts):
        parser.error("positive samples and declared counts 10,30,70,100 required")
    binary = ROOT / "target/release/leanisa-reduced-tree"
    binary_hash = sha(binary)
    approved = json.loads((ROOT / "leanISA/results/article/direct/fors-5.json").read_text())["guest_hash"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = [p for p in (HERE / "src").glob("*.rs")]
    source += [HERE / "guest/sumcheck.py", HERE / "Cargo.toml", HERE / "Cargo.lock", Path(__file__)]
    metadata = {"schema": 1, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "backend_revision": "575df819d9c857f38068cecf7b1640e0ce4bfb29",
                "host_binary_sha256": binary_hash, "approved_leaf_guest_hash": approved,
                "counts": args.counts, "samples": args.samples, "leaf_size": 5, "arity": 2,
                "threads_env": os.environ.get("LEANVM_NUM_THREADS"),
                "allocator": "unchanged upstream bench::Jemalloc",
                "sampling": "Three fresh pipelines in separate processes, no proving warmup or cross-sample proof reuse",
                "proving_work": "All fresh leaves + native child verification/advice + native sumcheck generation + every constrained wrapper STARK",
                "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in source}}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for count in args.counts:
        cfg = output / f"fors-{count}"
        cfg.mkdir(parents=True, exist_ok=True)
        public = cfg / "public.json"
        if not public.exists():
            subprocess.run([str(ROOT / ".venv/bin/python"), str(HERE / "prepare_fors.py"),
                            "--count", str(count), "--out", str(cfg)], cwd=ROOT, check=True)
        plan_path = cfg / "plan.json"
        subprocess.run([str(binary), "plan", "--public", str(public), "--out", str(plan_path)], cwd=ROOT, check=True)
        plan = json.loads(plan_path.read_text())
        if plan["leaf_guest_hash"] != approved:
            raise RuntimeError("The signature guest differs from the approved unchanged FORS verifier")
        public_hash = sha(public)
        for sample in range(args.samples):
            name = f"sample-{sample}"
            directory = cfg / name
            completed = directory / "completed.json"
            if completed.exists() and args.resume:
                old = json.loads(completed.read_text())
                if old.get("host_binary_sha256") == binary_hash and old.get("verified_public_only") is True:
                    print(f"Preserved FORS N={count} sample={sample}", flush=True)
                    continue
                raise RuntimeError("Cannot resume mismatched sample")
            if directory.exists():
                raise RuntimeError(f"Refusing existing sample: {directory}")
            cmd = [str(binary), "prove", "--public", str(public), "--inputs", str(cfg), "--out", str(directory)]
            start = time.monotonic()
            print(f"Starting reduced FORS N={count} sample={sample}", flush=True)
            with (cfg / f"{name}.stdout.log").open("w") as stdout, (cfg / f"{name}.stderr.log").open("w") as stderr:
                subprocess.run(cmd, cwd=ROOT, stdout=stdout, stderr=stderr, check=True)
            with tempfile.TemporaryDirectory(prefix="leanisa-reduced-receiver-", dir="/tmp") as temp:
                temp = Path(temp)
                shutil.copyfile(public, temp / "public.json")
                shutil.copyfile(directory / "root.proof", temp / "root.proof")
                consumer = [str(binary), "verify", "--public", str(temp / "public.json"),
                            "--proof", str(temp / "root.proof"), "--expect-public-sha256", public_hash,
                            "--expect-leaf-guest-hash", approved, "--out", str(directory / "verification.json")]
                with (directory / "receiver.log").open("w") as log:
                    subprocess.run(consumer, cwd=temp, stdout=log, stderr=log, check=True)
            check = json.loads((directory / "verification.json").read_text())
            if not check["verified"] or not check["all_reduced_claims_settled"]:
                raise RuntimeError("Incomplete root verification")
            record = {"schema": 1, "signatures": count, "sample": sample, "producer_command": cmd,
                      "consumer_command": consumer, "host_binary_sha256": binary_hash,
                      "public_sha256": public_hash, "approved_leaf_guest_hash": approved,
                      "root_proof_sha256": sha(directory / "root.proof"), "verified_public_only": True,
                      "receiver_files": ["public.json", "root.proof"], "process_elapsed_s": time.monotonic() - start}
            completed.write_text(json.dumps(record, indent=2) + "\n")
            report = json.loads((directory / "report.json").read_text())
            print(f"Finished FORS N={count} sample={sample}: prove={report['total_prove_s']:.3f}s, "
                  f"root={report['root_proof_bytes']}B, reduced_checks={check['terminal_evaluations']}", flush=True)


if __name__ == "__main__":
    main()
