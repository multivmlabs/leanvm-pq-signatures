#!/usr/bin/env python3
"""Run fresh RISC-V signature-tree pipelines sequentially and retain raw evidence.

This runner never estimates missing measurements. Completed sample directories
are preserved; pass --resume to skip them after an interrupted matrix.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schemes", nargs="+", choices=("falcon", "mldsa"), default=["falcon", "mldsa"])
    parser.add_argument("--counts", nargs="+", type=int, default=[10, 30, 70, 100])
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "risc-v/results/trees")
    parser.add_argument("--binary", type=Path, default=ROOT / ".cache/riscv-host-target/release/riscv-pq-treebench")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.samples < 1 or any(n not in (10, 30, 70, 100) for n in args.counts):
        parser.error("positive samples and the declared counts 10, 30, 70, 100 are required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve()
    binary_sha256 = digest(binary)
    env = os.environ.copy()
    env["LEANVM_NUM_THREADS"] = "8"
    for scheme in args.schemes:
        for count in args.counts:
            leaf_size = 10 if scheme == "falcon" else 2
            configuration = output / f"{scheme}-{count}"
            configuration.mkdir(parents=True, exist_ok=True)
            statement = configuration / "statement.json"
            if not statement.exists():
                command = [str(binary), "plan", "--scheme", scheme, "--n", str(count),
                           "--leaf-size", str(leaf_size), "--outdir", str(configuration),
                           "--threads", "8", "--rate", "1"]
                with (configuration / "plan.stdout.log").open("w") as stdout, (configuration / "plan.stderr.log").open("w") as stderr:
                    subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, check=True)
            intended = json.loads(statement.read_text())
            statement_sha256 = digest(statement)
            if intended["scheme"] != scheme or intended["signatures"] != count or intended["leaf_size"] != leaf_size:
                raise RuntimeError(f"Prepared statement differs from matrix: {configuration}")
            for sample in range(args.samples):
                sample_name = f"sample-{sample}"
                directory = configuration / sample_name
                completed = directory / "pipeline-completed.json"
                if completed.exists() and args.resume:
                    previous = json.loads(completed.read_text())
                    if previous.get("exit_code") == 0 and previous.get("binary_sha256") == binary_sha256:
                        print(f"Preserved completed {scheme} N={count} sample={sample}", flush=True)
                        continue
                    raise RuntimeError(f"Cannot resume mismatched sample: {directory}")
                if directory.exists() and any(directory.iterdir()):
                    raise RuntimeError(f"Refusing to overwrite sample: {directory}")
                command = [str(binary), "prove", "--scheme", scheme, "--n", str(count),
                           "--leaf-size", str(leaf_size), "--outdir", str(configuration), "--sample", sample_name,
                           "--threads", "8", "--rate", "1"]
                record = {"schema": 1, "scheme": scheme, "distinct_signatures": count,
                          "sample": sample, "command": command, "binary_sha256": binary_sha256,
                          "statement_sha256": statement_sha256, "elf_sha256": intended["elf_sha256"],
                          "runner_sha256": digest(Path(__file__)),
                          "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          "sampling": "One complete fresh pipeline in a fresh process; no in-process warmup or proof reuse across samples"}
                (configuration / f"{sample_name}.pipeline-started.json").write_text(json.dumps(record, indent=2) + "\n")
                print(f"Starting {scheme} N={count} sample={sample}", flush=True)
                start = time.monotonic()
                with (configuration / f"{sample_name}.producer.stdout.log").open("w") as stdout, (configuration / f"{sample_name}.producer.stderr.log").open("w") as stderr:
                    result = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
                record.update(exit_code=result.returncode, process_elapsed_s=time.monotonic() - start,
                              finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
                if result.returncode == 0:
                    consumer = [str(binary), "verify", "--outdir", str(directory),
                                "--statement", str(statement), "--proof", str(directory / "root.proof"),
                                "--expect-statement-sha256", statement_sha256,
                                "--expect-elf-sha256", intended["elf_sha256"], "--threads", "8"]
                    record["consumer_command"] = consumer
                    with (directory / "consumer.stdout.log").open("w") as stdout, (directory / "consumer.stderr.log").open("w") as stderr:
                        checked = subprocess.run(consumer, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
                    record["consumer_exit_code"] = checked.returncode
                    if checked.returncode:
                        record["exit_code"] = checked.returncode
                    else:
                        verification = json.loads((directory / "verification.json").read_text())
                        if verification.get("verified") is not True or verification.get("all_folded_claims_settled") is not True:
                            raise RuntimeError(f"Consumer did not verify every claim: {directory}")
                        record["public_only_verified"] = True
                directory.mkdir(parents=True, exist_ok=True)
                completed.write_text(json.dumps(record, indent=2) + "\n")
                print(f"Finished {scheme} N={count} sample={sample}: exit={result.returncode}, {record['process_elapsed_s']:.2f}s", flush=True)
                if record["exit_code"]:
                    raise RuntimeError(f"Pipeline failed; see {directory}")


if __name__ == "__main__":
    main()
