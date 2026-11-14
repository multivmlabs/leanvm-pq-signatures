#!/usr/bin/env python3
"""Run the unmodified pinned leanSPHINCS/recursive CLI as a reference workload."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--counts", nargs="+", type=int, default=[1, 16, 64, 256])
parser.add_argument("--repeat", type=int, default=3)
parser.add_argument("--recursion", action="store_true")
parser.add_argument("--out", default="results/upstream")
args = parser.parse_args()
out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
binary = ROOT / "vendor/leanVM/target/release/leanvm"
subprocess.run(["cargo", "build", "--release", "--locked", "-p", "leanvm-cli"], cwd=ROOT / "vendor/leanVM", check=True)
jobs = [(f"leansphincs-{n}", ["aggregate", "--sphincs", str(n)]) for n in args.counts]
if args.recursion:
    jobs.append(("leansphincs-2-to-1", ["recursion", "--n", "2", "--xmss-per-leaf", "0", "--sphincs-per-leaf", "16"]))
for name, workload in jobs:
    cmd = [str(binary), *workload, "--repeat", str(args.repeat), "--cooldown", "0", "--log-inv-rate", "1"]
    print(" ".join(cmd), flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    (out / (name + ".log")).write_text(result.stdout + result.stderr)
    (out / (name + ".command.json")).write_text(json.dumps({"command": cmd, "threads_env": os.getenv("LEANVM_NUM_THREADS"),
                                                            "kind": "upstream_reference_not_custom_scheme_recursion",
                                                            "exit_code": result.returncode}, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(f"{name} failed; inspect saved log")
