#!/usr/bin/env python3
"""Recheck saved proofs and measure cached and uncached verification separately."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--results", required=True)
parser.add_argument("--artifacts", required=True)
args = parser.parse_args()
directory = Path(args.results)
for path in sorted(directory.glob("*.json")):
    expected = json.loads(path.read_text())
    if expected.get("action") != "prove" or not expected.get("verified"):
        continue
    proof = Path(args.artifacts) / (path.stem + ".proof")
    command = [str(ROOT / "target/release/pq-leanbench"), "verify", "--input", str(proof) + ".statement.json",
               "--proof", str(proof), "--repeat", "3", "--warmup", "1"]
    output = subprocess.run(command, check=True, capture_output=True, text=True)
    checked = json.loads(output.stdout)
    for field in ("guest_hash", "public_input_hex", "proof_bytes"):
        if checked[field] != expected[field]:
            raise SystemExit(f"{path}: verification statement differs on {field}")
    destination = path.with_suffix(".verify.json")
    destination.write_text(json.dumps(checked, indent=2) + "\n")
    print(destination)
