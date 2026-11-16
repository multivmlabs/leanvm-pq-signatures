#!/usr/bin/env python3
"""Fetch exact article dependencies, or check existing copies with --check."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", action="store_true", help="Validate pins without fetching")
args = parser.parse_args()

for name, pin in json.loads((ROOT / "upstream.lock.json").read_text()).items():
    destination = ROOT / pin.get("path", "vendor/" + name)
    if destination.exists():
        actual = subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], text=True).strip()
        if actual != pin["rev"]:
            raise SystemExit(f"{name}: expected {pin['rev']}, found {actual}; preserve and relocate the existing checkout")
        if subprocess.check_output(["git", "-C", str(destination), "status", "--porcelain"], text=True).strip():
            raise SystemExit(f"{name}: checkout is dirty; use a clean pinned checkout")
        print(f"{name}: pinned checkout present")
        continue
    if args.check:
        raise SystemExit(f"Missing {name}; run python3 scripts/bootstrap.py")
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(destination)], check=True)
    subprocess.run(["git", "-C", str(destination), "remote", "add", "origin", pin["url"]], check=True)
    subprocess.run(["git", "-C", str(destination), "fetch", "--depth", "1", "origin", pin["rev"]], check=True)
    subprocess.run(["git", "-C", str(destination), "checkout", "--detach", "FETCH_HEAD"], check=True)
