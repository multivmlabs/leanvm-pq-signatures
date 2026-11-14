#!/usr/bin/env python3
"""Authenticate immutable public setup bytes before they enter the trusted ELF."""
import hashlib
import json
import argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def check_setup(terminal_cache=False):
    checks = json.loads((HERE / "trusted-setup-sha256.json").read_text())
    if terminal_cache:
        checks.update(json.loads((HERE / "trusted-cache-sha256.json").read_text()))
    for name, expected in checks.items():
        path = ROOT / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"missing or changed pinned public setup: {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal-cache", action="store_true")
    check_setup(parser.parse_args().terminal_cache)
