#!/usr/bin/env python3
"""Record the source and executable identities of the full verifier experiment."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "aerie": "49b6c212c209286c536196f53618823ffdf0e899",
    "leanVM-riscv": "06e5c9cd6981103786f9d0a17324241b559a50d3",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "results/aerie-wrapper/provenance.json")
    args = parser.parse_args()
    sources = {}
    for directory in ("aerie-port", "aerie-leanvm-guest", "aerie-leanvm-host", "aerie-wrapper-format", "aerie-wrapper-inputs", "aerie-selected-check", "aerie-q64-cache-check"):
        for path in sorted((ROOT / "experiments" / directory).rglob("*")):
            if path.is_file() and path.suffix in (".rs", ".toml", ".lock", ".py", ".ld", ".json", ".aks", ".bin", ".patch") and "target" not in path.parts:
                sources[str(path.relative_to(ROOT))] = digest(path)
    for name in ("aerie_wrapper_bench.py", "aerie_wrapper_figures.py", "aerie_wrapper_provenance.py", "aerie_wrapper_profile.py"):
        path = ROOT / "scripts" / name
        if path.is_file():
            sources[str(path.relative_to(ROOT))] = digest(path)
    checkouts = {}
    for name, expected in PINS.items():
        path = ROOT / "vendor" / name
        actual = command("git", "-C", str(path), "rev-parse", "HEAD")
        dirty = command("git", "-C", str(path), "status", "--porcelain")
        if actual != expected or dirty:
            raise SystemExit(f"{name}: clean pinned checkout required")
        checkouts[name] = {"revision": actual, "clean": True,
                           "cargo_lock_sha256": digest(path / "Cargo.lock")}
    setup, terminal_cache = {}, {}
    for count in (1, 10, 30, 70, 100):
        path = ROOT / "artifacts/aerie-wrapper/public-setup" / f"n{count}" / "setup.bin"
        setup[str(count)] = {"bytes": path.stat().st_size, "sha256": digest(path)}
        cache = ROOT / "artifacts/aerie-wrapper/q64-cache" / f"n{count}" / "terminal-cache.bin"
        terminal_cache[str(count)] = {"bytes": cache.stat().st_size, "sha256": digest(cache)}
    report = {
        "scope": "Source and artifact identities. This manifest is not an outer proof or a security audit.",
        "checkouts": checkouts,
        "source_sha256": sources,
        "public_setup": setup,
        "trusted_terminal_cache": terminal_cache,
        "executables": {name: {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest(path)}
                        for name, path in (("guest", args.elf), ("host", args.host), ("producer", args.producer))},
        "native_rustc": command("rustc", "+stable", "--version", "--verbose"),
        "guest_rustc": command("rustc", "+nightly-2026-10-03", "--version", "--verbose"),
        "machine": command("uname", "-a"),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(args.out)


if __name__ == "__main__":
    main()
