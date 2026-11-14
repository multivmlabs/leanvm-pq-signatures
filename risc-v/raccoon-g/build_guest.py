#!/usr/bin/env python3
"""Build the pinned strict Raccoon-G HD-wallet PoC verifier; no proving."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS = {
    "vendor/leanVM-riscv": "06e5c9cd6981103786f9d0a17324241b559a50d3",
    "risc-v/raccoon-g/sources/lattice-hd-wallets": "461a5ed9b6d57e3bf8c381be3bb79325ab21d906",
}


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def main():
    for directory, expected in PINS.items():
        actual = command("git", "-C", str(ROOT / directory), "rev-parse", "HEAD")
        if actual != expected:
            raise SystemExit(f"wrong {directory} revision: {actual}")
        if command("git", "-C", str(ROOT / directory), "status", "--porcelain"):
            raise SystemExit(f"modified reference checkout: {directory}")
    env = os.environ.copy()
    env.setdefault("CARGO_HOME", str(ROOT / ".cache/riscv-cargo"))
    subprocess.run(["cargo", "+nightly-2026-10-03", "build", "--release", "--offline", "--locked"], cwd=HERE / "guest", env=env, check=True)
    elf = HERE / "guest/target/riscv64im-unknown-none-elf/release/raccoong-riscv-guest"
    shutil.copyfile(elf, HERE / "raccoong.elf")
    paths = [p for subdirectory in ("guest", "host") for p in (HERE / subdirectory).rglob("*")
             if p.is_file() and "target" not in p.parts and p.suffix not in (".elf", ".json", ".bin")]
    paths += [HERE / "build_guest.py"]
    if (HERE / "generate_fixtures.py").exists():
        paths += [HERE / "generate_fixtures.py"]
    reference = HERE / "sources/lattice-hd-wallets/src/raccoon/thrc-py"
    paths += sorted(reference.glob("*.py"))
    paths += [ROOT / "vendor/leanVM-riscv/sdk/src/keccak.rs"]
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {
        "schema": 1,
        "profile": "raccoong-hd-authors-poc-strict-v1",
        "paper_conformance": "pending full-paper comparison",
        "backend_pins": PINS,
        "guest_rustc": command("rustc", "+nightly-2026-10-03", "--version", "--verbose"),
        "elf": "risc-v/raccoon-g/raccoong.elf",
        "elf_bytes": elf.stat().st_size,
        "elf_sha256": sha(elf),
        "norm_squared": "25650475979193785709999263840",
        "norm_policy": "floor of high-precision source bound squared; does not emulate binary64 boundary rounding",
        "keccak_kernel": "leanvm_sdk_software_f1600",
        "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(paths))},
        "correctness_fixture_sha256": {
            str(p.relative_to(ROOT)): sha(p) for p in sorted((HERE / "host/testdata").glob("*.json"))
        },
    }
    certificate = HERE / "review/norm-bound-certificate.json"
    if certificate.is_file():
        norm = json.loads(certificate.read_text())
        if norm["integer_threshold"] != manifest["norm_squared"]:
            raise SystemExit("norm certificate differs from the frozen guest profile")
        manifest["norm_certificate_sha256"] = sha(certificate)
    (HERE / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k:manifest[k] for k in ("elf", "elf_bytes", "elf_sha256")}, indent=2))


if __name__ == "__main__":
    main()
