#!/usr/bin/env python3
"""Build and identify the separate segmented Raccoon-G executable."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    "vendor/leanVM-riscv": "06e5c9cd6981103786f9d0a17324241b559a50d3",
    "risc-v/raccoon-g/sources/lattice-hd-wallets": "461a5ed9b6d57e3bf8c381be3bb79325ab21d906",
}


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    for directory, expected in PINS.items():
        path = ROOT / directory
        if command("git", "-C", str(path), "rev-parse", "HEAD") != expected:
            raise SystemExit(f"wrong source revision: {directory}")
        if command("git", "-C", str(path), "status", "--porcelain"):
            raise SystemExit(f"modified source checkout: {directory}")
    original_path = ROOT / "risc-v/raccoon-g/build-manifest.json"
    original = json.loads(original_path.read_text())
    for source, expected in original["source_sha256"].items():
        if sha(ROOT / source) != expected:
            raise SystemExit(f"original signature implementation changed: {source}")
    env = os.environ.copy()
    env.setdefault("CARGO_HOME", str(ROOT / ".cache/riscv-cargo"))
    subprocess.run(["cargo", "+nightly-2026-10-03", "build", "--release", "--locked", "--offline"],
                   cwd=HERE / "guest", env=env, check=True)
    elf = HERE / "guest/target/riscv64im-unknown-none-elf/release/raccoong-segmented-guest"
    shutil.copyfile(elf, HERE / "raccoong-segmented.elf")
    paths = [path for name in ("guest", "host") for path in (HERE / name).rglob("*")
             if path.is_file() and not {"target", "__pycache__", ".cache"}.intersection(path.relative_to(HERE).parts)
             and path.suffix not in (".elf", ".json", ".bin")]
    paths += [HERE / "build_guest.py", HERE / "generate_controls.py", original_path]
    paths += [ROOT / source for source in original["source_sha256"]]
    paths += list((ROOT / "vendor/leanVM-riscv/sdk/src").rglob("*.rs"))
    manifest = {
        "schema": 1,
        "profile": "raccoong-strict-segmented-two-rows-uniform-v1",
        "signature_relation": "unchanged raccoong-hd-authors-poc-strict-v1",
        "paper_conformance": "pending full-paper comparison",
        "backend_pins": PINS,
        "guest_rustc": command("rustc", "+nightly-2026-10-03", "--version", "--verbose"),
        "elf": str((HERE / "raccoong-segmented.elf").relative_to(ROOT)),
        "elf_sha256": sha(elf),
        "elf_bytes": elf.stat().st_size,
        "parts_per_signature": 5,
        "rows_per_part": 2,
        "row_pairs": [[0,1],[2,3],[4,5],[6,7],[8,8]],
        "binding_bytes_per_signature": 64,
        "trace_normalization": {
            "volatile_u64_store_count": 32768,
            "phase": "after all checks and public-value commits, before guest return",
            "destination": "disjoint naturally aligned local scratch; no reads",
            "policy": "unconditional fixed count; all executed work charged; no signature-check change",
        },
        "binding_codec": "two separated SDK BLAKE2s hashes of framed full signature and canonical complete LE16 commitment",
        "source_sha256": {str(path.relative_to(ROOT)): sha(path) for path in sorted(set(paths))},
        "correctness_control_sha256": {
            str((HERE / "review/codec-controls.json").relative_to(ROOT)): sha(HERE / "review/codec-controls.json")
        },
        "preparation_policy": "Fresh w reconstruction, D computation and advice packing are charged per complete pipeline; only keygen/signing are fixtures",
    }
    (HERE / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({key:manifest[key] for key in ("elf","elf_sha256","elf_bytes","parts_per_signature")}))


if __name__ == "__main__":
    main()
