#!/usr/bin/env python3
"""Record source evidence for the independent FORS review."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path(__file__).resolve().parents[3]
paths = []
for directory in ["risc-v/fors", "risc-v/bench", "risc-v/reviews/fors-probe"]:
    for path in sorted((root / directory).rglob("*")):
        if not path.is_file() or "target" in path.relative_to(root).parts:
            continue
        if path.name in ["source-hashes.json", "build-manifest.json"]:
            continue
        paths.append(path)
for relative in [
    "risc-v/reviews/fors-security.md",
    "risc-v/scripts/consumer_controls.py",
    "risc-v/results/consumer-controls.json",
    "risc-v/results/direct/fors-8.json",
]:
    paths.append(root / relative)
for count in (1, 2, 7):
    for relative in [
        f"risc-v/artifacts/fors-{count}.proof",
        f"risc-v/artifacts/fors-{count}.proof.statement.json",
        f"risc-v/results/direct/fors-{count}.json",
    ]:
        paths.append(root / relative)
manifest = {
    "backend_revision": subprocess.check_output(["git", "-C", str(root / "vendor/leanVM-riscv"), "rev-parse", "HEAD"], text=True).strip(),
    "backend_patch_state": subprocess.check_output(["git", "-C", str(root / "vendor/leanVM-riscv"), "status", "--short"], text=True),
    "consumer_binary_sha256": hashlib.sha256((root / ".cache/aerie-wrapper-host-target/release/riscv-pqbench").read_bytes()).hexdigest(),
    "files": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
}
Path(__file__).with_name("source-hashes.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Recorded {len(paths)} hashes")
