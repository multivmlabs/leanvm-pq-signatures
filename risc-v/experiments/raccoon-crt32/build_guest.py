#!/usr/bin/env python3
"""Build the source-pinned compact-input Raccoon-128-1 guest and record provenance."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {"vendor/leanVM-riscv": "06e5c9cd6981103786f9d0a17324241b559a50d3",
        "vendor/raccoon": "e789b4b72a2b7e8a2205df49c487736985fc8417"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def main():
    for directory, expected in PINS.items():
        actual = command("git", "-C", str(ROOT / directory), "rev-parse", "HEAD")
        if actual != expected:
            raise SystemExit(f"wrong {directory} revision: {actual}")
        if command("git", "-C", str(ROOT / directory), "status", "--porcelain"):
            raise SystemExit(f"modified vendor checkout: {directory}")
    env = os.environ.copy()
    compiler = env.get("RACCOON_CLANG", "clang")
    compiler_path = shutil.which(compiler) or compiler
    compiler_version = command(compiler, "--version")
    env["RACCOON_CLANG_FINGERPRINT"] = hashlib.sha256((compiler_path + "\n" + compiler_version).encode()).hexdigest()
    cache = ROOT / ".cache/riscv-cargo"
    if cache.is_dir():
        env.setdefault("CARGO_HOME", str(cache))
    subprocess.run(["cargo", "+nightly-2026-10-03", "build", "--release", "--offline", "--locked"],
                   cwd=HERE / "guest", env=env, check=True)
    elf = HERE / "guest/target/riscv64im-unknown-none-elf/release/raccoon-riscv-guest"
    shutil.copyfile(elf, HERE / "raccoon.elf")
    inputs = [p for directory in ("guest", "host", "c")
              for p in (HERE / directory).rglob("*") if p.is_file()
              and not {"target", ".cache", "__pycache__"}.intersection(p.parts) and p.suffix not in (".elf", ".json")]
    inputs += [HERE / "build_support.rs", HERE / "build_guest.py"]
    c_ref = ROOT / "vendor/raccoon/ref-c"
    files = ("racc_core", "racc_serial", "polyr", "ntt64", "xof_sample", "racc_api", "util/ct_util", "util/sha3_t", "util/keccakf1600", "util/nist_random", "util/test_aes1kt")
    inputs += [c_ref / (name + ".c") for name in files]
    inputs += sorted(c_ref.glob("*.h")) + sorted((c_ref / "inc").glob("*.h"))
    manifest = {"schema": 1, "backend_pins": PINS,
                "guest_rustc": command("rustc", "+nightly-2026-10-03", "--version", "--verbose"),
                "clang": compiler_version, "clang_path": compiler_path,
                "clang_fingerprint": env["RACCOON_CLANG_FINGERPRINT"],
                "keccak_kernel": "PR605_register_state_software_f1600",
                "elf": "risc-v/experiments/raccoon-crt32/raccoon.elf", "elf_bytes": elf.stat().st_size,
                "elf_sha256": sha(elf),
                "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(inputs))},
                "specification_sha256": sha(ROOT / "risc-v/raccoon/sources/raccoon-spec-web.pdf"),
                "selected_arithmetic": "original 64-bit Montgomery NTT; CRT32 retained only as unsuccessful trial",
                "keccak_origin": {"pull_request": 605, "head": "c67701c037c11d229c563671419ccc48827b5c2d", "merged": False},
                "features": ["sdk-keccak", "register-keccak"],
                "relation": "original Raccoon-128-1 reference interoperability, unchanged public domain and compact bytes",
                "changes": ["bounded 40-bit decode in at most six bytes", "complete partial-byte and whole-byte zero-padding check", "alignment-checked LE 64-bit helper accesses", "register-state software Keccak"],
                "flags": "-O3 -ffreestanding -fno-builtin -fno-strict-aliasing -fwrapv -ffunction-sections -fdata-sections -include c/namespace.h -include c/include/plat_local.h --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 -mcmodel=medany -mno-relax -emit-llvm"}
    generated = max((HERE / "guest/target/riscv64im-unknown-none-elf/release/build").glob("raccoon-riscv-guest/*/out/keccak-sdk.c"), key=lambda p: p.stat().st_mtime_ns)
    manifest["generated_c_sha256"] = sha(generated)
    manifest["source_sha256"]["vendor/leanVM-riscv/sdk/src/keccak.rs"] = sha(ROOT / "vendor/leanVM-riscv/sdk/src/keccak.rs")
    (HERE / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: manifest[k] for k in ("elf", "elf_bytes", "elf_sha256")}, indent=2))


if __name__ == "__main__":
    main()
