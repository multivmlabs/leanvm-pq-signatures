#!/usr/bin/env python3
"""Build the source-pinned compact-input ML-DSA-44 guest and record provenance."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PINS = {"vendor/leanVM-riscv": "06e5c9cd6981103786f9d0a17324241b559a50d3",
        "vendor/ETHDILITHIUM": "f9f4fe1d84e68304b425e054c273c276fe44ba11"}


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
    compiler = env.get("MLDSA_CLANG", "clang")
    compiler_path = shutil.which(compiler) or compiler
    compiler_version = command(compiler, "--version")
    env["MLDSA_CLANG_FINGERPRINT"] = hashlib.sha256((compiler_path + "\n" + compiler_version).encode()).hexdigest()
    cache = ROOT / ".cache/aerie-cargo"
    if cache.is_dir():
        env.setdefault("CARGO_HOME", str(cache))
    subprocess.run(["cargo", "+nightly-2026-10-03", "build", "--release", "--offline", "--locked"],
                   cwd=HERE / "guest", env=env, check=True)
    elf = HERE / "guest/target/riscv64im-unknown-none-elf/release/mldsa-riscv-guest"
    shutil.copyfile(elf, HERE / "mldsa.elf")
    inputs = [p for p in HERE.rglob("*") if p.is_file()
              and "target" not in p.parts and p.name != "build-manifest.json"
              and p.suffix not in (".elf", ".json")]
    c_ref = ROOT / "vendor/ETHDILITHIUM/c-ref"
    files = ("sign", "packing", "polyvec", "poly", "ntt", "reduce", "rounding", "fips202", "symmetric-shake")
    inputs += [c_ref / (name + ".c") for name in files]
    inputs += sorted(c_ref.glob("*.h"))
    manifest = {"schema": 1, "backend_pins": PINS,
                "guest_rustc": command("rustc", "+nightly-2026-10-03", "--version", "--verbose"),
                "clang": compiler_version, "clang_path": compiler_path,
                "clang_fingerprint": env["MLDSA_CLANG_FINGERPRINT"],
                "keccak_kernel": "leanvm_sdk_software_f1600",
                "elf": "risc-v/mldsa/mldsa.elf", "elf_bytes": elf.stat().st_size,
                "elf_sha256": sha(elf),
                "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(inputs))},
                "flags": "-O3 -ffreestanding -fno-builtin -fno-strict-aliasing -ffunction-sections -fdata-sections -DETHDILITHIUM=0 -DDILITHIUM_MODE=2 --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 -mcmodel=medany -mno-relax -emit-llvm"}
    generated = max((HERE / "guest/target/riscv64im-unknown-none-elf/release/build").glob("mldsa-riscv-guest/*/out/fips202-sdk-keccak.c"), key=lambda p: p.stat().st_mtime_ns)
    manifest["generated_c_sha256"] = sha(generated)
    manifest["source_sha256"]["vendor/leanVM-riscv/sdk/src/keccak.rs"] = sha(ROOT / "vendor/leanVM-riscv/sdk/src/keccak.rs")
    (HERE / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: manifest[k] for k in ("elf", "elf_bytes", "elf_sha256")}, indent=2))


if __name__ == "__main__":
    main()
