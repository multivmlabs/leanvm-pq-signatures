#!/usr/bin/env python3
"""Build the pinned full Aerie verifier for the single-hart leanVM target."""
import json
import hashlib
import argparse
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TARGET = ROOT / ".cache/aerie-wrapper-target"
LOGS = ROOT / "artifacts/aerie-wrapper"
NIGHTLY = "nightly-2026-10-03"


def run(command, env, log):
    LOGS.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        done = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if done.returncode:
        print(log.read_text()[-12000:])
        raise SystemExit(done.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derive-setup", action="store_true", help="regenerate the public setup inside the VM")
    parser.add_argument("--all-schedules", action="store_true", help="retain the original prepare-all-schedules constructor")
    parser.add_argument("--no-terminal-cache", action="store_true", help="prepare selected terminal NTT data inside the VM")
    args = parser.parse_args()
    terminal_cache = not (args.derive_setup or args.all_schedules or args.no_terminal_cache)
    if not args.derive_setup:
        from check_setup import check_setup
        check_setup(terminal_cache)
    env = {**os.environ, "CARGO_HOME": str(ROOT / ".cache/aerie-cargo"),
           "CARGO_TARGET_DIR": str(TARGET), "RUSTC_WRAPPER": str(HERE / "rustc-wrapper.py"),
           "AERIE_RUST_SYSROOT": subprocess.check_output(["rustc", "+" + NIGHTLY, "--print", "sysroot"], text=True).strip(),
           "RUSTFLAGS": f"-C target-cpu=generic-rv64 -C panic=abort -C linker={HERE / 'riscv-linker.py'} -C linker-flavor=ld.lld -C link-arg=-T{HERE / 'link.ld'}"}
    command = ["cargo", "+" + NIGHTLY, "build", "--offline", "--locked", "--manifest-path", str(HERE / "Cargo.toml"),
               "--release", "--target", "riscv64im-unknown-none-elf", "-Zbuild-std=core,alloc"]
    # Cargo cannot infer the implicit --extern std dependency injected by our
    # wrapper. Invalidate its target consumers after a shim source change.
    sources = sorted((HERE.parent / "aerie-port/std").rglob("*.rs"))
    source_hash = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    revision = TARGET / "guest-std-source.sha256"
    if not revision.exists() or revision.read_text() != source_hash:
        run(["cargo", "+" + NIGHTLY, "clean", "--manifest-path", str(HERE / "Cargo.toml"),
             "--target", "riscv64im-unknown-none-elf", "--release"], env, LOGS / "guest-clean.log")
        revision.parent.mkdir(parents=True, exist_ok=True)
        revision.write_text(source_hash)
    run(command + ["-p", "aerie-guest-std"], {**env, "AERIE_BUILDING_STD":"1"}, LOGS / "guest-std-build.log")
    candidates = list((TARGET / "riscv64im-unknown-none-elf/release/build/aerie-guest-std").glob("*/out/libstd-*.rmeta"))
    if not candidates:
        raise SystemExit("guest std build produced no metadata")
    metadata = max(candidates, key=lambda p: p.stat().st_mtime_ns)
    env["AERIE_GUEST_STD_RMETA"] = str(metadata)
    features = [] if args.derive_setup else ["trusted-public-setup"]
    if terminal_cache:
        features += ["trusted-terminal-cache"]
    if args.all_schedules:
        features += ["prepare-all-schedules"]
    feature_flags = ["--no-default-features"]
    if features:
        feature_flags += ["--features", ",".join(features)]
    run(command + ["-p", "aerie-leanvm-guest"] + feature_flags, env, LOGS / "guest-full-build.log")
    elf = TARGET / "riscv64im-unknown-none-elf/release/aerie-leanvm-guest"
    print(json.dumps({"elf": str(elf), "std_metadata": str(metadata), "nightly": NIGHTLY,
                      "setup": "derived in guest" if args.derive_setup else "immutable pinned public setup bank",
                      "schedule_preparation": "all admitted rows" if args.all_schedules else "only deterministically selected row",
                      "terminal_cache": "immutable pinned public Q64 NTT data" if terminal_cache else "prepared inside guest",
                      "scope": "Complete Aerie public verifier, scalar single-thread runtime"}, indent=2))


if __name__ == "__main__":
    main()
