#!/usr/bin/env python3
"""Supply the guest's local std subset only to RV target consumer crates."""
import os
from pathlib import Path
import sys

command = sys.argv[1:]
def argument(name):
    try:
        return command[command.index(name) + 1]
    except (ValueError, IndexError):
        return None

target = argument("--target")
crate = argument("--crate-name")
if target == "riscv64im-unknown-none-elf" and crate not in {"___", "core", "alloc", "compiler_builtins", "std"} and os.environ.get("AERIE_BUILDING_STD") != "1":
    metadata = os.environ.get("AERIE_GUEST_STD_RMETA")
    if not metadata:
        raise SystemExit("build the aerie-guest-std workspace package and set AERIE_GUEST_STD_RMETA first")
    path = Path(metadata).resolve()
    if not path.is_file():
        raise SystemExit(f"missing guest std metadata: {path}")
    command += ["--extern", "std=" + str(path), "-L", "dependency=" + str(path.parent)]
    sources = [Path(arg) for arg in command if arg.endswith(".rs")]
    text = sources[0].read_text() if sources else ""
    if crate != "linked_list_allocator" and ("no_std" not in text or "extern crate std" in text):
        command += ["-Zcrate-attr=feature(alloc_io)"]
    output = Path(os.environ["CARGO_TARGET_DIR"]) / target / "release/build"
    for candidate in sorted(output.glob("*/*/out")):
        command += ["-L", "dependency=" + str(candidate)]
os.execv(command[0], command)
