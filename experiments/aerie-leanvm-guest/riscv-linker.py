#!/usr/bin/env python3
"""Run the pinned Rust linker with its bundled LLVM dynamic library visible."""
import os
from pathlib import Path
import sys
root = Path(os.environ["AERIE_RUST_SYSROOT"])
linkers = list(root.glob("lib/rustlib/*/bin/rust-lld"))
if len(linkers) != 1:
    raise SystemExit("expected one pinned host rust-lld")
env = {**os.environ, "DYLD_LIBRARY_PATH": str(root / "lib"), "LD_LIBRARY_PATH": str(root / "lib")}
os.execve(str(linkers[0]), [str(linkers[0]), *sys.argv[1:]], env)
