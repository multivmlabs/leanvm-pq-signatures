#!/usr/bin/env python3
"""Approved standard-Raccoon matrix with explicit bounded-memory allocation.

Preserves study.py and its original pilot/preflight cohort unchanged. The same
native binaries and proof parameters are used. This launcher records the actual
prefixed Jemalloc runtime policy in a separate immutable experiment cohort.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
POLICY = "dirty_decay_ms:0,muzzy_decay_ms:0"
KEYS = ("MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS")
os.environ.setdefault("_RJEM_MALLOC_CONF", POLICY)
spec = importlib.util.spec_from_file_location("immutable_raccoon_study", HERE / "study.py")
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)
Base = protocol.Study


class RuntimeStudy(Base):
    def __init__(self, args):
        super().__init__(args)
        if self.env.get("_RJEM_MALLOC_CONF") != POLICY:
            raise RuntimeError("This cohort requires the documented page-purging policy")
        if args.execute_approved and args.stage != "freeze":
            frozen = json.loads((self.output / "environment.json").read_text())
            if frozen["runtime_environment"] != {k: self.env.get(k) for k in KEYS}:
                raise RuntimeError("Runtime allocator/thread settings differ from the frozen cohort")

    def freeze(self):
        super().freeze()
        if self.args.execute_approved:
            path = self.output / "environment.json"
            frozen = json.loads(path.read_text())
            frozen["runtime_environment"] = {k: self.env.get(k) for k in KEYS}
            frozen["allocator_policy"] = "Override bench crate dirty_decay_ms:-1 with explicit dirty/muzzy page purging; original default-allocator pilot is retained separately"
            protocol.write(path, frozen)

    def run(self, command, prefix, **kwargs):
        try:
            return super().run(command, prefix, **kwargs)
        finally:
            path = prefix.with_suffix(".completed.json")
            if self.args.execute_approved and path.exists():
                record = json.loads(path.read_text())
                record["runtime_environment"] = {k: self.env.get(k) for k in KEYS}
                record["protocol_launcher_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                protocol.write(path, record)


if __name__ == "__main__":
    if "--output" not in sys.argv:
        sys.argv.extend(["--output", str(ROOT / "risc-v/results/raccoon-runtime-study")])
    protocol.Study = RuntimeStudy
    protocol.main()
