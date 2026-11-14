#!/usr/bin/env python3
"""Run approved segmented G trees with fresh producers and isolated full receivers.

The default only previews commands. No proof is reused between samples. The
receipt contains auxiliary D values, never signature witnesses or child proofs.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "06e5c9cd6981103786f9d0a17324241b559a50d3"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


class Matrix:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.binary = args.binary.resolve()
        self.env = os.environ.copy()
        self.env["LEANVM_NUM_THREADS"] = "8"
        if args.execute_approved and args.stage != "freeze":
            self.frozen = json.loads((self.output / "environment.json").read_text())
            if self.frozen["backend_revision"] != PIN or self.frozen["binary_sha256"] != digest(self.binary):
                raise RuntimeError("Runner differs from frozen experiment")
            for source, expected in self.frozen["source_sha256"].items():
                if digest(ROOT / source) != expected:
                    raise RuntimeError("Frozen source changed: " + source)
            for name in ("MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS"):
                if self.env.get(name) != self.frozen["environment"].get(name):
                    raise RuntimeError("Runtime environment differs from freeze: " + name)

    def freeze(self):
        path = self.output / "environment.json"
        if not self.args.execute_approved:
            print(json.dumps({"freeze": str(path), "binary": str(self.binary), "executes_guest": False}))
            return
        if path.exists():
            raise RuntimeError("Refusing to overwrite frozen environment")
        manifest_path = HERE / "build-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        if manifest["backend_pins"]["vendor/leanVM-riscv"] != PIN:
            raise RuntimeError("Wrong backend pin")
        sources = {}
        for name, expected in manifest["source_sha256"].items():
            if digest(ROOT / name) != expected:
                raise RuntimeError("Guest source differs from build: " + name)
            sources[name] = expected
        if digest(ROOT / manifest["elf"]) != manifest["elf_sha256"]:
            raise RuntimeError("Guest ELF differs from manifest")
        for path_input in [Path(__file__), manifest_path, ROOT / ".cargo/config.toml"]:
            sources[str(path_input.relative_to(ROOT))] = digest(path_input)
        for source in (HERE / "runner").rglob("*"):
            if source.is_file() and not {"target", ".cache", "__pycache__"}.intersection(source.parts) \
                    and (source.suffix == ".rs" or source.name in ("Cargo.toml", "Cargo.lock")):
                sources[str(source.relative_to(ROOT))] = digest(source)
        backend = ROOT / "vendor/leanVM-riscv"
        revision = subprocess.check_output(["git", "-C", str(backend), "rev-parse", "HEAD"], text=True).strip()
        patch = subprocess.check_output(["git", "-C", str(backend), "status", "--porcelain"], text=True).strip()
        if revision != PIN or patch:
            raise RuntimeError("Backend checkout changed")
        tracked = subprocess.check_output(["git", "-C", str(backend), "ls-files"], text=True).splitlines()
        for name in tracked:
            source = backend / name
            if source.is_file() and (source.suffix == ".rs" or source.name in ("Cargo.toml", "Cargo.lock")):
                sources[str(source.relative_to(ROOT))] = digest(source)
        self.output.mkdir(parents=True, exist_ok=True)
        identity_dir = self.output / "identity"
        subprocess.run([str(self.binary), "identity", "--outdir", str(identity_dir)], check=True, env=self.env)
        identity = json.loads((identity_dir / "identity.json").read_text())
        if identity["embedded_elf_sha256"] != manifest["elf_sha256"] \
                or identity["embedded_build_manifest_sha256"] != digest(manifest_path):
            raise RuntimeError("Native runner embeds a different guest or manifest")
        write(path, {"schema": 1, "scheme": "raccoon-g", "profile": identity["profile"],
                     "backend_revision": PIN, "binary_sha256": digest(self.binary),
                     "elf": manifest["elf"], "elf_sha256": manifest["elf_sha256"],
                     "guest_manifest": str(manifest_path.relative_to(ROOT)),
                     "guest_manifest_sha256": digest(manifest_path),
                     "parts_per_signature": identity["parts_per_signature"],
                     "rows_per_leaf": identity["rows_per_leaf"], "rows_per_signature": identity["rows_per_signature"],
                     "threads_requested": 8, "log_inverse_rate": 1,
                     "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count()},
                     "native_rustc": subprocess.check_output(["rustc", "+stable", "--version", "--verbose"], text=True).strip(),
                     "environment": {key: self.env.get(key) for key in
                                     ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS")},
                     "source_sha256": sources, "frozen_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "approval": "User approved both complete Raccoon benchmark matrices in this chat on 2026-11-09",
                     "proving_scope": "Fresh native W/D/advice preparation plus every partial leaf and native merge proof",
                     "prepared_complete_verification": "Envelope decode, D-derived complete part coverage and complete native Tree::verify",
                     "prepared_core_verification": "Decode core TreeProof and complete native Tree::verify on already derived outputs"})

    def command(self, action, *options):
        return [str(self.binary), action, *map(str, options), "--threads", "8", "--rate", "1"]

    def run(self, command, prefix, cwd=ROOT):
        if not self.args.execute_approved:
            print(json.dumps({"command": command, "cwd": str(cwd)}))
            return
        if prefix.with_suffix(".completed.json").exists():
            raise RuntimeError("Refusing to overwrite completed command: " + str(prefix))
        prefix.parent.mkdir(parents=True, exist_ok=True)
        record = {"schema": 1, "command": command, "cwd": str(cwd), "binary_sha256": digest(self.binary),
                  "runner_sha256": digest(Path(__file__)), "backend_revision": PIN,
                  "environment": {key: self.env.get(key) for key in ("MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS")},
                  "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "timeout_s": self.args.timeout_s, "rss_limit_bytes": self.args.rss_limit_gib * 1024**3}
        write(prefix.with_suffix(".started.json"), record)
        start = time.monotonic()
        aborted = None
        with prefix.with_suffix(".stdout.log").open("w") as stdout, prefix.with_suffix(".stderr.log").open("w") as stderr:
            process = subprocess.Popen(command, cwd=cwd, env=self.env, stdout=stdout, stderr=stderr, start_new_session=True)
            while process.poll() is None:
                if time.monotonic() - start > self.args.timeout_s:
                    aborted = "wall_clock_limit"
                else:
                    try:
                        observed = subprocess.run(["ps", "-o", "rss=", "-p", str(process.pid)], capture_output=True, text=True, check=False)
                        rss = observed.stdout.strip()
                        if (observed.returncode or not rss.isdigit()) and process.poll() is None:
                            aborted = "rss_monitor_unavailable"
                            record["rss_monitor_error"] = {"exit_code": observed.returncode, "stdout": observed.stdout[-1000:], "stderr": observed.stderr[-1000:]}
                        elif rss.isdigit() and int(rss) * 1024 > record["rss_limit_bytes"]:
                            aborted = "resident_memory_limit"
                    except OSError as error:
                        aborted = "rss_monitor_unavailable"
                        record["rss_monitor_error"] = {"error": str(error)}
                if aborted:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.25)
            returncode = process.wait()
        record.update(exit_code=returncode, aborted=aborted, process_elapsed_s=time.monotonic() - start,
                      finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        write(prefix.with_suffix(".completed.json"), record)
        if returncode or aborted:
            raise RuntimeError("Command stopped or failed; inspect " + str(prefix))

    def plan(self, count):
        folder = self.output / f"count-{count}"
        if self.args.execute_approved and (folder / "statement.json").exists():
            intended = json.loads((folder / "statement.json").read_text())
            if intended["signatures"] != count or intended["elf_sha256"] != self.frozen["elf_sha256"]:
                raise RuntimeError("Existing plan identity mismatch")
            return
        self.run(self.command("plan", "--n", count, "--outdir", folder), folder / "planner")

    def prove(self, count, sample):
        folder = self.output / f"count-{count}"
        sample_name = f"sample-{sample}"
        directory = folder / sample_name
        self.run(self.command("prove", "--n", count, "--outdir", folder, "--sample", sample_name), folder / f"{sample_name}-producer")
        if self.args.execute_approved:
            report = json.loads((directory / "report.json").read_text())
            if report.get("verified") is not True or report.get("all_folded_claims_settled") is not True:
                raise RuntimeError("Producer did not complete every folded claim")

    def verify(self, count, sample):
        folder = self.output / f"count-{count}"
        directory = folder / f"sample-{sample}"
        receiver = directory / "public-only-receiver"
        if not self.args.execute_approved:
            print(json.dumps({"consumer": "isolated public-only receiver", "directory": str(receiver)}))
            return
        receiver.mkdir()
        statement = folder / "statement.json"
        shutil.copyfile(statement, receiver / "statement.json")
        shutil.copyfile(directory / "root.proof", receiver / "root.proof")
        self.run(self.command("verify", "--outdir", receiver, "--statement", receiver / "statement.json", "--proof", receiver / "root.proof",
                              "--expect-statement-sha256", digest(statement), "--expect-elf-sha256", self.frozen["elf_sha256"], "--controls", "true"),
                 receiver / "consumer", cwd=receiver)
        checked = json.loads((receiver / "verification.json").read_text())
        if checked.get("verified") is not True or checked.get("all_folded_claims_settled") is not True \
                or checked.get("verification_uses_signatures") is not False or checked.get("verification_uses_child_proofs") is not False:
            raise RuntimeError("Incomplete public-only receiver")
        write(directory / "pipeline-completed.json", {"schema": 1, "verified_public_only": True,
              "binary_sha256": self.frozen["binary_sha256"], "elf_sha256": self.frozen["elf_sha256"],
              "statement_sha256": digest(statement), "root_proof_sha256": digest(directory / "root.proof"),
              "signatures": count, "sample": sample, "receiver_inputs": ["statement.json", "root.proof"],
              "all_folded_claims_settled": True, "parts_per_signature": self.frozen["parts_per_signature"]})

    def matrix(self):
        for count in self.args.counts:
            self.plan(count)
            for sample in range(self.args.samples):
                directory = self.output / f"count-{count}" / f"sample-{sample}"
                completed = directory / "pipeline-completed.json"
                if self.args.execute_approved and self.args.resume and completed.exists():
                    previous = json.loads(completed.read_text())
                    if previous.get("binary_sha256") != self.frozen["binary_sha256"] or previous.get("verified_public_only") is not True:
                        raise RuntimeError("Cannot preserve mismatched completed sample")
                    print(f"Preserved complete N={count} sample={sample}", flush=True)
                    continue
                print(f"{'Starting' if self.args.execute_approved else 'Previewing'} fresh G N={count} sample={sample}", flush=True)
                self.prove(count, sample)
                self.verify(count, sample)
                print(f"{'Completed' if self.args.execute_approved else 'Prepared command preview for'} fresh G N={count} sample={sample}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("freeze", "plan", "prove", "verify", "matrix"))
    parser.add_argument("--counts", type=int, nargs="+", default=[10, 30, 70, 100])
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--output", type=Path, default=ROOT / "risc-v/results/raccoong-segmented-trees")
    parser.add_argument("--binary", type=Path, default=ROOT / ".cache/raccoon-optimized-study-target/release/raccoong-segmented-treebench")
    parser.add_argument("--timeout-s", type=int, default=1800)
    parser.add_argument("--rss-limit-gib", type=int, default=18)
    parser.add_argument("--execute-approved", action="store_true")
    parser.add_argument("--resume", action="store_true", help="Skip fully completed samples only; partial samples are not reused")
    args = parser.parse_args()
    if any(n not in (1, 2, 10, 30, 70, 100) for n in args.counts) or args.samples < 1 or args.sample < 0 \
            or args.timeout_s < 1 or args.rss_limit_gib < 1:
        parser.error("Valid counts, positive samples/resource limits and nonnegative sample are required")
    matrix = Matrix(args)
    if args.stage == "freeze":
        matrix.freeze()
    elif args.stage == "matrix":
        matrix.matrix()
    else:
        for count in args.counts:
            if args.stage == "plan":
                matrix.plan(count)
            elif args.stage == "prove":
                matrix.prove(count, args.sample)
            else:
                matrix.verify(count, args.sample)


if __name__ == "__main__":
    main()
