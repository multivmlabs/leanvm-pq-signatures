#!/usr/bin/env python3
"""Preview or run the approved Raccoon benchmark stages.

Without --execute-approved this only prints commands. It does not execute a
guest, plan a witness, or produce a proof. Keep the approval in the chat; the
flag is an execution guard, not a substitute for that approval.
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

ROOT = Path(__file__).resolve().parents[2]
BACKEND = "06e5c9cd6981103786f9d0a17324241b559a50d3"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


class Study:
    def __init__(self, args):
        self.args = args
        self.output = args.output.resolve()
        self.direct = args.direct_binary.resolve()
        self.tree = args.tree_binary.resolve()
        self.env = os.environ.copy()
        self.env["LEANVM_NUM_THREADS"] = "8"
        if args.execute_approved and args.stage != "freeze":
            frozen = json.loads((self.output / "environment.json").read_text())
            if frozen["backend_revision"] != BACKEND or \
                    frozen["direct_binary_sha256"] != sha(self.direct) or \
                    frozen["tree_binary_sha256"] != sha(self.tree):
                raise RuntimeError("Study binaries differ from the frozen environment")
            for source, expected in frozen["source_sha256"].items():
                if sha(ROOT / source) != expected:
                    raise RuntimeError(f"Source changed after study freeze: {source}")

    def command(self, binary: Path, action: str, *options: str) -> list[str]:
        return [str(binary), action, "--scheme", self.args.scheme,
                *map(str, options), "--threads", "8", "--rate", "1"]

    def freeze(self) -> None:
        """Freeze provenance only, with no guest execution or benchmark."""
        path = self.output / "environment.json"
        if not self.args.execute_approved:
            print(json.dumps({"freeze_only": str(path), "executes_guest": False,
                              "direct_binary": str(self.direct), "tree_binary": str(self.tree)}))
            return
        if path.exists():
            raise RuntimeError(f"Refusing to overwrite frozen environment: {path}")
        sources = {}
        schemes = {}
        backend = ROOT / "vendor/leanVM-riscv"
        revision = subprocess.check_output(["git", "-C", str(backend), "rev-parse", "HEAD"], text=True).strip()
        patch_state = subprocess.check_output(["git", "-C", str(backend), "status", "--porcelain"], text=True).strip()
        if revision != BACKEND or patch_state:
            raise RuntimeError("Backend checkout is modified or differs from the pinned revision")
        for source in backend.rglob("*"):
            if source.is_file() and not {"target", ".git"}.intersection(source.parts) \
                    and (source.suffix == ".rs" or source.name in ("Cargo.toml", "Cargo.lock")):
                sources[str(source.relative_to(ROOT))] = sha(source)
        sources[".cargo/config.toml"] = sha(ROOT / ".cargo/config.toml")
        for name, folder in (("raccoon", "experiments/raccoon-crt32"), ("raccoon-g", "raccoon-g")):
            manifest_path = ROOT / "risc-v" / folder / "build-manifest.json"
            manifest = json.loads(manifest_path.read_text())
            if manifest["backend_pins"]["vendor/leanVM-riscv"] != BACKEND:
                raise RuntimeError("Guest backend pin mismatch")
            if sha(ROOT / manifest["elf"]) != manifest["elf_sha256"]:
                raise RuntimeError("Guest ELF changed after its build manifest")
            for source, expected in manifest["source_sha256"].items():
                actual = sha(ROOT / source)
                if actual != expected:
                    raise RuntimeError(f"Source changed after guest build: {source}")
                sources[source] = actual
            sources[str(manifest_path.relative_to(ROOT))] = sha(manifest_path)
            schemes[name] = {"elf": manifest["elf"], "elf_sha256": manifest["elf_sha256"],
                             "guest_manifest": str(manifest_path.relative_to(ROOT)),
                             "guest_manifest_sha256": sha(manifest_path)}
        for source in Path(__file__).parent.rglob("*"):
            if source.is_file() and "target" not in source.parts and "__pycache__" not in source.parts \
                    and (source.suffix in (".rs", ".py") or source.name in ("Cargo.toml", "Cargo.lock")):
                sources[str(source.relative_to(ROOT))] = sha(source)
        self.output.mkdir(parents=True, exist_ok=True)
        write(path, {"schema": 1, "backend_revision": BACKEND, "schemes": schemes,
                     "direct_binary_sha256": sha(self.direct), "tree_binary_sha256": sha(self.tree),
                     "threads_requested": 8, "log_inverse_rate": 1,
                     "host": {"platform": platform.platform(), "logical_cpus": os.cpu_count()},
                     "native_rustc": subprocess.check_output(["rustc", "+stable", "--version", "--verbose"], text=True).strip(),
                     "environment": {key: os.environ.get(key) for key in
                                     ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "MALLOC_CONF", "LEANVM_NUM_THREADS")},
                     "approval": "User approved both complete benchmark matrices in this chat on 2026-11-09",
                     "source_freeze_scope": "Executable/build sources, dependency locks and guest manifests; editable documentation and later evidence are separate",
                     "source_sha256": sources,
                     "frozen_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})

    def run(self, command: list[str], prefix: Path, *, cwd=ROOT,
            allow_failure=False) -> bool:
        if not self.args.execute_approved:
            print(json.dumps({"command": command, "cwd": str(cwd)}))
            return True
        prefix.parent.mkdir(parents=True, exist_ok=True)
        if prefix.with_suffix(".completed.json").exists():
            raise RuntimeError(f"Refusing to overwrite completed command: {prefix}")
        record = {
            "schema": 1, "command": command, "cwd": str(cwd),
            "backend_revision": BACKEND, "binary_sha256": sha(Path(command[0])),
            "runner_sha256": sha(Path(__file__)),
            "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "timeout_s": self.args.timeout_s,
            "rss_limit_bytes": self.args.rss_limit_gib * 1024**3,
        }
        write(prefix.with_suffix(".started.json"), record)
        started = time.monotonic()
        aborted = None
        with prefix.with_suffix(".stdout.log").open("w") as stdout, \
                prefix.with_suffix(".stderr.log").open("w") as stderr:
            process = subprocess.Popen(command, cwd=cwd, env=self.env,
                                       stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            while process.poll() is None:
                if time.monotonic() - started > self.args.timeout_s:
                    aborted = "wall_clock_limit"
                else:
                    try:
                        observed = subprocess.run(
                            ["ps", "-o", "rss=", "-p", str(process.pid)],
                            capture_output=True, text=True, check=False)
                        rss = observed.stdout.strip()
                        if (observed.returncode or not rss.isdigit()) and process.poll() is None:
                            aborted = "rss_monitor_unavailable"
                            record["rss_monitor_error"] = {
                                "exit_code": observed.returncode, "stdout": observed.stdout[-1000:],
                                "stderr": observed.stderr[-1000:],
                            }
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
        record.update(exit_code=returncode, aborted=aborted,
                      process_elapsed_s=time.monotonic() - started,
                      finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        write(prefix.with_suffix(".completed.json"), record)
        if aborted or (returncode and not allow_failure):
            raise RuntimeError(f"Command failed or stopped, see {prefix}")
        return returncode == 0

    def public_consumer(self, directory: Path, proof: Path, statement: Path,
                        binary: Path, *, tree: bool) -> None:
        receiver = directory / "public-only-receiver"
        if not self.args.execute_approved:
            print(json.dumps({"consumer": "isolated directory with root proof and public statement only",
                              "binary": str(binary), "directory": str(receiver)}))
            return
        receiver.mkdir()
        target_proof = receiver / "root.proof"
        target_statement = receiver / "statement.json"
        shutil.copyfile(proof, target_proof)
        shutil.copyfile(statement, target_statement)
        intended = json.loads(target_statement.read_text())
        options = ["--statement", str(target_statement), "--proof", str(target_proof),
                   "--expect-statement-sha256", sha(target_statement),
                   "--expect-elf-sha256", intended["elf_sha256"]]
        if tree:
            options += ["--outdir", str(receiver), "--controls", "true"]
        else:
            options += ["--out", str(receiver / "verification.json"),
                        "--repeat", "3", "--warmup", "1"]
        self.run(self.command(binary, "verify", *options), receiver / "consumer", cwd=receiver)
        checked = json.loads((receiver / "verification.json").read_text())
        if checked.get("verified") is not True or \
                (tree and checked.get("all_folded_claims_settled") is not True):
            raise RuntimeError("Complete public-only verification missing")

    def capacity(self) -> None:
        # Check every prefix. Table padding and data-dependent instruction mix
        # need not produce a monotone boundary; do not stop at the first refusal.
        for count in range(1, self.args.input_limit + 1):
            directory = self.output / self.args.scheme / "capacity"
            report = directory / f"count-{count}.json"
            self.run(self.command(self.direct, "measure", "--n", str(count),
                                  "--out", str(report)), directory / f"count-{count}")

    def direct_batches(self) -> None:
        for count in self.args.counts:
            directory = self.output / self.args.scheme / "direct" / f"count-{count}"
            report = directory / "report.json"
            proof = directory / "root.proof"
            self.run(self.command(self.direct, "prove", "--n", str(count),
                                  "--out", str(report), "--proof", str(proof),
                                  "--repeat", "3", "--warmup", "1"), directory / "producer")
            if self.args.execute_approved:
                result = json.loads(report.read_text())
                if result.get("status") == "rejected":
                    # The direct runner also invokes the actual prover on the
                    # rejected plan and records its refusal. No fabricated point.
                    if "prover_error" not in result:
                        raise RuntimeError("Planning refusal lacks actual prover refusal")
                    continue
                if result.get("verified") is not True:
                    raise RuntimeError("Producer did not verify its proof")
            self.public_consumer(directory, proof, Path(str(proof) + ".statement.json"),
                                 self.direct, tree=False)

    def tree_plans(self) -> None:
        for leaf_size in self.args.candidate_leaf_sizes:
            directory = self.output / self.args.scheme / "tree-candidates" / f"leaf-{leaf_size}"
            self.run(self.command(self.tree, "plan", "--n", "100", "--leaf-size", str(leaf_size),
                                  "--outdir", str(directory)), directory / "planner",
                     allow_failure=True)

    def trees(self) -> None:
        for count in (10, 30, 70, 100):
            directory = self.output / self.args.scheme / "trees" / f"count-{count}"
            self.run(self.command(self.tree, "plan", "--n", str(count),
                                  "--leaf-size", str(self.args.leaf_size),
                                  "--outdir", str(directory)), directory / "planner")
            for sample in range(3):
                sample_name = f"sample-{sample}"
                self.run(self.command(self.tree, "prove", "--n", str(count),
                                      "--leaf-size", str(self.args.leaf_size),
                                      "--sample", sample_name, "--outdir", str(directory)),
                         directory / f"{sample_name}-producer")
                sample_dir = directory / sample_name
                self.public_consumer(sample_dir, sample_dir / "root.proof",
                                     directory / "statement.json", self.tree, tree=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("freeze", "capacity", "direct", "tree-plan", "tree"))
    parser.add_argument("--scheme", choices=("raccoon", "raccoon-g"), required=True)
    parser.add_argument("--input-limit", type=int, required=True,
                        help="Explicit guest advice/input bound, not assumed proof capacity")
    parser.add_argument("--counts", type=int, nargs="+", default=list(range(1, 31)))
    parser.add_argument("--leaf-size", type=int, choices=(1, 2, 5, 10), default=1)
    parser.add_argument("--candidate-leaf-sizes", type=int, nargs="+", choices=(1, 2, 5, 10),
                        default=[1, 2, 5, 10])
    parser.add_argument("--output", type=Path, default=ROOT / "risc-v/results/raccoon-optimized-study")
    parser.add_argument("--direct-binary", type=Path,
                        default=ROOT / ".cache/raccoon-optimized-study-target/release/riscv-raccoon-optimized-direct")
    parser.add_argument("--tree-binary", type=Path,
                        default=ROOT / ".cache/raccoon-optimized-study-target/release/riscv-raccoon-optimized-tree")
    parser.add_argument("--timeout-s", type=int, default=1800)
    parser.add_argument("--rss-limit-gib", type=int, default=18)
    parser.add_argument("--execute-approved", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.input_limit <= 64 or args.timeout_s < 1 or args.rss_limit_gib < 1 or \
            (args.stage == "direct" and any(not 1 <= n <= args.input_limit for n in args.counts)):
        parser.error("input limit 1..64, positive resource bounds and direct counts within the input bound are required")
    if (args.stage == "tree" and args.leaf_size > args.input_limit) or \
            (args.stage == "tree-plan" and any(n > args.input_limit for n in args.candidate_leaf_sizes)):
        parser.error("leaf sizes must fit the explicit guest input bound")
    study = Study(args)
    {"freeze": study.freeze, "capacity": study.capacity, "direct": study.direct_batches,
     "tree-plan": study.tree_plans, "tree": study.trees}[args.stage]()


if __name__ == "__main__":
    main()
