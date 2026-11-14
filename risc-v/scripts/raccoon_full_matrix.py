#!/usr/bin/env python3
"""Serial coordinator for the explicitly approved complete Raccoon study.

Frozen native producers and protocol launchers are imported unchanged. Only
fully completed, verified samples can be preserved on resume. Partial samples
are never recycled, and a resource stop ends this coordinator for investigation.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import traceback

ROOT = Path(__file__).resolve().parents[2]
POLICY = "dirty_decay_ms:0,muzzy_decay_ms:0"
COUNTS = (10, 30, 70, 100)
SAMPLES = 3


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def completed_command(prefix):
    path = prefix.with_suffix(".completed.json")
    if not path.exists():
        if prefix.with_suffix(".started.json").exists():
            raise RuntimeError("Preserved partial command requires investigation: " + str(prefix))
        return False
    record = read(path)
    if record["exit_code"] != 0 or record.get("aborted"):
        raise RuntimeError("Preserved failed command requires investigation: " + str(prefix))
    return True


def check_sample(directory, statement_path, count, leaves, segmented):
    report = read(directory / "report.json")
    receiver = read(directory / "public-only-receiver/verification.json")
    slots = 1 << (leaves - 1).bit_length()
    if (report.get("verified") is not True
            or report.get("all_folded_claims_settled") is not True
            or report["signatures"] != count
            or report["actual_leaves"] != leaves
            or report["leaf_slots"] != slots
            or report["merge_count"] != slots - 1
            or len(report["leaf_reports"]) != leaves
            or len(report["merge_reports"]) != slots - 1):
        raise RuntimeError("Incomplete fresh production accounting: " + str(directory))
    if (receiver.get("verified") is not True
            or receiver.get("all_folded_claims_settled") is not True
            or receiver.get("verification_uses_child_proofs") is not False
            or receiver.get("verification_uses_signatures") is not False):
        raise RuntimeError("Incomplete public-only receiver: " + str(directory))
    root_digest = sha(directory / "root.proof")
    if (report["root_proof_sha256"] != root_digest
            or receiver["root_proof_sha256"] != root_digest
            or report["statement_sha256"] != sha(statement_path)):
        raise RuntimeError("Root or public-statement evidence differs: " + str(directory))
    for leaf in report["leaf_reports"]:
        if sha(directory / f"leaf-{leaf['leaf']}.proof") != leaf["proof_sha256"]:
            raise RuntimeError("Saved fresh leaf differs")
    for merge in report["merge_reports"]:
        if sha(directory / f"merge-{merge['node']}.proof") != merge["proof_sha256"]:
            raise RuntimeError("Saved fresh merge differs")
    if segmented and report.get("parts_per_signature") != 5:
        raise RuntimeError("Segmented G coverage must contain five parts per signature")
    return {"schema": 1, "verified_public_only": True,
            "signatures": count, "actual_leaves": leaves, "leaf_slots": slots,
            "merge_count": slots - 1, "root_proof_sha256": root_digest,
            "statement_sha256": sha(statement_path),
            "elf_sha256": report["elf_sha256"],
            "total_prove_s": report["total_prove_s"],
            "root_proof_bytes": report["root_proof_bytes"],
            "all_folded_claims_settled": True,
            "coordinator_sha256": sha(Path(__file__)), "checked_utc": now()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-approved", action="store_true")
    parser.add_argument("--timeout-s", type=int, default=21600)
    parser.add_argument("--rss-limit-gib", type=int, default=19)
    args = parser.parse_args()
    if not args.execute_approved:
        parser.error("This long-running matrix requires the already authorized execution flag")
    if args.timeout_s < 1 or args.rss_limit_gib < 1:
        parser.error("Positive operational resource limits are required")
    if os.environ.get("_RJEM_MALLOC_CONF") != POLICY or os.environ.get("MALLOC_CONF"):
        parser.error("Use the frozen prefixed Jemalloc page-purging policy, without MALLOC_CONF")
    os.environ["LEANVM_NUM_THREADS"] = "8"
    state_dir = ROOT / "risc-v/results/raccoon-full-matrix"
    state_dir.mkdir(parents=True, exist_ok=True)
    lock = (state_dir / "process.lock").open("a+")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    protocol = load("standard_runtime_matrix", ROOT / "risc-v/raccoon-optimized-study/runtime_study.py")
    g_protocol = load("segmented_g_matrix", ROOT / "risc-v/experiments/raccoong-segmented/matrix.py")
    std_args = argparse.Namespace(output=ROOT / "risc-v/results/raccoon-runtime-study",
        direct_binary=ROOT / ".cache/raccoon-optimized-study-target/release/riscv-raccoon-optimized-direct",
        tree_binary=ROOT / ".cache/raccoon-optimized-study-target/release/riscv-raccoon-optimized-tree",
        execute_approved=True, stage="tree", timeout_s=args.timeout_s,
        rss_limit_gib=args.rss_limit_gib, scheme="raccoon", input_limit=64,
        counts=list(range(2, 31)), leaf_size=1, candidate_leaf_sizes=[1, 2, 5, 10])
    std = protocol.RuntimeStudy(std_args)
    g_args = argparse.Namespace(output=ROOT / "risc-v/results/raccoong-segmented-uniform-trees",
        binary=ROOT / ".cache/raccoon-optimized-study-target/release/raccoong-segmented-treebench",
        execute_approved=True, stage="matrix", counts=[], samples=3, sample=0,
        timeout_s=args.timeout_s, rss_limit_gib=args.rss_limit_gib, resume=True)
    g = g_protocol.Matrix(g_args)
    state = {"schema": 1, "status": "running", "started_utc": now(),
        "coordinator_sha256": sha(Path(__file__)), "counts": list(COUNTS), "samples": SAMPLES,
        "standard_output": str(std.output), "segmented_g_output": str(g.output),
        "timeout_s_per_command": args.timeout_s,
        "sampled_rss_stop_bytes": args.rss_limit_gib * 1024**3,
        "rss_policy": "Operational RSS sampling at 0.25 s, not a hard allocation cap",
        "environment": {name: os.environ.get(name) for name in
                        ("MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS")},
        "approval": "User explicitly approved both full matrices with three fresh runs and full verification",
        "completed_samples": []}

    def progress(message):
        state["activity"] = message
        state["updated_utc"] = now()
        write(state_dir / "progress.json", state)
        print(now(), message, flush=True)

    try:
        for count in range(1, 65):
            directory = std.output / "raccoon/capacity"
            prefix = directory / f"count-{count}"
            progress(f"Standard Raccoon production capacity check N={count}")
            if not completed_command(prefix):
                std.run(std.command(std.direct, "measure", "--n", count,
                                    "--out", directory / f"count-{count}.json"), prefix)
            measured = read(directory / f"count-{count}.json")
            if measured.get("count") != count or measured.get("status") not in ("accepted", "rejected"):
                raise RuntimeError("Missing production capacity result")
        for count in range(2, 31):
            directory = std.output / f"raccoon/direct/count-{count}"
            prefix = directory / "producer"
            progress(f"Standard Raccoon direct production attempt N={count}")
            if not completed_command(prefix):
                std.run(std.command(std.direct, "prove", "--n", count,
                    "--out", directory / "report.json", "--proof", directory / "root.proof",
                    "--repeat", 3, "--warmup", 1), prefix)
            report = read(directory / "report.json")
            if report.get("status") == "rejected":
                if "prover_error" not in report:
                    raise RuntimeError("Capacity refusal is missing actual production prover refusal")
            else:
                if not (directory / "public-only-receiver/consumer.completed.json").exists():
                    std.public_consumer(directory, directory / "root.proof",
                        directory / "root.proof.statement.json", std.direct, tree=False)
        for count in COUNTS:
            directory = std.output / f"raccoon/trees/count-{count}"
            progress(f"Standard Raccoon tree planning N={count}")
            if not completed_command(directory / "planner"):
                std.run(std.command(std.tree, "plan", "--n", count, "--leaf-size", 1,
                                    "--outdir", directory), directory / "planner")
            for sample in range(SAMPLES):
                name = f"sample-{sample}"
                run = directory / name
                marker = run / "pipeline-completed.json"
                progress(f"Standard Raccoon fresh tree N={count} sample={sample}")
                if marker.exists():
                    evidence = check_sample(run, directory / "statement.json", count, count, False)
                    if read(marker)["root_proof_sha256"] != evidence["root_proof_sha256"]:
                        raise RuntimeError("Completed root identity changed")
                else:
                    if run.exists() or (directory / f"{name}-producer.started.json").exists():
                        raise RuntimeError("Partial standard sample preserved for investigation: " + str(run))
                    std.run(std.command(std.tree, "prove", "--n", count, "--leaf-size", 1,
                                        "--sample", name, "--outdir", directory),
                            directory / f"{name}-producer")
                    std.public_consumer(run, run / "root.proof", directory / "statement.json", std.tree, tree=True)
                    evidence = check_sample(run, directory / "statement.json", count, count, False)
                    evidence["sample"] = sample
                    write(marker, evidence)
                state["completed_samples"].append({"scheme": "raccoon", "count": count,
                                                    "sample": sample, **evidence})
                progress(f"Completed standard Raccoon N={count} sample={sample}")
            g.plan(count)
            for sample in range(SAMPLES):
                run = g.output / f"count-{count}/sample-{sample}"
                marker = run / "pipeline-completed.json"
                progress(f"Segmented G fresh complete tree N={count} sample={sample}")
                if not marker.exists():
                    if run.exists() or (g.output / f"count-{count}/sample-{sample}-producer.started.json").exists():
                        raise RuntimeError("Partial G sample preserved for investigation: " + str(run))
                    g.prove(count, sample)
                    g.verify(count, sample)
                evidence = check_sample(run, g.output / f"count-{count}/statement.json", count, count * 5, True)
                write(run / "coordinator-validated.json", evidence)
                state["completed_samples"].append({"scheme": "raccoon-g", "count": count,
                                                    "sample": sample, **evidence})
                progress(f"Completed segmented G N={count} sample={sample}")
        state["status"] = "complete"
        progress("All 24 requested fresh tree pipelines passed separate full verification")
    except BaseException:
        state["status"] = "stopped_for_investigation"
        state["error"] = traceback.format_exc()
        progress("Stopped; all partial evidence retained")
        raise


if __name__ == "__main__":
    main()
