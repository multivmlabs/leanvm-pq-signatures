#!/usr/bin/env python3
"""Add Raccoon curves to the three existing schemes from verified reports only.

No prover is run. Missing Raccoon studies cause an error before any output is
written. Existing article figures and raw measurements remain unchanged.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
PIN = "06e5c9cd6981103786f9d0a17324241b559a50d3"
COUNTS = (10, 30, 70, 100)
NEW = ("raccoon", "raccoon-g")
SCHEMES = {
    "falcon": ("Falcon-512 (RISC-V)", "falconblue", "*"),
    "mldsa": ("ML-DSA-44 (RISC-V)", "mldsaorange", "square"),
    "fors": ("FORS (leanISA + Keccak)", "forsgreen", "triangle*"),
    "raccoon": ("Raccoon-128-1 (RISC-V)", "raccoonpurple", "diamond*"),
    "raccoon-g": ("Raccoon-G HD (RISC-V)", "raccoonggold", "pentagon*"),
}
SOURCES = {}
PURGING_POLICY = "dirty_decay_ms:0,muzzy_decay_ms:0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    raw = path.read_bytes()
    value = hashlib.sha256(raw).hexdigest()
    SOURCES[str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)] = value
    return value


def read(path):
    digest(path)
    return json.loads(path.read_text())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def complete_command(path, binary_hash, runtime=None):
    record = read(path)
    require(record.get("exit_code") == 0 and record.get("aborted") is None
            and record.get("binary_sha256") == binary_hash,
            f"Incomplete or changed command: {path}")
    if runtime is not None:
        actual = record.get("runtime_environment", record.get("environment", {}))
        require(all(actual.get(name) == value for name, value in runtime.items()),
                f"Runtime environment differs from the selected cohort: {path}")
    return record


def environment(directory, segmented=False, selected=False):
    frozen = read(directory / "environment.json")
    require(frozen["schema"] == 1 and frozen["backend_revision"] == PIN
            and frozen["threads_requested"] == 8 and frozen["log_inverse_rate"] == 1,
            "Unexpected frozen Raccoon experiment settings")
    for source, expected in frozen["source_sha256"].items():
        require(digest(ROOT / source) == expected, f"Changed frozen Raccoon source: {source}")
    identities = [frozen] if segmented else list(frozen["schemes"].values())
    for identity in identities:
        require(digest(ROOT / identity["elf"]) == identity["elf_sha256"],
                f"Changed guest ELF: {identity['elf']}")
        require(digest(ROOT / identity["guest_manifest"]) == identity["guest_manifest_sha256"],
                f"Changed guest build manifest: {identity['guest_manifest']}")
    if selected:
        runtime = frozen.get("runtime_environment", frozen.get("environment", {}))
        require(runtime.get("_RJEM_MALLOC_CONF") == PURGING_POLICY
                and runtime.get("MALLOC_CONF") is None
                and runtime.get("LEANVM_NUM_THREADS") == "8",
                f"Unexpected selected allocator/thread policy: {directory}")
    return frozen


def direct(directory, frozen, old, schemes=("raccoon",)):
    rows = []
    runtime = frozen["runtime_environment"]
    for scheme in schemes:
        accepted = 0
        folders = list((directory / scheme / "direct").glob("count-*"))
        require(all(folder.name.removeprefix("count-").isdigit() for folder in folders),
                f"Invalid direct measurement directory for {scheme}")
        folders.sort(key=lambda folder: int(folder.name.removeprefix("count-")))
        for folder in folders:
            report = read(folder / "report.json")
            complete_command(folder / "producer.completed.json", frozen["direct_binary_sha256"], runtime)
            count = int(folder.name.removeprefix("count-"))
            require(count > 0 and report.get("action") == "prove"
                    and report["count"] == count and report["scheme"] == scheme
                    and report["leanvm_revision"] == PIN
                    and report["threads"] == 8 and report["log_inverse_rate"] == 1
                    and report["elf_sha256"] == frozen["schemes"][scheme]["elf_sha256"],
                    f"Wrong direct workload identity: {folder}")
            if report.get("status") == "rejected":
                require("prover_error" in report, f"Refusal not checked by the prover: {folder}")
                continue
            receiver = folder / "public-only-receiver"
            checked = read(receiver / "verification.json")
            complete_command(receiver / "consumer.completed.json", frozen["direct_binary_sha256"], runtime)
            statement_path = Path(str(folder / "root.proof") + ".statement.json")
            statement = read(statement_path)
            statement_hash = digest(statement_path)
            proof_hash = digest(folder / "root.proof")
            require(digest(receiver / "root.proof") == proof_hash
                    and digest(receiver / "statement.json") == statement_hash,
                    f"Changed public-only receiver inputs: {folder}")
            require(folder.name == f"count-{count}" and statement["count"] == count
                    and len(statement["public_records"]) == count,
                    f"Mismatched direct count: {folder}")
            require(report.get("action") == "prove" and report.get("status") == "accepted"
                    and report.get("verified") is True and checked.get("action") == "verify"
                    and checked.get("verified") is True and checked.get("statement_pinned") is True
                    and checked.get("verification_uses_signatures") is False,
                    f"Missing full public-only proof verification: {folder}")
            for item in (report, checked):
                require(item["scheme"] == scheme and item["count"] == count
                        and item["leanvm_revision"] == PIN and item["threads"] == 8
                        and item["log_inverse_rate"] == 1
                        and item["zero_knowledge"] is False
                        and item["elf_sha256"] == frozen["schemes"][scheme]["elf_sha256"]
                        and item["statement_sha256"] == statement_hash
                        and item["proof_sha256"] == proof_hash,
                        f"Direct producer/receiver identity mismatch: {folder}")
            require(report["warmup"] == 1 and len(report["prove_s"]) == 3
                    and len(checked["verify_s"]) == 3
                    and statement["elf_sha256"] == report["elf_sha256"]
                    and statement["scheme"] == scheme
                    and (folder / "root.proof").stat().st_size == report["proof_bytes"]
                    == checked["proof_bytes"], f"Direct sample or byte mismatch: {folder}")
            require(0 < report["execution"]["committed_words"] <= 2**28,
                    f"Accepted direct point exceeds the pinned witness cap: {folder}")
            require(all(math.isfinite(value) and value > 0
                        for value in report["prove_s"] + checked["verify_s"]),
                    f"Invalid direct timing samples: {folder}")
            rows.append(old.measurements(scheme, count, report["proof_bytes_samples"],
                        report["prove_s"], checked["verify_s"], report["peak_rss_bytes"],
                        report["execution"]["committed_words"], report["execution"]["cycles"]))
            accepted += 1
        require(accepted > 0, f"No verified direct Raccoon measurements: {scheme}")
        require(set(range(1, 31)) <= {int(folder.name.removeprefix("count-")) for folder in folders},
                f"Missing attempted direct counts in the approved 1..30 matrix: {scheme}")
    require(len({(row["scheme"], row["count"]) for row in rows}) == len(rows),
            "Duplicate Raccoon direct measurements")
    return rows


def trees(directory, frozen, old, schemes=("raccoon",)):
    rows, samples = [], []
    runtime = frozen["runtime_environment"]
    for scheme in schemes:
        leaf_sizes = set()
        for count in COUNTS:
            folder = directory / scheme / "trees" / f"count-{count}"
            statement_path = folder / "statement.json"
            intended = read(statement_path)
            statement_hash = digest(statement_path)
            leaf_size = intended["leaf_size"]
            leaf_sizes.add(leaf_size)
            actual = count // leaf_size
            slots = max(2, 1 << (actual - 1).bit_length())
            require(count % leaf_size == 0 and intended["signatures"] == count
                    and intended["scheme"] == scheme and intended["backend_revision"] == PIN
                    and intended["elf_sha256"] == frozen["schemes"][scheme]["elf_sha256"]
                    and intended["arity_0"] == intended["arity"] == 2
                    and intended["log_inverse_rate"] == 1
                    and intended["actual_leaves"] == actual and intended["leaf_slots"] == slots
                    and len(intended["public_records"]) == count
                    and len(intended["expected_leaf_outputs"]) == actual,
                    f"Unexpected intended tree: {folder}")
            require(len({r["public_key"] for r in intended["public_records"]}) == count,
                    f"Repeated signers in corpus: {folder}")
            selected = []
            for sample in range(3):
                run = folder / f"sample-{sample}"
                receiver = run / "public-only-receiver"
                report, checked = read(run / "report.json"), read(receiver / "verification.json")
                complete_command(folder / f"sample-{sample}-producer.completed.json",
                                 frozen["tree_binary_sha256"], runtime)
                complete_command(receiver / "consumer.completed.json", frozen["tree_binary_sha256"], runtime)
                require(report.get("status") == "accepted" and report.get("verified") is True
                        and report.get("action") == "prove" and checked.get("action") == "verify"
                        and checked.get("verified") is True and checked.get("statement_pinned") is True
                        and checked.get("verification_uses_signatures") is False
                        and checked.get("verification_uses_child_proofs") is False
                        and all(checked.get("controls", {}).values()) and checked.get("controls"),
                        f"Missing complete public-only tree verification: {run}")
                controls = {"wrong_output", "wrong_leaf_count", "corrupt_root", "trailing_byte",
                            "changed_key_recommitted", "changed_message_recommitted"}
                if actual >= 2:
                    controls.add("reordered_leaves")
                require(controls <= checked["controls"].keys(), f"Missing receiver controls: {run}")
                for item in (report, checked):
                    require(item.get("all_folded_claims_settled") is True
                            and item["zero_knowledge"] is False
                            and item["scheme"] == scheme and item["signatures"] == count
                            and item["backend_revision"] == PIN
                            and item["statement_sha256"] == statement_hash
                            and item["elf_sha256"] == intended["elf_sha256"]
                            and item["actual_leaves"] == actual and item["leaf_slots"] == slots
                            and item["threads_requested"] == 8,
                            f"Tree producer/receiver identity mismatch: {run}")
                require(report["leaf_size"] == leaf_size and report["padding_slots"] == slots - actual
                        and report["arity_0"] == report["arity"] == 2
                        and report["log_inverse_rate"] == 1,
                        f"Changed tree operating point or padding: {run}")
                leaves, merges = report["leaf_reports"], report["merge_reports"]
                require(len(leaves) == actual and len(merges) == report["merge_count"] == slots - 1
                        and all(leaf["signatures"] == leaf_size for leaf in leaves),
                        f"Incorrect fresh leaf or merge work: {run}")
                for kind, reports in (("leaf", leaves), ("merge", merges)):
                    for index, item in enumerate(reports):
                        proof = run / f"{kind}-{index}.proof"
                        require(digest(proof) == item["proof_sha256"]
                                and proof.stat().st_size == item["proof_bytes"],
                                f"Changed intermediate proof: {proof}")
                work = sum(p["prove_s"] for p in leaves + merges)
                require(abs(work - report["total_prove_s"]) < 1e-8,
                        f"Incomplete proving work: {run}")
                proof = run / "root.proof"
                require(digest(proof) == report["root_proof_sha256"] == checked["root_proof_sha256"]
                        and proof.stat().st_size == report["root_proof_bytes"] == checked["root_proof_bytes"],
                        f"Changed complete root: {run}")
                require(digest(receiver / "root.proof") == report["root_proof_sha256"]
                        and digest(receiver / "statement.json") == statement_hash,
                        f"Changed public-only receiver inputs: {run}")
                prepared = checked["prepared_complete_verify_s"]
                cold = checked["program_load_s"] + checked["tree_setup_s"] + checked["first_complete_verify_s"]
                require(len(prepared) == 3 and abs(cold - checked["cold_complete_verify_s"]) < 1e-8,
                        f"Missing full verification costs: {run}")
                require(all(math.isfinite(value) and value > 0
                            for value in [cold, *prepared, *[item["prove_s"] for item in leaves + merges]]),
                        f"Invalid complete-tree timing samples: {run}")
                selected.append({"scheme": scheme, "backend": "RISC-V", "count": count,
                                 "sample": sample, "prove_s": work,
                                 "proof_kib": proof.stat().st_size / 1024,
                                 "verify_cold_ms": 1000 * cold,
                                 "verify_cached_ms": 1000 * statistics.median(prepared),
                                 "claim_ms": 1000 * checked["public_claim_derivation_s"],
                                 "rss_gib": report["peak_rss_bytes"] / 2**30,
                                 "leaf_size": leaf_size, "leaf_count": actual,
                                 "leaf_slots": slots, "padding_slots": slots - actual,
                                 "merge_count": len(merges)})
            samples.extend(selected)
            row = {"scheme": scheme, "backend": "RISC-V", "count": count}
            for field in selected[0]:
                if field not in ("scheme", "backend", "count", "sample"):
                    old.stats(row, field, [item[field] for item in selected])
            rows.append(row)
        require(len(leaf_sizes) == 1, f"Changed leaf operating point across counts: {scheme}")
    return rows, samples


def receipt_parts(proof, statement):
    """Check the actual RGSTK001 wire envelope before counting its bytes."""
    raw = proof.read_bytes()
    count = statement["signatures"]
    require(raw[:8] == b"RGSTK001" and len(raw) >= 60 + 64 * count,
            f"Wrong segmented receipt header: {proof}")
    for offset, expected in zip((8, 12, 16),
                                (count, statement["parts_per_signature"], statement["leaf_slots"])):
        require(int.from_bytes(raw[offset:offset + 4], "little") == expected,
                f"Wrong segmented receipt policy: {proof}")
    require(raw[20:52].hex() == statement["elf_sha256"], f"Wrong receipt ELF: {proof}")
    offset = 52 + 64 * count
    size = int.from_bytes(raw[offset:offset + 8], "little")
    core = raw[offset + 8:]
    require(len(core) == size, f"Truncated or extended segmented receipt: {proof}")
    return raw, core


def segmented_trees(directory, frozen, old, policy):
    require(frozen["scheme"] == "raccoon-g" and frozen["parts_per_signature"] == 5
            and frozen["rows_per_leaf"] == 2 and frozen["rows_per_signature"] == 9,
            "Unexpected segmented G coverage policy")
    runtime = {name: frozen["environment"].get(name)
               for name in ("MALLOC_CONF", "_RJEM_MALLOC_CONF", "LEANVM_NUM_THREADS")}
    samples, raw_timers = [], []
    for count in COUNTS:
        folder = directory / f"count-{count}"
        statement_path = folder / "statement.json"
        intended = read(statement_path)
        statement_hash = digest(statement_path)
        actual = 5 * count
        slots = max(2, 1 << (actual - 1).bit_length())
        require(intended["backend_revision"] == PIN and intended["scheme"] == "raccoon-g"
                and intended["profile"] == frozen["profile"] and intended["signatures"] == count
                and intended["elf_sha256"] == frozen["elf_sha256"]
                and intended["parts_per_signature"] == 5 and intended["rows_per_leaf"] == 2
                and intended["rows_per_signature"] == 9
                and intended["actual_leaves"] == actual and intended["leaf_slots"] == slots
                and intended["arity_0"] == intended["arity"] == 2
                and intended["log_inverse_rate"] == 1
                and len(intended["public_records"]) == count,
                f"Wrong segmented G statement or coverage: {folder}")
        require(len({record["public_key"] for record in intended["public_records"]}) == count,
                f"Repeated G public keys: {folder}")
        plan = read(folder / "plan.json")
        require(plan["status"] == "accepted" and plan["all_100_corpus_leaf_shapes_match"] is True
                and not plan["failures"] and len(plan["leaf_measurements"]) == 500
                and plan["elf_sha256"] == frozen["elf_sha256"],
                f"Missing complete unchanged-corpus G shape check: {folder}")
        for sample in policy["expected_samples"]["raccoon-g"][str(count)]:
            run = folder / f"sample-{sample}"
            receiver = run / "public-only-receiver"
            report, checked = read(run / "report.json"), read(receiver / "verification.json")
            completed = read(run / "pipeline-completed.json")
            complete_command(folder / f"sample-{sample}-producer.completed.json",
                             frozen["binary_sha256"], runtime)
            complete_command(receiver / "consumer.completed.json", frozen["binary_sha256"], runtime)
            require(completed.get("verified_public_only") is True
                    and completed["receiver_inputs"] == ["statement.json", "root.proof"]
                    and completed["binary_sha256"] == frozen["binary_sha256"]
                    and completed["elf_sha256"] == frozen["elf_sha256"]
                    and completed["statement_sha256"] == statement_hash
                    and completed["signatures"] == count and completed["sample"] == sample,
                    f"Incomplete fresh G pipeline: {run}")
            for item in (report, checked):
                require(item.get("verified") is True and item.get("all_folded_claims_settled") is True
                        and item["zero_knowledge"] is False
                        and item["backend_revision"] == PIN and item["scheme"] == "raccoon-g"
                        and item["profile"] == frozen["profile"]
                        and item["elf_sha256"] == frozen["elf_sha256"]
                        and item["statement_sha256"] == statement_hash
                        and item["signatures"] == count and item["parts_per_signature"] == 5
                        and item["rows_per_leaf"] == 2 and item["rows_per_signature"] == 9
                        and item["actual_leaves"] == actual and item["leaf_slots"] == slots
                        and item["threads_requested"] == 8,
                        f"G producer/receiver identity mismatch: {run}")
            require(report["action"] == "prove" and report["status"] == "accepted"
                    and checked["action"] == "verify" and checked["statement_pinned"] is True
                    and checked["verification_uses_signatures"] is False
                    and checked["verification_uses_child_proofs"] is False
                    and checked["witness_bindings_are_untrusted_auxiliary"] is True
                    and report["padding_slots"] == slots - actual
                    and report["arity_0"] == report["arity"] == 2
                    and report["log_inverse_rate"] == 1,
                    f"Incomplete G receipt verification: {run}")
            controls = {"trailing_byte", "truncated_receipt", "changed_binding", "corrupt_root",
                        "wrong_leaf_count", "reordered_parts", "duplicated_part_missing_coverage",
                        "changed_key_recommitted", "changed_message_recommitted",
                        "changed_signature_count", "changed_parts_policy"}
            require(controls <= checked.get("controls", {}).keys()
                    and all(checked["controls"].values()), f"Missing G rejection controls: {run}")
            leaves, merges = report["leaf_reports"], report["merge_reports"]
            require(len(leaves) == actual and len(merges) == report["merge_count"] == slots - 1
                    and len(report["native_prepare_samples_s"]) == count,
                    f"Incorrect G leaf, merge or preparation count: {run}")
            for index, leaf in enumerate(leaves):
                require(leaf["leaf"] == index and leaf["signature"] == index // 5
                        and leaf["part"] == index % 5, f"Wrong G part coverage: {run}")
            for kind, items in (("leaf", leaves), ("merge", merges)):
                for index, item in enumerate(items):
                    proof = run / f"{kind}-{index}.proof"
                    require(digest(proof) == item["proof_sha256"]
                            and proof.stat().st_size == item["proof_bytes"],
                            f"Changed G intermediate proof: {proof}")
            preparation = sum(report["native_prepare_samples_s"])
            work = preparation + sum(item["prove_s"] for item in leaves + merges)
            require(abs(preparation - report["native_prepare_s"]) < 1e-8
                    and abs(work - report["total_prove_s"]) < 1e-8,
                    f"Missing charged G witness preparation or proof work: {run}")
            proof = run / "root.proof"
            raw, core = receipt_parts(proof, intended)
            proof_hash = digest(proof)
            require(proof_hash == completed["root_proof_sha256"] == report["root_proof_sha256"]
                    == checked["root_proof_sha256"]
                    and len(raw) == report["root_proof_bytes"] == checked["root_proof_bytes"]
                    and len(core) == report["root_core_bytes"] == checked["root_core_bytes"]
                    and hashlib.sha256(core).hexdigest() == report["root_core_sha256"]
                    and len(raw) - len(core) == report["auxiliary_bytes"]
                    == checked["auxiliary_bytes"] == 60 + 64 * count
                    and digest(receiver / "root.proof") == proof_hash
                    and digest(receiver / "statement.json") == statement_hash,
                    f"Wrong complete G receipt bytes or identity: {run}")
            full, core_times = checked["prepared_complete_verify_s"], checked["prepared_core_verify_s"]
            configuration = checked["public_configuration_prepare_s"]
            cold = configuration + checked["program_load_s"] + checked["tree_setup_s"] + checked["first_complete_verify_s"]
            require(len(full) == len(core_times) == 3
                    and abs(cold - checked["cold_complete_verify_s"]) < 1e-8,
                    f"Wrong G verification sample/accounting scope: {run}")
            require(all(math.isfinite(value) and value > 0
                        for value in [work, cold, *full, *core_times]),
                    f"Invalid G timings: {run}")
            samples.append({"scheme": "raccoon-g", "backend": "RISC-V-segmented",
                "count": count, "sample": sample, "prove_s": work,
                "proof_kib": len(raw) / 1024, "core_kib": len(core) / 1024,
                "auxiliary_kib": (len(raw) - len(core)) / 1024,
                "rss_gib": report["peak_rss_bytes"] / 2**30,
                "leaf_count": actual, "leaf_slots": slots, "padding_slots": slots - actual,
                "merge_count": len(merges), "parts_per_signature": 5, "rows_per_leaf": 2,
                "native_prepare_s": preparation, "verify_cold_ms": 1000 * cold,
                "verify_cached_ms": 1000 * statistics.median(full),
                "claim_ms": 1000 * checked["public_claim_derivation_s"],
                "full_cold_ms": 1000 * cold,
                "full_prepared_ms": 1000 * (configuration + statistics.median(full)),
                "core_prepared_ms": 1000 * statistics.median(core_times),
                "public_processing_ms": 1000 * (configuration + checked["public_claim_derivation_s"]),
                "timing_kind": "Measured complete calls plus separately measured public configuration"})
            raw_timers.append({"scheme": "raccoon-g", "count": count, "sample": sample,
                "public_configuration_prepare_s": configuration,
                "public_claim_derivation_s": checked["public_claim_derivation_s"],
                "program_load_s": checked["program_load_s"], "tree_setup_s": checked["tree_setup_s"],
                "first_complete_verify_s": checked["first_complete_verify_s"],
                "prepared_complete_verify_s": json.dumps(full),
                "prepared_core_verify_s": json.dumps(core_times),
                "complete_includes_public_derivation": True})
    return samples, raw_timers


def regular_timers(samples, standard_directory):
    """Retain raw scopes and add explicitly derived end-to-end quantities."""
    raw_timers = []
    for item in samples:
        if item["scheme"] == "fors":
            path = ROOT / f"leanISA/reduction/results/trees/fors-{item['count']}/sample-{item['sample']}/verification.json"
        elif item["scheme"] == "raccoon":
            path = standard_directory / f"raccoon/trees/count-{item['count']}/sample-{item['sample']}/public-only-receiver/verification.json"
        else:
            path = ROOT / f"risc-v/results/trees/{item['scheme']}-{item['count']}/sample-{item['sample']}/verification.json"
        checked = read(path)
        claim = checked["public_claim_derivation_s"]
        core = checked["prepared_complete_verify_s"]
        item["full_cold_ms"] = item["verify_cold_ms"] + 1000 * claim
        item["full_prepared_ms"] = item["verify_cached_ms"] + 1000 * claim
        item["core_prepared_ms"] = item["verify_cached_ms"]
        item["public_processing_ms"] = 1000 * claim
        item["timing_kind"] = "Derived sum: separately measured public claims plus complete proof verification"
        raw_timers.append({"scheme": item["scheme"], "count": item["count"], "sample": item["sample"],
            "public_claim_derivation_s": claim, "cold_complete_verify_s": checked["cold_complete_verify_s"],
            "prepared_complete_verify_s": json.dumps(core),
            "program_load_or_compile_s": checked.get("program_load_s", checked.get("program_compile_s")),
            "tree_setup_or_table_prepare_s": checked.get("tree_setup_s", checked.get("table_prepare_s")),
            "first_complete_verify_s": checked["first_complete_verify_s"],
            "complete_includes_public_derivation": False})
    return raw_timers


def aggregate(samples, old, policy):
    rows = []
    for scheme in SCHEMES:
        for count in COUNTS:
            selected = [item for item in samples if item["scheme"] == scheme and item["count"] == count]
            expected = policy["expected_samples"].get(scheme, {}).get(str(count), [0, 1, 2])
            require(len(selected) == len(expected) and {item["sample"] for item in selected} == set(expected),
                    f"Missing authorized complete pipelines: {scheme} {count}")
            row = {"scheme": scheme, "backend": selected[0]["backend"], "count": count,
                   "sample_count": len(selected),
                   "statistic": "single measured pipeline" if len(selected) == 1 else "median of three fresh pipelines",
                   "timing_kind": selected[0]["timing_kind"]}
            for field in selected[0]:
                if field not in row and field != "sample" and isinstance(selected[0][field], (int, float)):
                    old.stats(row, field, [item[field] for item in selected])
            rows.append(row)
    return rows


def refusal_ledger(directory, frozen):
    """Retain failed experiments as failures, never as zero-valued curve points."""
    rows = []
    for scheme in NEW:
        for count in range(1, 65):
            folder = directory / scheme / "capacity"
            report = read(folder / f"count-{count}.json")
            complete_command(folder / f"count-{count}.completed.json", frozen["direct_binary_sha256"])
            require(report["action"] == "measure" and report["status"] == "rejected"
                    and report["scheme"] == scheme and report["count"] == count
                    and report["elf_sha256"] == frozen["schemes"][scheme]["elf_sha256"]
                    and report["leanvm_revision"] == PIN,
                    f"Unexpected original capacity result: {scheme} {count}")
            rows.append({"cohort": str(directory.relative_to(ROOT)), "scheme": scheme,
                         "study": "capacity", "count": count, "status": "rejected",
                         "error": report["error"], "elf_sha256": report["elf_sha256"],
                         "proof_produced": False})
        for count in range(1, 31):
            folder = directory / scheme / "direct" / f"count-{count}"
            report = read(folder / "report.json")
            complete_command(folder / "producer.completed.json", frozen["direct_binary_sha256"])
            require(report["action"] == "prove" and report["status"] == "rejected"
                    and "prover_error" in report and report["scheme"] == scheme
                    and report["count"] == count and report["leanvm_revision"] == PIN
                    and report["elf_sha256"] == frozen["schemes"][scheme]["elf_sha256"],
                    f"Missing original actual prover refusal: {folder}")
            rows.append({"cohort": str(directory.relative_to(ROOT)), "scheme": scheme,
                         "study": "direct prover", "count": count, "status": "rejected",
                         "error": report["prover_error"], "elf_sha256": report["elf_sha256"],
                         "proof_produced": False})
        for count in COUNTS:
            for sample in range(3):
                folder = directory / scheme / "tree-attempts" / f"count-{count}" / f"sample-{sample}"
                command = read(folder / "preflight.completed.json")
                error = read(folder / "error.json")
                args = command["command"]
                require(command.get("exit_code") != 0 and command.get("aborted") is None
                        and command["binary_sha256"] == frozen["tree_binary_sha256"]
                        and error["action"] == "plan" and error["backend_revision"] == PIN
                        and args[1] == "plan" and args[args.index("--scheme") + 1] == scheme
                        and args[args.index("--n") + 1] == str(count),
                        f"Missing original failed fresh tree preflight: {folder}")
                rows.append({"cohort": str(directory.relative_to(ROOT)), "scheme": scheme,
                             "study": "tree preflight", "count": count, "sample": sample,
                             "status": "rejected before proving", "error": error["error"],
                             "elf_sha256": frozen["schemes"][scheme]["elf_sha256"],
                             "proof_produced": False})
    return rows


def sampling_policy(directory):
    policy = read(directory / "sampling-policy.json")
    expected = {scheme: {str(count): [0, 1, 2] for count in COUNTS} for scheme in NEW}
    expected["raccoon-g"]["100"] = [0]
    require(policy["status"] == "user_approved_reduced_repetitions"
            and policy["expected_samples"] == expected
            and policy["required_retained_complete_tree_pipelines"] == 22
            and policy["accepted_guard_pipeline_counts"] == {"19_GiB": 17, "20_GiB": 5}
            and policy["no_further_proving_authorized_for_this_matrix"] is True,
            "Sampling policy does not match the user's reduced benchmark scope")
    progress = read(directory / "progress.json")
    require(progress["status"] == "user_stopped" and len(progress["completed_samples"]) == 22,
            "Final matrix is not stopped with the authorized completed samples")
    return policy


def user_stop_ledger(directory, segmented_environment, policy):
    archive = ROOT / policy["user_stop_archive"]
    manifest = read(archive / "manifest.json")
    mapping = read(archive / "archive-mapping.json")
    stopped = read(archive / "stop-confirmation.json")
    require(manifest["classification"] == "user_requested_stop"
            and manifest["proof_capacity_failure"] is False
            and manifest["resident_memory_failure"] is False
            and manifest["counted_as_accepted_curve_sample"] is False
            and manifest["verified_complete_root_exists_for_stopped_sample"] is False
            and manifest["completed_required_roots_after_user_scope_change"] == 22
            and manifest["saved_leaf_proofs"] == 7 and manifest["saved_merge_proofs"] == 0
            and manifest["sample_2_never_started"] is True
            and stopped["producers_idle"] is True
            and stopped["no_more_benchmark_authorized"] is True
            and set(mapping) == set(manifest["files"]) and len(mapping) == 12,
            "User-stopped attempt misclassified or producers not confirmed idle")
    for original, expected in manifest["files"].items():
        entry = mapping[original]
        path = (archive / entry["archived"]).resolve()
        require(archive.resolve() in path.parents and entry["sha256"] == expected
                and digest(path) == expected, f"Changed user-stop evidence: {original}")
    original_sample = "risc-v/results/" + manifest["original_sample"]
    record = read(archive / mapping[original_sample + "/report.json"]["archived"])
    require(record["elf_sha256"] == segmented_environment["elf_sha256"]
            and record["status"] == "running" and len(record["leaf_reports"]) == 7
            and not record["merge_reports"] and "root_proof_bytes" not in record
            and not (ROOT / original_sample).exists()
            and not (ROOT / original_sample).with_name("sample-2").exists(),
            "User-stopped partial sample entered the selected measurement cohort")
    return [{"scheme": "raccoon-g", "count": 100, "sample": 1,
             "classification": "user requested stop", "saved_partial_leaves": 7,
             "saved_partial_leaf_prove_s": manifest["saved_partial_leaf_prove_s"],
             "saved_merges": 0, "complete_root_produced": False,
             "included_in_successful_medians": False, "proof_capacity_failure": False,
             "archive": str(archive.relative_to(ROOT)), "archived_files_checked": len(mapping)}]


def forecast_rows(directory):
    """Independently recompute the G70-based forecast, separate from all curves."""
    forecast = read(directory / "g100-estimate.json")
    require(forecast["classification"] == "heuristic_estimate_not_a_benchmark_measurement"
            and forecast["basis_signatures"] == 70 and forecast["target_signatures"] == 100
            and forecast["basis_and_target_leaf_slots"] == 512
            and forecast["basis_and_target_merge_count"] == 511
            and len(forecast["basis"]) == 3, "Wrong independent forecast basis")
    times, sizes = [], []
    rows = []
    for basis in forecast["basis"]:
        path = ROOT / basis["report"]
        require(digest(path) == basis["report_sha256"], "Changed forecast basis report")
        report = read(path)
        leaf = sum(item["prove_s"] for item in report["leaf_reports"])
        merge = sum(item["prove_s"] for item in report["merge_reports"])
        require(abs(leaf - basis["leaf_prove_s"]) < 1e-8
                and abs(merge - basis["merge_prove_s"]) < 1e-8
                and report["native_prepare_s"] == basis["native_prepare_s"]
                and report["root_core_bytes"] == basis["root_core_bytes"], "Forecast component mismatch")
        estimate = (leaf + report["native_prepare_s"]) * (100 / 70) + merge
        require(abs(estimate - basis["estimated_100_s"]) < 1e-8, "Wrong forecast formula")
        times.append(estimate)
        sizes.append(report["root_core_bytes"])
        rows.append({"classification": "heuristic estimate, not a benchmark", "basis_sample": basis["sample"],
                     "basis_count": 70, "target_count": 100, "estimated_prove_s": estimate,
                     "estimated_receipt_bytes": report["root_core_bytes"] + 60 + 6400,
                     "included_in_measured_curves": False})
    require(abs(statistics.median(times) - forecast["estimated_time_s"]["median"]) < 1e-8
            and statistics.median(sizes) + 60 + 6400 == forecast["estimated_receipt_bytes"],
            "Wrong forecast summary")
    actual = forecast["actual_single_run_validation"]
    require(digest(ROOT / actual["report"]) == actual["report_sha256"]
            and actual["sample_count"] == 1, "Changed independent G100 validation report")
    actual_report = read(ROOT / actual["report"])
    require(abs(actual_report["total_prove_s"] - actual["actual_prove_s"]) < 1e-8
            and actual_report["root_proof_bytes"] == actual["actual_receipt_bytes"],
            "G100 actual and forecast validation disagree")
    return rows, forecast


def resource_stop_ledger(directory, segmented_environment, standard_directory, segmented_directory, policy):
    """Verify archived operational failures without turning them into samples.

    Called only during final figure generation, after timed producers are idle.
    Original paths can now hold a fresh retry, so hashes use archive-mapping.json.
    """
    transition = read(directory / "guard-policy-transition.json")
    require(transition["old_operational_rss_stop_bytes"] == 19 * 2**30
            and transition["new_operational_rss_stop_bytes"] == 20 * 2**30
            and transition["backend_committed_words_cap_unchanged"] == 2**28
            and transition["timeout_s_unchanged"] == 21600
            and transition["native_binaries_and_guest_elfs_unchanged"] is True
            and transition["allocator_policy_unchanged"] == PURGING_POLICY
            and transition["failed_attempt_reused"] is False,
            "Unexpected operational-guard transition")
    coordinator_hash = digest(ROOT / "risc-v/scripts/raccoon_full_matrix.py")
    require(coordinator_hash == transition["coordinator_sha256_unchanged"],
            "Coordinator changed across the operational-guard transition")
    rows, archives = [], []
    for manifest_path in sorted((directory / "resource-stops").glob("*/manifest.json")):
        archive = manifest_path.parent
        manifest = read(manifest_path)
        mapping = read(archive / "archive-mapping.json")
        require(manifest["classification"] == "operational_resident_memory_limit"
                and manifest["proof_capacity_failure"] is False
                and manifest["counted_as_accepted_curve_sample"] is False
                and manifest["verified_complete_root_exists"] is False
                and manifest["partial_proof_reuse_allowed"] is False
                and manifest["backend_committed_words_cap_unchanged"] == 2**28
                and manifest["coordinator_sha256"] == coordinator_hash
                and manifest["operational_stop_bytes"] == 19 * 2**30
                and set(mapping) == set(manifest["files"]),
                f"Wrong operational-stop classification or archive mapping: {archive}")
        for original_path, expected in manifest["files"].items():
            entry = mapping[original_path]
            archived_path = (archive / entry["archived"]).resolve()
            require(archive.resolve() in archived_path.parents and entry["sha256"] == expected
                    and digest(archived_path) == expected,
                    f"Changed archived interrupted-attempt evidence: {original_path}")
        original_sample = "risc-v/results/" + manifest["original_sample"]
        report_path = original_sample + "/report.json"
        command_path = original_sample + "-producer.completed.json"
        report = read(archive / mapping[report_path]["archived"])
        command = read(archive / mapping[command_path]["archived"])
        require(command["aborted"] == "resident_memory_limit" and command["exit_code"] != 0
                and command["rss_limit_bytes"] == manifest["operational_stop_bytes"]
                and command["binary_sha256"] == segmented_environment["binary_sha256"]
                and report["elf_sha256"] == segmented_environment["elf_sha256"]
                and report["status"] == "running" and report["signatures"] == 70
                and report["sample"] == "sample-2"
                and len(report["leaf_reports"]) == manifest["saved_leaf_proofs"] == 71
                and len(report["merge_reports"]) == manifest["saved_merge_proofs"] == 0
                and "root_proof_bytes" not in report and "peak_rss_bytes" not in report,
                f"Interrupted attempt was misclassified as a complete proof: {archive}")
        replacement = read(ROOT / original_sample / "pipeline-completed.json")
        replacement_command = read(ROOT / (original_sample + "-producer.completed.json"))
        require(replacement["verified_public_only"] is True
                and replacement["binary_sha256"] == command["binary_sha256"]
                and replacement["elf_sha256"] == report["elf_sha256"]
                and replacement_command["rss_limit_bytes"] == 20 * 2**30
                and datetime.fromisoformat(replacement_command["started_utc"])
                > datetime.fromisoformat(command["finished_utc"]),
                "The interrupted pipeline lacks its separately verified fresh replacement")
        stopped_path = "risc-v/results/raccoon-full-matrix/progress.json"
        stopped = read(archive / mapping[stopped_path]["archived"])
        previous_samples = stopped["completed_samples"]
        require(len(previous_samples) == manifest["completed_requested_pipelines"]
                == transition["completed_requested_samples_to_preserve"] == 17,
                "Wrong number of previously completed pipelines at the operating stop")
        for previous in previous_samples:
            if previous["scheme"] == "raccoon":
                previous_folder = standard_directory / f"raccoon/trees/count-{previous['count']}"
            else:
                require(previous["scheme"] == "raccoon-g", "Unknown preserved scheme")
                previous_folder = segmented_directory / f"count-{previous['count']}"
            previous_report = read(previous_folder / f"sample-{previous['sample']}/report.json")
            require(previous_report["root_proof_sha256"] == previous["root_proof_sha256"]
                    and previous_report["statement_sha256"] == previous["statement_sha256"]
                    and previous_report["elf_sha256"] == previous["elf_sha256"]
                    and previous_report["root_proof_bytes"] == previous["root_proof_bytes"]
                    and abs(previous_report["total_prove_s"] - previous["total_prove_s"]) < 1e-8,
                    "A completed sample changed after the operational stop")
        rows.append({"scheme": "raccoon-g", "count": 70, "sample": 2,
                     "classification": "operational resident-memory stop",
                     "elapsed_s": command["process_elapsed_s"],
                     "sampled_rss_stop_target_bytes": command["rss_limit_bytes"],
                     "new_sampled_rss_stop_target_bytes": transition["new_operational_rss_stop_bytes"],
                     "measured_failed_peak_rss_bytes": None,
                     "saved_partial_leaves": len(report["leaf_reports"]), "saved_merges": 0,
                     "complete_root_produced": False, "included_in_successful_medians": False,
                     "partial_proof_reuse_allowed": False,
                     "backend_committed_words_cap": 2**28,
                     "archive": str(archive.relative_to(ROOT)),
                     "archived_files_checked": len(mapping)})
        archives.append(str(archive.relative_to(ROOT)))
    require(len(rows) == 1 and rows[0]["archived_files_checked"] == 77,
            "Expected the disclosed single interrupted G70 attempt with 77 archived files")
    guard_counts = {19 * 2**30: 0, 20 * 2**30: 0}
    for scheme, base in (("raccoon", standard_directory / "raccoon/trees"),
                         ("raccoon-g", segmented_directory)):
        for count in COUNTS:
            for sample in policy["expected_samples"][scheme][str(count)]:
                command = read(base / f"count-{count}/sample-{sample}-producer.completed.json")
                require(command["rss_limit_bytes"] in guard_counts
                        and command["aborted"] is None and command["exit_code"] == 0,
                        f"Unexpected completed-pipeline operating guard: {scheme} {count} {sample}")
                guard_counts[command["rss_limit_bytes"]] += 1
    require(guard_counts == {19 * 2**30: 17, 20 * 2**30: 5},
            "Completed pipeline guards do not match the disclosed transition")
    return rows, {"transition": str((directory / "guard-policy-transition.json").relative_to(ROOT)),
                  "archives": archives, "interrupted_attempts": len(rows),
                  "initial_sampled_rss_target_bytes": 19 * 2**30,
                  "resumed_sampled_rss_target_bytes": 20 * 2**30,
                  "completed_pipelines_at_initial_target": 17,
                  "completed_pipelines_at_resumed_target": 5,
                  "previously_completed_sample_hashes_and_proving_totals_preserved": True,
                  "failed_peak_rss_recorded": False,
                  "effect_on_curves": "No interrupted elapsed time, partial-proof size or partial leaf count enters a successful curve or median"}


def capacity_comparison(standard_directory, segmented_directory, original):
    diagnostic = read(ROOT / "risc-v/experiments/raccoon-fit/diagnostic-summary.json")
    require(diagnostic["backend_revision"] == PIN and diagnostic["cap_words"] == 2**28,
            "Wrong raw-layout diagnostic backend or cap")
    rows = []
    for scheme, key in (("raccoon", "raccoon"), ("raccoon-g", "raccoong")):
        item = diagnostic["records"][key]
        require(item["elf_sha256"] == original["schemes"][scheme]["elf_sha256"]
                and item["production_measure"]["accepted"] is False
                and item["committed_words"] > 2**28,
                "Uncapped diagnostic does not match the refused production guest")
        rows.append({"label": "Original Raccoon whole" if scheme == "raccoon" else "Original G whole",
                     "scope": "Uncapped layout diagnostic; production refused", "scheme": scheme,
                     "committed_words": item["committed_words"], "diagnostic": 1})
    direct = read(standard_directory / "raccoon/direct/count-1/report.json")
    partial = read(segmented_directory / "count-10/sample-0/report.json")["leaf_reports"][0]
    rows.insert(1, {"label": "Selected Raccoon whole", "scope": "Actual verified whole-signature proof",
                    "scheme": "raccoon", "committed_words": direct["execution"]["committed_words"], "diagnostic": 0})
    rows.append({"label": "Selected G two-row part", "scope": "Actual verified partial proof; five parts per signature",
                 "scheme": "raccoon-g", "committed_words": partial["execution"]["committed_words"], "diagnostic": 0})
    for index, row in enumerate(rows):
        row["index"] = index
        row["million_words"] = row["committed_words"] / 1e6
    return rows


def colors(document):
    return document.replace(r"\begin{document}",
        "\\definecolor{raccoonpurple}{HTML}{CC79A7}\n"
        "\\definecolor{raccoonggold}{HTML}{E69F00}\n\\begin{document}")


def profile_note(document, text=None, y=-1.1):
    text = text or (r"G: five linked two-row parts per signature, with native preparation charged.\\"
                    r"Public keys/messages are additional transport; G receipts include 64 binding bytes per signature.")
    note = (r"\node[font=\scriptsize,align=center,anchor=north] at (7.85cm,-1.1cm)"
            "{" + text + "};")
    note = note.replace("-1.1cm", f"{y:g}cm")
    return document.replace(r"\end{tikzpicture}", note + "\n" + r"\end{tikzpicture}")


def direct_verification_document(verification_memory_document):
    """Export only direct verification with a centered, compact legend."""
    parts = verification_memory_document.split(r"\begin{axis}")
    require(len(parts) == 3, "Expected verification and memory panels")
    axis = r"\begin{axis}" + parts[1].split(r"\end{axis}", 1)[0] + "\\end{axis}\n"
    require("title={Direct batch verification}" in axis, "Unexpected verification panel")
    axis = axis.replace("Raccoon-128-1 (RISC-V)", "Raccoon-128 (RISC-V)")
    axis = axis.replace("FORS (leanISA + Keccak)", "FORS (leanISA)")
    axis = axis.replace("at={(1.15,1.2)}", "at={(0.5,1.2)}")
    axis = axis.replace("legend columns=3", "legend columns=2")
    return parts[0] + axis + "\\end{tikzpicture}\n\\end{document}\n"


def prover_document(batching_document, verification_memory_document):
    """Combine the existing proving panels without changing their plot data."""
    def axes(document):
        return [r"\begin{axis}" + part.split(r"\end{axis}", 1)[0]
                + "\\end{axis}\n" for part in document.split(r"\begin{axis}")[1:]]

    top = axes(batching_document)
    memory = axes(verification_memory_document)
    require(len(top) == 2 and len(memory) == 2, "Expected two original panels per figure")
    require("title={Direct batch proof size}" in top[0]
            and "title={Direct batch proving}" in top[1]
            and "title={Prover memory}" in memory[1], "Unexpected prover panels")
    require("name=panel1,at={(8.6cm,0cm)}" in memory[1], "Unexpected memory-panel position")
    bottom = memory[1].replace("name=panel1,at={(8.6cm,0cm)}",
                               "name=panel2,at={(4.3cm,-5.8cm)}")
    header = batching_document.split(r"\begin{axis}", 1)[0]
    return header + "".join(top) + bottom + "\\end{tikzpicture}\n\\end{document}\n"


def tree_document(rows, verification=False):
    panels = [("full_cold_ms", "Total verification time (ms)",
               r"\shortstack{Complete verification\\[2pt]\footnotesize $T_{\text{first use}}\approx T_{\text{setup}}+T_{\text{public processing}}+T_{\text{proof checks}}$}"),
              ("full_prepared_ms", "Total verification time (ms)",
               r"\shortstack{Complete verification (setup cached)\\[2pt]\footnotesize $T_{\text{prepared}}\approx T_{\text{public processing}}+T_{\text{proof checks}}$}"),
              ("core_prepared_ms", "Proof checks (ms)",
               r"\shortstack{Proof checks only\\[2pt]\footnotesize $T_{\text{proof checks}}$ (public statement already prepared)}"),
              ("public_processing_ms", "Public processing (ms)",
               r"\shortstack{Preparing the public statement\\[2pt]\footnotesize $T_{\text{public processing}}$ (all keys and messages)}")] if verification else [
              ("prove_s", "Proving work (s)", "Fresh leaves and merges"),
              ("proof_kib", "Complete aggregate (KiB)", "Serialized aggregate proof")]
    axes = []
    for panel, (field, ylabel, title) in enumerate(panels):
        scale = "ymin=0," if field == "proof_kib" else "ymode=log,log basis y=10,"
        position = (8.6 * (panel % 2), -7.2 * (panel // 2))
        axes.append("\\begin{axis}["
            f"at={{({position[0]}cm,{position[1]}cm)}},width=7.1cm,height=5.3cm,title={{{title}}},ylabel={{{ylabel}}},"
            + scale + r"xlabel={Distinct signatures},xmin=5,xmax=105,xtick={10,30,70,100},grid=major,"
            r"grid style={gray!15},tick label style={font=\small},label style={font=\small},"
            r"title style={font=\small},scaled y ticks=false,line width=0.9pt,"
            r"legend style={font=\scriptsize,draw=none,fill=none,at={(1.15,1.25)},anchor=south,legend columns=3}]")
        for scheme, (label, color, mark) in SCHEMES.items():
            error = "" if field == "proof_kib" else r",error bars/.cd,y dir=both,y explicit"
            columns = f"x=count,y={field},col sep=comma"
            if error:
                columns += f",y error minus={field}_error_minus,y error plus={field}_error_plus"
            filename = f"tree-{scheme}.csv" if scheme != "raccoon-g" else "tree-raccoon-g-repeated.csv"
            mark_options = f",mark options={{fill={color},draw={color}}}" if mark.endswith("*") else ""
            axes.append(f"\\addplot+[color={color},mark={mark},mark size=2.1pt{mark_options}{error}] "
                        f"table[{columns}] {{{filename}}};")
            if panel == 0:
                axes.append(f"\\addlegendentry{{{label}}}")
            if scheme == "raccoon-g":
                axes.append(f"\\addplot[color={color},dashed,no marks,forget plot] "
                            f"table[x=count,y={field},col sep=comma] {{tree-raccoon-g-last-segment.csv}};")
                axes.append(f"\\addplot[color={color},only marks,mark={mark},mark size=2.6pt,"
                            f"mark options={{fill=white}},forget plot] "
                            f"table[x=count,y={field},col sep=comma] {{tree-raccoon-g-single.csv}};")
        axes.append(r"\end{axis}")
    document = colors(r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\definecolor{falconblue}{HTML}{0072B2}
\definecolor{mldsaorange}{HTML}{D55E00}
\definecolor{forsgreen}{HTML}{009E73}
\begin{document}
\begin{tikzpicture}
AXES
\end{tikzpicture}
\end{document}
""".replace("AXES", "\n".join(axes)))
    if verification:
        document = document.replace(r"\usepackage{pgfplots}", "\\usepackage{pgfplots}\n\\usepackage{amsmath}")
        document = document.replace("at={(1.15,1.25)}", "at={(1.15,1.33)}")
    return document.replace("Raccoon-128-1 (RISC-V)", "Raccoon-128 (RISC-V)").replace(
        "FORS (leanISA + Keccak)", "FORS (leanISA)")


def capacity_document(rows):
    labels = (r"{Raccoon whole\\original port},{Raccoon whole\\selected port},"
              r"{G whole\\original port},{G two-row part\\selected port}")
    plots = []
    for row in rows:
        color = "raccoonpurple" if row["scheme"] == "raccoon" else "raccoonggold"
        pattern = f",pattern=north east lines,pattern color={color}" if row["diagnostic"] else ""
        plots.append(f"\\addplot+[bar shift=0pt,draw={color},fill={color}!65{pattern}] coordinates {{({row['index']},{row['million_words']:.9f})}};")
    return colors(r"""\documentclass[tikz,border=5pt]{standalone}
\usepackage{pgfplots}
\usetikzlibrary{patterns}
\pgfplotsset{compat=1.18}
\begin{document}
\begin{tikzpicture}
\begin{axis}[width=15.7cm,height=6cm,ybar,bar width=25pt,ymin=0,
ylabel={Committed witness words (millions)},
xtick={0,1,2,3},xticklabels={LABELS},x tick label style={font=\small,align=center},
xmin=-0.6,xmax=3.6,grid=major,grid style={gray!15},scaled y ticks=false,
tick label style={font=\small},label style={font=\small}]
PLOTS
\addplot[sharp plot,gray,dashed,no marks,forget plot] coordinates {(-0.6,268.435456) (3.6,268.435456)};
\node[font=\scriptsize,anchor=south east] at (axis cs:3.5,268.435456) {$2^{28}$ production cap};
\end{axis}
\node[font=\scriptsize,align=center,anchor=north] at (7.85cm,-1.45cm)
{Hatched bars: uncapped layout diagnostics, rejected by production. Solid bars: actual verified proof layouts.\\
The G partial leaf checks two rows; a complete signature requires five linked leaves.};
\end{tikzpicture}
\end{document}
""".replace("LABELS", labels).replace("PLOTS", "\n".join(plots)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", "--standard-study", dest="standard_study", type=Path,
                        default=ROOT / "risc-v/results/raccoon-runtime-study")
    parser.add_argument("--segmented-study", type=Path,
                        default=ROOT / "risc-v/results/raccoong-segmented-uniform-trees")
    parser.add_argument("--reference-study", type=Path,
                        default=ROOT / "risc-v/results/raccoon-study")
    parser.add_argument("--matrix-control", type=Path,
                        default=ROOT / "risc-v/results/raccoon-full-matrix")
    parser.add_argument("--output", type=Path, default=ROOT / "results/mine/raccoon-figures")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    standard, segmented = args.standard_study.resolve(), args.segmented_study.resolve()
    reference, output = args.reference_study.resolve(), args.output.resolve()
    require(output != ROOT / "results/mine/figures", "Use an additive output directory")
    require(not output.exists(), "Choose a new output directory; existing figures are preserved")
    original_directory = ROOT / "results/mine/figures"
    original_provenance = read(original_directory / "provenance.json")
    for source, expected in original_provenance["source_sha256"].items():
        require(digest(ROOT / source) == expected, f"An original three-scheme input changed: {source}")
    original_snapshot = {str(path.relative_to(ROOT)): digest(path)
                         for path in original_directory.iterdir() if path.is_file()}
    frozen = environment(standard, selected=True)
    segmented_environment = environment(segmented, segmented=True, selected=True)
    reference_environment = environment(reference)
    old = module("mine_original_figures", ROOT / "articles/scripts/mine_figures.py")
    helper = module("raccoon_plot_helper", ROOT / "risc-v/scripts/figures.py")
    policy = sampling_policy(args.matrix_control.resolve())
    new_direct = direct(standard, frozen, old)
    _, standard_samples = trees(standard, frozen, old)
    segmented_samples, segmented_raw_timers = segmented_trees(segmented, segmented_environment, old, policy)
    failures = refusal_ledger(reference, reference_environment)
    resource_stops, guard_history = resource_stop_ledger(args.matrix_control.resolve(), segmented_environment,
                                                        standard, segmented, policy)
    user_stops = user_stop_ledger(args.matrix_control.resolve(), segmented_environment, policy)
    estimates, forecast = forecast_rows(args.matrix_control.resolve())
    direct_rows = old.direct() + new_direct
    direct_rows.sort(key=lambda row: (list(SCHEMES).index(row["scheme"]), row["count"]))
    _, rv_samples = old.riscv_trees()
    _, fors_samples = old.reduced_fors_trees()
    regular_samples = rv_samples + fors_samples + standard_samples
    raw_timers = regular_timers(regular_samples, standard) + segmented_raw_timers
    tree_samples = regular_samples + segmented_samples
    tree_rows = aggregate(tree_samples, old, policy)
    require(len(tree_samples) == 58 and len(tree_rows) == 20, "Wrong authorized curve/sample count")
    capacity = capacity_comparison(standard, segmented, reference_environment)
    SOURCES.update(old.SOURCES)
    helper.SCHEMES = {scheme: label for scheme, label in SCHEMES.items()
                      if any(row["scheme"] == scheme for row in direct_rows)}
    # Create outputs only after every included root and receiver passed validation.
    output.mkdir(parents=True)
    old.write_csv(output / "measurements.csv", direct_rows)
    old.write_csv(output / "recursive-trees.csv", tree_rows)
    old.write_csv(output / "recursive-tree-samples.csv", tree_samples)
    old.write_csv(output / "verification-raw-timers.csv", raw_timers)
    old.write_csv(output / "refused-experiments.csv", failures)
    old.write_csv(output / "resource-stops.csv", resource_stops)
    old.write_csv(output / "user-stops.csv", user_stops)
    old.write_csv(output / "g100-estimate.csv", estimates)
    old.write_csv(output / "one-signature-witness-layouts.csv", capacity)
    for scheme in SCHEMES:
        selected_direct = [r for r in direct_rows if r["scheme"] == scheme]
        if selected_direct:
            old.write_csv(output / f"{scheme}.csv", selected_direct)
        old.write_csv(output / f"tree-{scheme}.csv", [r for r in tree_rows if r["scheme"] == scheme])
    g_rows = [r for r in tree_rows if r["scheme"] == "raccoon-g"]
    old.write_csv(output / "tree-raccoon-g-repeated.csv", [r for r in g_rows if r["count"] < 100])
    old.write_csv(output / "tree-raccoon-g-single.csv", [r for r in g_rows if r["count"] == 100])
    old.write_csv(output / "tree-raccoon-g-last-segment.csv", [r for r in g_rows if r["count"] >= 70])
    definitions = {
        "figure-1-batching": (("proof_kib", "Proof size (KiB)", "Direct batch proof size"),
                              ("prove_s", "Proving time (s)", "Direct batch proving")),
        "figure-2-verification-memory": (("verify_ms", "Verification time (ms)", "Direct batch verification"),
                                         ("rss_gib", "Peak process RSS (GiB)", "Prover memory")),
        "figure-3-capacity-efficiency": (("capacity_percent", r"Commitment budget used (\%)", "Capacity"),
                                        ("prove_per_signature_ms", "Proving per signature (ms)", "Amortized proving")),
    }
    documents = {}
    for name, (left, right) in definitions.items():
        document = colors(helper.tex_document(left, right, direct_rows, output))
        document = document.replace("legend columns=-1", "legend columns=3").replace("font=\\small,draw=none", "font=\\scriptsize,draw=none")
        if right[0] in ("prove_s", "prove_per_signature_ms"):
            require(all(r[right[0]] > 0 and math.isfinite(r[right[0]]) for r in direct_rows),
                    "Nonpositive or nonfinite proving time")
            pieces = document.split(r"\begin{axis}")
            for i, section in enumerate(pieces):
                if f"title={{{right[2]}}}" in section:
                    pieces[i] = section.replace("ymin=0", "ymode=log,log basis y=10", 1)
            document = r"\begin{axis}".join(pieces)
        if name in ("figure-1-batching", "figure-3-capacity-efficiency"):
            document = document.replace("Raccoon-128-1 (RISC-V)", "Raccoon-128 (RISC-V)")
            documents[name] = document.replace("FORS (leanISA + Keccak)", "FORS (leanISA)")
        else:
            documents[name] = profile_note(document,
                r"Only accepted proofs are plotted. The full G verifier does not fit this backend; no direct G point is inferred.\\"
                r"Raccoon uses the selected optimized port and page-purging allocator; prior workloads retain their recorded settings.")
    documents["figure-direct-batch-verification"] = direct_verification_document(
        documents["figure-2-verification-memory"])
    documents["figure-prover-overview"] = prover_document(
        documents["figure-1-batching"], documents["figure-2-verification-memory"])
    documents["figure-4-recursive-trees"] = tree_document(tree_rows)
    documents["figure-5-tree-verification"] = tree_document(tree_rows, verification=True)
    documents["figure-6-witness-layouts"] = capacity_document(capacity)
    cache = output / ".tectonic-cache"
    if args.render:
        helper.prepare_tex_cache(cache)
    for name, document in documents.items():
        tex = output / f"{name}.tex"
        tex.write_text(document)
        if args.render:
            helper.render(tex, cache)
    for source in (Path(__file__), ROOT / "articles/scripts/mine_figures.py", ROOT / "risc-v/scripts/figures.py"):
        digest(source)
    require(all(digest(ROOT / source) == expected for source, expected in original_snapshot.items()),
            "Original three-scheme figure artifacts changed during additive generation")
    (output / "provenance.json").write_text(json.dumps({
        "schema": 2, "backend_revision": PIN, "schemes": list(SCHEMES),
        "guest_identities": {"raccoon": frozen["schemes"]["raccoon"], "raccoon-g": {
            key: segmented_environment[key] for key in
            ("elf", "elf_sha256", "guest_manifest", "guest_manifest_sha256", "profile")}},
        "selected_standard_cohort": str(standard.relative_to(ROOT)),
        "selected_segmented_G_cohort": str(segmented.relative_to(ROOT)),
        "original_refusal_cohort": str(reference.relative_to(ROOT)),
        "original_three_scheme_artifact_snapshot": original_snapshot,
        "direct_measurements": len(direct_rows),
        "recursive_tree_measurements": len(tree_rows), "source_sha256": SOURCES,
        "policy": "Actual verified measurements only; direct lines connect measured points. Three fresh tree pipelines per scheme/count except user-authorized G100 with one complete measured pipeline, hollow marker and dashed link. No forecast enters measured curves.",
        "sampling_policy": policy,
        "G100_independent_forecast": forecast,
        "user_stop_policy": "The user stopped further G100 proving after one complete measured pipeline. The next partial attempt is archived separately and excluded; sample 2 never started.",
        "refusal_policy": "Original monolithic capacity refusals, actual prover refusals and failed fresh tree preflights are retained separately; none is a zero-valued curve point.",
        "operational_guard_history": guard_history,
        "operational_stop_policy": "A sampled process-RSS stop at a 19 GiB target interrupted one G70 attempt after 71 partial leaves and no root. Its 77 archived files are checked through archive-mapping.json. That entire attempt is excluded from successful medians; the replacement is a complete fresh pipeline under a 20 GiB target. These are sampled operating targets, not hard allocation bounds or a measured failed peak. Source, ELFs, proof rate, workers, allocator and backend witness cap are unchanged.",
        "direct_scope": "Standard Raccoon uses its measured optimized whole-signature port. Monolithic G has no accepted direct point. Cold pilots and nonuniform segmented candidates are excluded.",
        "segmented_G_scope": "Five fresh two-row partial leaves per original signature, all native W/D/advice preparation charged, every merge charged, complete RGSTK001 receipt with 60+64*N auxiliary bytes. Final row is repeated and charged.",
        "segmented_G_assumptions": "Common-witness composition is conditional on extraction and joint commitment binding as stated in the implementation specification/review; no formal composition theorem or full-paper conformance is claimed.",
        "verification": "Complete independent public-only consumers; every folded claim settled and every intended public pair processed. G additionally derives all five part outputs from one untrusted 64-byte binding per original pair.",
        "verification_end_to_end_cold": "Old four: separately measured public_claim_derivation_s plus cold_complete_verify_s. G: recorded cold_complete_verify_s already includes public_configuration_prepare_s and first complete call with D-derived outputs.",
        "verification_end_to_end_prepared": "Old four: explicitly derived sums of public_claim_derivation_s and median complete proof verification. G: measured complete-call samples already include envelope and D-derived outputs; only public_configuration_prepare_s is added. Independently timed component medians need not sum exactly to a complete-call median.",
        "verification_core": "Native tree verification with intended outputs prepared. Every plotted proof verifier checks the root and all terminal obligations. G prepared_core_verify_s still calls full Tree::verify, excluding only RGSTK001 envelope/public-output derivation. FORS starts from a decoded envelope; native RISC-V timers include TreeProof decoding.",
        "verification_public_processing": "Old four use public_claim_derivation_s. G adds public_configuration_prepare_s and public_claim_derivation_s; this standalone timer includes envelope and D-derived outputs. It is not subtracted from the complete-call samples.",
        "allocator_policy": "New standard and segmented G cohorts set _RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0; old three schemes retain their original recorded policies. Implementation timings are not controlled primitive-only comparisons.",
        "capacity_comparison": "Over-cap whole-guest bars use clearly identified uncapped layout diagnostics crosschecked against production refusals. Fitting bars use actual verified whole/partial proof layouts; a G part is not a whole signature.",
        "rendering": "LaTeX/PGFPlots, PNG rasterized from the same PDF", "rendered": args.render,
    }, indent=2) + "\n")
    (output / "validation.json").write_text(json.dumps({
        "schema": 1, "passed": True,
        "scope": "Figure-input consistency, complete production receiver records and retained proof/statement hashes; not an independent proof-system audit",
        "direct_measurements": len(direct_rows), "tree_measurements": len(tree_rows),
        "fresh_tree_pipelines": len(tree_samples), "tree_signatures": list(COUNTS),
        "samples_per_scheme_count": "3 except Raccoon-G at 100: 1 complete producer pipeline", "new_direct_schemes": ["raccoon"],
        "G_direct_point_inferred": False,
        "original_refusal_ledger_rows": len(failures),
        "operational_resource_stop_rows": len(resource_stops),
        "user_requested_stop_rows": len(user_stops),
        "user_stop_archive_hashes_match": True,
        "G100_forecast_independently_recomputed_and_excluded_from_curves": True,
        "operational_stop_archive_hashes_match": True,
        "operational_stops_excluded_from_successful_curves": True,
        "failed_attempt_peak_rss_inferred": False,
        "all_new_frozen_sources_and_guest_identities_match": True,
        "original_three_scheme_279_inputs_and_artifacts_unchanged": True,
        "all_new_saved_proofs_match_producer_and_public_only_receiver": True,
        "every_G_part_and_common_binding_covered": True,
        "G_native_prepare_and_all_partial_merge_proofs_charged": True,
        "G_complete_wire_header_core_and_64_byte_bindings_counted": True,
        "verification_component_scopes_recorded": True,
        "input_files_hashed": len(SOURCES), "PDFs_rendered": args.render,
        "visual_review": "Pending separate rendered-image inspection" if args.render else "Not rendered",
    }, indent=2) + "\n")
    print(json.dumps({"output": str(output), "direct_points": len(direct_rows),
                      "tree_points": len(tree_rows), "rendered": args.render}))


if __name__ == "__main__":
    main()
