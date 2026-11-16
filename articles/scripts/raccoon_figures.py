#!/usr/bin/env python3
"""Validate retained measurements and regenerate the five article plots."""
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
              ("proof_kib", "Complete aggregate (KiB)", "Serialized aggregate proof"),
              ("rss_gib", "Peak process RSS (GiB)", "Prover memory")]
    axes = []
    for panel, (field, ylabel, title) in enumerate(panels):
        scale = "ymin=0," if field in ("proof_kib", "rss_gib") else "ymode=log,log basis y=10,"
        position = (4.3, -5.8) if not verification and panel == 2 else (
            8.6 * (panel % 2), -7.2 * (panel // 2))
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




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", "--standard-study", dest="standard_study", type=Path,
                        default=ROOT / "risc-v/results/raccoon-runtime-study")
    parser.add_argument("--segmented-study", type=Path,
                        default=ROOT / "risc-v/results/raccoong-segmented-uniform-trees")
    parser.add_argument("--matrix-control", type=Path,
                        default=ROOT / "risc-v/results/raccoon-full-matrix")
    parser.add_argument("--output", type=Path, default=ROOT / "build/figures")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    standard, segmented = args.standard_study.resolve(), args.segmented_study.resolve()
    output = args.output.resolve()
    require(not output.exists(), "Choose a new output directory")
    frozen = environment(standard, selected=True)
    segmented_environment = environment(segmented, segmented=True, selected=True)
    old = module("mine_original_figures", ROOT / "articles/scripts/mine_figures.py")
    helper = module("raccoon_plot_helper", ROOT / "risc-v/scripts/figures.py")
    policy = sampling_policy(args.matrix_control.resolve())
    new_direct = direct(standard, frozen, old)
    _, standard_samples = trees(standard, frozen, old)
    segmented_samples, segmented_raw_timers = segmented_trees(segmented, segmented_environment, old, policy)
    direct_rows = old.direct() + new_direct
    direct_rows.sort(key=lambda row: (list(SCHEMES).index(row["scheme"]), row["count"]))
    _, rv_samples = old.riscv_trees()
    _, fors_samples = old.reduced_fors_trees()
    regular_samples = rv_samples + fors_samples + standard_samples
    raw_timers = regular_timers(regular_samples, standard) + segmented_raw_timers
    tree_samples = regular_samples + segmented_samples
    tree_rows = aggregate(tree_samples, old, policy)
    require(len(tree_samples) == 58 and len(tree_rows) == 20, "Wrong authorized curve/sample count")
    SOURCES.update(old.SOURCES)
    helper.SCHEMES = {scheme: label for scheme, label in SCHEMES.items()
                      if any(row["scheme"] == scheme for row in direct_rows)}
    # Create outputs only after every included root and receiver passed validation.
    output.mkdir(parents=True)
    old.write_csv(output / "measurements.csv", direct_rows)
    old.write_csv(output / "recursive-trees.csv", tree_rows)
    old.write_csv(output / "recursive-tree-samples.csv", tree_samples)
    old.write_csv(output / "verification-raw-timers.csv", raw_timers)
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
    # Publish only the five experimental plots used by the article.
    documents = {name: documents[name] for name in (
        "figure-prover-overview", "figure-3-capacity-efficiency",
        "figure-direct-batch-verification", "figure-4-recursive-trees",
        "figure-5-tree-verification")}
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
    (output / "provenance.json").write_text(json.dumps({
        "schema": 3, "backend_revision": PIN, "schemes": list(SCHEMES),
        "source_sha256": SOURCES,
        "direct_measurements": len(direct_rows),
        "recursive_tree_measurements": len(tree_rows),
        "fresh_tree_pipelines": len(tree_samples),
        "sampling_policy": policy,
        "policy": "Measured results only; three fresh tree pipelines per point except Raccoon-G at 100 signatures (one). No estimates enter curves.",
        "validation_scope": "Frozen measured sources, final receipt and public-statement hashes, complete receiver records, all component timings and G part coverage. Intermediate proof files are omitted; their hashes and sizes remain in the reports. This command does not rerun cryptographic verification.",
        "rendered": args.render,
    }, indent=2) + "\n")
    (output / "validation.json").write_text(json.dumps({
        "passed": True, "direct_measurements": len(direct_rows),
        "tree_measurements": len(tree_rows), "fresh_tree_pipelines": len(tree_samples),
        "final_receipts_checked": True, "intermediate_proofs_distributed": False,
        "cryptographic_verification_rerun": False,
    }, indent=2) + "\n")
    print(json.dumps({"output": str(output), "direct_points": len(direct_rows),
                      "tree_points": len(tree_rows), "rendered": args.render}))




if __name__ == "__main__":
    main()
