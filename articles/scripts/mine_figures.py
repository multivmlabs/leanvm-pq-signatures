#!/usr/bin/env python3
"""Load the article's verified Falcon, ML-DSA and FORS measurements."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
RV_PIN = "06e5c9cd6981103786f9d0a17324241b559a50d3"
ISA_PIN = "575df819d9c857f38068cecf7b1640e0ce4bfb29"
RV_GUESTS = {
    "falcon": "421470c0aef38d3b2c2ca392edd7786c7425085f6a430b0286a679c69f0f9a4c",
    "mldsa": "73fa19d855adbd0ad6d8368260b5e1b173cc57a854e52624dd1b8e65d95f69d6",
}
CAP = 2**28
COUNTS = (10, 30, 70, 100)
SOURCES = {}


def read(path):
    raw = path.read_bytes()
    SOURCES[str(path.relative_to(ROOT))] = hashlib.sha256(raw).hexdigest()
    return json.loads(raw)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stats(row, name, values):
    values = [float(value) for value in values]
    require(bool(values), f"No samples for {name}")
    center = statistics.median(values)
    row[name] = center
    row[name + "_min"] = min(values)
    row[name + "_max"] = max(values)
    row[name + "_error_minus"] = center - min(values)
    row[name + "_error_plus"] = max(values) - center


def measurements(scheme, count, proof_sizes, proves, verifies, rss, words, cycles):
    require(len(proves) == len(verifies) == len(proof_sizes) == 3,
            f"Expected three samples: {scheme} {count}")
    row = {"scheme": scheme, "count": count,
           "proof_kib": statistics.median(proof_sizes) / 1024,
           "rss_gib": rss / 2**30,
           "committed_words": words, "capacity_percent": 100 * words / CAP,
           "cycles": cycles}
    stats(row, "prove_s", proves)
    stats(row, "verify_ms", [1000 * value for value in verifies])
    stats(row, "prove_per_signature_ms", [1000 * value / count for value in proves])
    # Column names used by the existing LaTeX renderer.
    for name, unit in (("prove", "s"), ("verify", "ms"), ("prove_per_signature", "ms")):
        for end in ("minus", "plus"):
            row[f"{name}_error_{end}_{unit}"] = row[f"{name}_{unit}_error_{end}"]
    return row


def direct():
    rows = []
    for scheme in ("falcon", "mldsa"):
        guest_hashes = set()
        for path in sorted((ROOT / "risc-v/results/direct").glob(f"{scheme}-*.json")):
            report = read(path)
            if report.get("status") != "accepted":
                continue
            require(report.get("action") == "prove" and report.get("verified") is True,
                    f"Not an accepted verified proof: {path}")
            require(report["leanvm_revision"] == RV_PIN and report["scheme"] == scheme,
                    f"Unexpected backend or scheme: {path}")
            require(report["elf_sha256"] == RV_GUESTS[scheme], f"Changed baseline guest: {path}")
            require(report["threads"] == 8 and report["log_inverse_rate"] == 1
                    and report["warmup"] == 1, f"Mixed RISC-V settings: {path}")
            count = report["count"]
            require(path.name == f"{scheme}-{count}.json", f"Count mismatch: {path}")
            guest_hashes.add(report["elf_sha256"])
            statement_path = ROOT / f"risc-v/artifacts/{scheme}-{count}.proof.statement.json"
            statement_raw = statement_path.read_bytes()
            require(hashlib.sha256(statement_raw).hexdigest() == report["statement_sha256"],
                    f"Public statement digest mismatch: {path}")
            statement = read(statement_path)
            require(statement["scheme"] == scheme and statement["count"] == count
                    and statement["elf_sha256"] == report["elf_sha256"],
                    f"Public statement identity mismatch: {path}")
            proof = ROOT / f"risc-v/artifacts/{scheme}-{count}.proof"
            require(proof.stat().st_size == report["proof_bytes"], f"Proof size mismatch: {path}")
            rows.append(measurements(scheme, count, report["proof_bytes_samples"],
                         report["prove_s"], report["verify_s"], report["peak_rss_bytes"],
                         report["execution"]["committed_words"], report["execution"]["cycles"]))
        require(len(guest_hashes) == 1, f"Mixed guest programs for {scheme}")
    for count in (*range(1, 31), 70, 100):
        path = ROOT / f"leanISA/results/article/direct/fors-{count}.json"
        report, verifier = read(path), read(path.with_name(f"fors-{count}.verify.json"))
        require(report.get("action") == "prove" and report.get("verified") is True
                and verifier.get("verified") is True and verifier.get("statement_pinned") is True,
                f"Missing verified, pinned public receiver: {path}")
        require(report["leanvm_revision"] == verifier["leanvm_revision"] == ISA_PIN,
                f"Unexpected leanISA pin: {path}")
        require(report["metadata"]["count"] == count
                and report["metadata"]["parameters"] == {"n": 32, "k": 16, "a": 8}
                and report["scheme"] == "fors-keccak-research", f"Wrong FORS profile: {path}")
        require(report["guest_hash"] == verifier["guest_hash"]
                and report["public_input_hex"] == verifier["public_input_hex"]
                and report["proof_bytes"] == verifier["proof_bytes"], f"Receiver mismatch: {path}")
        require(report["warmup_passes"] == 1 and report["log_inv_rate"] == 1
                and report["threads_env"] is None, f"Mixed FORS settings: {path}")
        rows.append(measurements("fors", count, report["proof_bytes_samples"],
                    report["prove_s"], verifier["verify_cached_s"],
                    report["process_peak_rss_bytes"], report["committed_cells"], report["cycles"]))
    return sorted(rows, key=lambda row: (("falcon", "mldsa", "fors").index(row["scheme"]), row["count"]))




def riscv_trees(schemes=("falcon", "mldsa"), counts=COUNTS):
    """Read fresh RISC-V pipelines and their independent public-only receivers."""
    rows, samples = [], []
    for scheme in schemes:
        for count in counts:
            directory = ROOT / f"risc-v/results/trees/{scheme}-{count}"
            leaf_size = 10 if scheme == "falcon" else 2
            statement_path = directory / "statement.json"
            statement = read(statement_path)
            statement_hash = SOURCES[str(statement_path.relative_to(ROOT))]
            require(statement["backend_revision"] == RV_PIN
                    and statement["scheme"] == scheme and statement["signatures"] == count
                    and statement["elf_sha256"] == RV_GUESTS[scheme]
                    and statement["leaf_size"] == leaf_size
                    and statement["arity_0"] == statement["arity"] == 2
                    and statement["log_inverse_rate"] == 1,
                    f"Unexpected trusted tree statement: {statement_path}")
            actual = count // leaf_size
            slots = max(2, 1 << (actual - 1).bit_length())
            require(statement["actual_leaves"] == actual and statement["leaf_slots"] == slots
                    and len(statement["public_records"]) == count
                    and len(statement["expected_leaf_outputs"]) == actual,
                    f"Wrong distinct-count or padding configuration: {statement_path}")
            keys = [record["public_key"] for record in statement["public_records"]]
            require(len(set(keys)) == count, f"Repeated signers in intended public claims: {statement_path}")
            selected = []
            for sample in range(3):
                run = directory / f"sample-{sample}"
                report, verifier = read(run / "report.json"), read(run / "verification.json")
                require(report.get("action") == "prove" and report.get("status") == "accepted"
                        and report.get("verified") is True and report.get("all_folded_claims_settled") is True,
                        f"Missing complete accepted RISC-V tree: {run}")
                require(verifier.get("action") == "verify" and verifier.get("verified") is True
                        and verifier.get("statement_pinned") is True
                        and verifier.get("all_folded_claims_settled") is True
                        and verifier.get("verification_uses_child_proofs") is False
                        and verifier.get("verification_uses_signatures") is False,
                        f"Missing complete public-only tree receiver: {run}")
                for item in (report, verifier):
                    require(item["backend_revision"] == RV_PIN and item["scheme"] == scheme
                            and item["signatures"] == count and item["actual_leaves"] == actual
                            and item["leaf_slots"] == slots
                            and item["elf_sha256"] == statement["elf_sha256"]
                            and item["statement_sha256"] == statement_hash,
                            f"Producer/receiver statement identity mismatch: {run}")
                require(report["leaf_size"] == leaf_size and report["padding_slots"] == slots - actual
                        and report["arity_0"] == report["arity"] == 2
                        and report["log_inverse_rate"] == 1
                        and report["threads_requested"] == verifier["threads_requested"] == 8,
                        f"Mixed RISC-V tree settings: {run}")
                leaves, merges = report["leaf_reports"], report["merge_reports"]
                require(len(leaves) == actual and len(merges) == report["merge_count"] == slots - 1
                        and all(leaf["signatures"] == leaf_size for leaf in leaves),
                        f"Missing real leaves or charged merge work: {run}")
                work = sum(leaf["prove_s"] for leaf in leaves) + sum(node["prove_s"] for node in merges)
                require(abs(work - report["total_prove_s"]) < 1e-8,
                        f"Proving-work accounting mismatch: {run}")
                proof_path = run / "root.proof"
                proof = proof_path.read_bytes()
                require(hashlib.sha256(proof).hexdigest() == report["root_proof_sha256"]
                        == verifier["root_proof_sha256"]
                        and len(proof) == report["root_proof_bytes"] == verifier["root_proof_bytes"],
                        f"Root proof identity mismatch: {run}")
                SOURCES[str(proof_path.relative_to(ROOT))] = report["root_proof_sha256"]
                prepared = verifier["prepared_complete_verify_s"]
                require(len(prepared) == 3, f"Missing prepared verification samples: {run}")
                cold = verifier["program_load_s"] + verifier["tree_setup_s"] + verifier["first_complete_verify_s"]
                require(abs(cold - verifier["cold_complete_verify_s"]) < 1e-8,
                        f"Incomplete cold verification accounting: {run}")
                selected.append({"scheme": scheme, "backend": "RISC-V", "count": count, "sample": sample,
                    "prove_s": work, "proof_kib": len(proof) / 1024,
                    "core_kib": len(proof) / 1024, "auxiliary_kib": 0,
                    "verify_cold_ms": 1000 * cold,
                    "verify_cached_ms": 1000 * statistics.median(prepared),
                    "claim_ms": 1000 * verifier["public_claim_derivation_s"],
                    "rss_gib": report["peak_rss_bytes"] / 2**30,
                    "leaf_size": leaf_size, "leaf_count": actual, "leaf_slots": slots, "padding_slots": slots - actual,
                    "merge_count": len(merges), "edge_count": 2 * (slots - 1)})
            samples.extend(selected)
            row = {"scheme": scheme, "backend": "RISC-V", "count": count}
            for field in selected[0]:
                if field not in ("scheme", "backend", "count", "sample"):
                    stats(row, field, [entry[field] for entry in selected])
            rows.append(row)
    return rows, samples


def reduced_fors_trees(counts=COUNTS):
    """Read actual leanISA sumcheck-reduced trees and complete public receivers.

    Native reduction generation is prover work. Omitting it would compare a
    precomputed reduction with the complete native RISC-V aggregation API.
    """
    approved = read(ROOT / "leanISA/results/article/direct/fors-5.json")["guest_hash"]
    environment = read(ROOT / "leanISA/reduction/results/trees/environment.json")
    require(environment["backend_revision"] == ISA_PIN
            and environment["approved_leaf_guest_hash"] == approved
            and environment["counts"] == list(COUNTS) and environment["samples"] == 3
            and environment["leaf_size"] == 5 and environment["arity"] == 2
            and environment["threads_env"] is None,
            "Unexpected reduced FORS benchmark environment")
    for name, expected_hash in environment["source_sha256"].items():
        actual_hash = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        require(actual_hash == expected_hash, f"Reduced FORS source changed since measurement: {name}")
        SOURCES[name] = actual_hash
    for name in ("leanISA/src/recursion_guest.rs", "leanISA/src/recursion_support.rs",
                 "leanISA/guests/aggregate_falcon.py", "leanISA/guests/fors.py",
                 "leanISA/python/pqbench/article_inputs.py", "leanISA/python/pqbench/fors.py"):
        SOURCES[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    rows, samples = [], []
    thread_settings = set()
    for count in counts:
        directory = ROOT / f"leanISA/reduction/results/trees/fors-{count}"
        public_path = directory / "public.json"
        public = read(public_path)
        public_hash = SOURCES[str(public_path.relative_to(ROOT))]
        source_hash = hashlib.sha256(public["leaf_source"].encode()).hexdigest()
        plan = read(directory / "plan.json")
        actual = count // 5
        slots = 1 << (actual - 1).bit_length()
        depth = slots.bit_length() - 1
        require(public["schema"] == 1 and public["backend_revision"] == ISA_PIN
                and public["scheme"] == "fors" and public["signatures"] == count
                and public["leaf_size"] == 5 and len(public["public_records"]) == count,
                f"Wrong reduced FORS public statement: {public_path}")
        keys = [bytes.fromhex(record["public_key_hex"]) for record in public["public_records"]]
        messages = [bytes.fromhex(record["message_hex"]) for record in public["public_records"]]
        require(all(len(key) == 64 for key in keys) and all(len(msg) == 32 for msg in messages)
                and len(set(zip(keys, messages))) == count,
                f"Wrong or repeated intended FORS key/message pairs: {public_path}")
        require(plan["backend_revision"] == ISA_PIN and plan["signatures"] == count
                and plan["leaf_size"] == 5 and plan["real_leaves"] == actual
                and plan["leaf_slots"] == slots and plan["depth"] == depth
                and plan["terminal_evaluations"] == depth
                and plan["public_sha256"] == public_hash
                and plan["leaf_source_sha256"] == source_hash
                and plan["leaf_guest_hash"] == approved,
                f"Wrong reduced FORS plan or approved leaf: {directory}")
        families = plan["families"]
        require(len(families) == depth + 1 and families[0]["guest_hash"] == approved
                and families[-1]["guest_hash"] == plan["root_guest_hash"],
                f"Wrong acyclic program family chain: {directory}")
        for index, family in enumerate(families):
            instructions = int(family["bytecode_instructions"])
            require(instructions > 0 and instructions & (instructions - 1) == 0
                    and family["family"] == index
                    and family["table_words"] == 16 * instructions
                    and family["dimensions"] == instructions.bit_length() - 1 + 4
                    and family["min_log_committed"] == 22,
                    f"Unexpected trusted bytecode family: {directory}, {index}")
        selected = []
        for sample in range(3):
            run = directory / f"sample-{sample}"
            report, verifier = read(run / "report.json"), read(run / "verification.json")
            completed = read(run / "completed.json")
            require(completed.get("verified_public_only") is True
                    and completed["host_binary_sha256"] == environment["host_binary_sha256"]
                    and completed["public_sha256"] == public_hash
                    and completed["approved_leaf_guest_hash"] == approved
                    and completed["receiver_files"] == ["public.json", "root.proof"],
                    f"Missing frozen-binary isolated receiver evidence: {run}")
            require(report.get("action") == "prove" and report.get("status") == "accepted"
                    and report.get("verified") is True
                    and report.get("all_reduced_claims_settled") is True
                    and report["scheme"] == "fors",
                    f"Missing accepted reduced FORS proof: {run}")
            require(verifier.get("action") == "verify" and verifier.get("verified") is True
                    and verifier.get("statement_pinned") is True
                    and verifier.get("all_reduced_claims_settled") is True
                    and verifier.get("uses_child_proof_files") is False
                    and verifier.get("uses_signature_witnesses") is False
                    and verifier["caller_leaf_guest_hash"] == approved,
                    f"Missing complete reduced FORS receiver: {run}")
            for item in (report, verifier):
                require(item["backend_revision"] == ISA_PIN and item["signatures"] == count
                        and item["leaf_size"] == 5 and item["real_leaves"] == actual
                        and item["leaf_slots"] == slots and item["padding_slots"] == slots - actual
                        and item["depth"] == depth and item["terminal_evaluations"] == depth
                        and item["original_tree_edges"] == 2 * (slots - 1)
                        and item["public_sha256"] == public_hash
                        and item["leaf_source_sha256"] == source_hash
                        and item["families"] == families,
                        f"Producer/receiver reduced FORS identity mismatch: {run}")
            thread_settings.add(report.get("threads_env"))
            leaves, merges = report["leaf_reports"], report["merge_reports"]
            require(len(leaves) == actual and len(merges) == report["merge_count"] == slots - 1
                    and all(leaf["signatures"] == 5 for leaf in leaves),
                    f"Missing fresh reduced FORS work: {run}")
            leaf_work = sum(leaf["prove_s"] for leaf in leaves)
            merge_prepare = sum(node["prepare_s"] for node in merges)
            native_reduction = sum(node["native_reduction_prove_s"] for node in merges)
            wrapper_stark = sum(node["wrapper_stark_prove_s"] for node in merges)
            merge_work = merge_prepare + wrapper_stark
            require(all(abs(node["total_prove_s"] - node["prepare_s"]
                            - node["wrapper_stark_prove_s"]) < 1e-8 for node in merges)
                    and all(node["native_reduction_prove_s"] <= node["prepare_s"] + 1e-8 for node in merges)
                    and abs(leaf_work - report["leaf_prove_s"]) < 1e-8
                    and abs(merge_work - report["merge_prove_s"]) < 1e-8
                    and abs(native_reduction - report["native_reduction_prove_s"]) < 1e-8
                    and abs(wrapper_stark - report["wrapper_stark_prove_s"]) < 1e-8
                    and abs(leaf_work + merge_work - report["total_prove_s"]) < 1e-8,
                    f"Native reduction or STARK proving work omitted: {run}")
            # Per-node work and proof identities remain in the measured report.
            # Only final receipts are distributed; child proofs are reproducible.
            proof_path = run / "root.proof"
            proof = proof_path.read_bytes()
            require(hashlib.sha256(proof).hexdigest() == report["root_proof_sha256"]
                    == verifier["root_proof_sha256"]
                    == completed["root_proof_sha256"]
                    and len(proof) == report["root_proof_bytes"] == verifier["root_proof_bytes"]
                    and report["root_core_bytes"] + report["root_auxiliary_bytes"] == len(proof),
                    f"Reduced root proof identity/size mismatch: {run}")
            SOURCES[str(proof_path.relative_to(ROOT))] = report["root_proof_sha256"]
            prepared = verifier["prepared_complete_verify_s"]
            require(len(prepared) == 3 and len(verifier["root_core_s"]) == 3
                    and len(verifier["terminal_evaluation_s"]) == 3,
                    f"Missing complete reduced FORS verification samples: {run}")
            cold = verifier["program_compile_s"] + verifier["table_prepare_s"] + verifier["first_complete_verify_s"]
            require(abs(cold - verifier["cold_complete_verify_s"]) < 1e-8,
                    f"Incomplete reduced FORS cold verification: {run}")
            selected.append({"scheme": "fors", "backend": "leanISA-reduced", "count": count, "sample": sample,
                "prove_s": leaf_work + merge_work, "proof_kib": len(proof) / 1024,
                "core_kib": report["root_core_bytes"] / 1024,
                "auxiliary_kib": report["root_auxiliary_bytes"] / 1024,
                "verify_cold_ms": 1000 * cold,
                "verify_cached_ms": 1000 * statistics.median(prepared),
                "claim_ms": 1000 * verifier["public_claim_derivation_s"],
                "rss_gib": report["peak_rss_bytes"] / 2**30,
                "leaf_size": 5, "leaf_count": actual, "leaf_slots": slots,
                "padding_slots": slots - actual, "merge_count": len(merges),
                "edge_count": 2 * (slots - 1), "terminal_evaluations": depth,
                "native_reduction_prove_s": native_reduction,
                "merge_prepare_s": merge_prepare, "wrapper_stark_prove_s": wrapper_stark,
                "root_core_ms": 1000 * statistics.median(verifier["root_core_s"]),
                "terminal_evaluation_ms": 1000 * statistics.median(verifier["terminal_evaluation_s"])})
        samples.extend(selected)
        row = {"scheme": "fors", "backend": "leanISA-reduced", "count": count}
        for field in selected[0]:
            if field not in ("scheme", "backend", "count", "sample"):
                stats(row, field, [entry[field] for entry in selected])
        rows.append(row)
    require(thread_settings == {None}, "Mixed or unexpected reduced FORS worker settings")
    return rows, samples


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(dict.fromkeys(key for row in rows for key in row)))
        writer.writeheader()
        writer.writerows(rows)








