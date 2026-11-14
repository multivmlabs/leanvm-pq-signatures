#!/usr/bin/env python3
"""Audit one completed saved pipeline. Does not prove, measure or rerun verifier."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from binding import check_root_digest, validate_statement
from segmented_binding import check_receipt_binding


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit(statement_path, report_path, receiver_path, *, segmented):
    statement = json.loads(statement_path.read_text())
    report = json.loads(report_path.read_text())
    received = json.loads(receiver_path.read_text())
    root = report_path.parent / "root.proof"
    n = statement["signatures"]
    leaves = 5 * n if segmented else n // statement["leaf_size"]
    slots = max(2, 1 << (leaves - 1).bit_length())
    assert report["status"] == "accepted" and report["verified"] is True
    assert report["all_folded_claims_settled"] is True
    assert report["signatures"] == n and report["actual_leaves"] == leaves
    assert report["leaf_slots"] == slots and report["padding_slots"] == slots - leaves
    assert report["statement_sha256"] == file_hash(statement_path)
    assert report["elf_sha256"] == statement["elf_sha256"]
    assert report["zero_knowledge"] is False
    binding = check_receipt_binding(statement, root.read_bytes()) if segmented else (
        validate_statement(statement, tree=True) or check_root_digest(statement, root.read_bytes()))
    assert len(report["leaf_reports"]) == leaves
    assert len(report["merge_reports"]) == report["merge_count"] == slots - 1
    assert report["depth"] == slots.bit_length() - 1
    assert [leaf["leaf"] for leaf in report["leaf_reports"]] == list(range(leaves))
    assert [node["node"] for node in report["merge_reports"]] == list(range(slots - 1))
    counts = Counter(node["level"] for node in report["merge_reports"])
    assert counts == {level: slots >> (level + 1) for level in range(report["depth"])}
    for node in report["merge_reports"]:
        assert node["children"] == 2
        assert node["kind"] == ("first" if node["level"] == 0 else "node")
    file_checks = []
    for key, prefix, index in (("leaf_reports", "leaf", "leaf"),
                                ("merge_reports", "merge", "node")):
        for item in report[key]:
            proof = report_path.parent / f"{prefix}-{item[index]}.proof"
            assert item["proof_bytes"] == proof.stat().st_size
            assert item["proof_sha256"] == file_hash(proof)
            assert math.isfinite(item["prove_s"]) and item["prove_s"] > 0
            file_checks.append({"name": proof.name, "sha256": item["proof_sha256"],
                                "bytes": item["proof_bytes"]})
            if segmented and key == "leaf_reports":
                assert item["signature"] == item["leaf"] // 5
                assert item["part"] == item["leaf"] % 5
    leaf_s = sum(leaf["prove_s"] for leaf in report["leaf_reports"])
    merge_s = sum(node["prove_s"] for node in report["merge_reports"])
    assert math.isclose(leaf_s, report["leaf_prove_s"], abs_tol=1e-9)
    assert math.isclose(merge_s, report["merge_prove_s"], abs_tol=1e-9)
    preparation = report["native_prepare_s"] if segmented else 0
    if segmented:
        assert len(report["native_prepare_samples_s"]) == n
        assert math.isclose(preparation, sum(report["native_prepare_samples_s"]), abs_tol=1e-9)
        assert report["root_core_bytes"] == binding["core_bytes"]
        assert report["auxiliary_bytes"] == 60 + 64 * n
    assert math.isclose(report["total_prove_s"], preparation + leaf_s + merge_s, abs_tol=1e-9)
    root_hash = file_hash(root)
    assert report["root_proof_sha256"] == root_hash
    assert report["root_proof_bytes"] == root.stat().st_size
    assert received["root_proof_sha256"] == root_hash
    assert received["root_proof_bytes"] == root.stat().st_size
    assert received["verified"] is True and received["all_folded_claims_settled"] is True
    assert received["statement_pinned"] is True
    assert received["verification_uses_child_proofs"] is False
    assert received["verification_uses_signatures"] is False
    assert received["statement_sha256"] == file_hash(statement_path)
    assert file_hash(receiver_path.parent / "statement.json") == file_hash(statement_path)
    assert file_hash(receiver_path.parent / "root.proof") == root_hash
    assert all(received["controls"].values())
    assert list(receiver_path.parent.glob("*.proof")) == [receiver_path.parent / "root.proof"]
    assert len(received["prepared_complete_verify_s"]) == 3
    assert all(math.isfinite(t) and t > 0 for t in received["prepared_complete_verify_s"])
    return {"schema": 1, "layout": "segmented-five-parts" if segmented else "whole-signature-leaves",
            "source_report": str(report_path), "source_report_sha256": file_hash(report_path),
            "statement_sha256": file_hash(statement_path), "approved_elf_sha256": statement["elf_sha256"],
            "root_proof_sha256": root_hash,
            "public_root_digest_blake2s": binding.get("root_digest", binding.get("ordered_root_digest")),
            "signatures": n, "actual_fresh_leaves": leaves, "canonical_slots": slots,
            "fresh_merges": slots - 1, "binding_check": binding,
            "all_saved_proof_hashes_checked": True, "saved_proofs": file_checks,
            "total_prove_s_accounting_matches": True, "public_only_full_verification_evidence": True,
            "verifier_scope": received.get("prepared_complete_scope", "Complete native Tree::verify with prederived public outputs; public derivation is reported separately"),
            "plain_proofs_may_be_deterministic": True,
            "description": "Read-only saved-evidence audit. Freshness is checked against producer source and command records; equal plain-proof hashes across samples do not imply reuse. This audit does not rerun full cryptographic verification.",
            "passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("statement", "report", "receiver", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--segmented", action="store_true")
    args = parser.parse_args()
    result = audit(args.statement, args.report, args.receiver, segmented=args.segmented)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Audited N={result['signatures']}, {result['actual_fresh_leaves']} leaves, {result['fresh_merges']} merges")


if __name__ == "__main__":
    main()
