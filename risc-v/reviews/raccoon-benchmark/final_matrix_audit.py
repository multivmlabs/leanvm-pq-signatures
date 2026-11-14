#!/usr/bin/env python3
"""Final read-only audit for the user-reduced 22-root study. Never proves."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

from audit_tree_sample import audit, file_hash

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
MATRIX = ROOT / "risc-v/results/raccoon-full-matrix"


def read(path):
    return json.loads(path.read_text())


def close(a, b):
    assert abs(a - b) < max(1e-10, abs(a) * 1e-12), (a, b)


def archive(folder, expected):
    manifest = read(folder / "manifest.json")
    mapping = read(folder / "archive-mapping.json")
    assert set(mapping) == set(manifest["files"]) and len(mapping) == expected
    for original, entry in mapping.items():
        assert file_hash(folder / entry["archived"]) == entry["sha256"] == manifest["files"][original]
    return {"path": str(folder.relative_to(ROOT)), "files_checked": expected,
            "manifest_sha256": file_hash(folder / "manifest.json"), "passed": True}


def main():
    policy = read(MATRIX / "sampling-policy.json")
    assert policy["required_retained_complete_tree_pipelines"] == 22
    assert policy["expected_samples"]["raccoon-g"]["100"] == [0]
    assert policy["no_further_proving_authorized_for_this_matrix"]
    assert policy["accepted_guard_pipeline_counts"] == {"19_GiB": 17, "20_GiB": 5}
    accepted, guards, public_prefixes = [], Counter(), {}
    for scheme, counts in policy["expected_samples"].items():
        segmented = scheme == "raccoon-g"
        base = ROOT / ("risc-v/results/raccoong-segmented-uniform-trees" if segmented
                       else "risc-v/results/raccoon-runtime-study/raccoon/trees")
        canonical = read(base / "count-100/statement.json")["public_records"]
        for count, samples in counts.items():
            n = int(count)
            statement = base / f"count-{n}/statement.json"
            assert read(statement)["public_records"] == canonical[:n]
            for sample in samples:
                directory = base / f"count-{n}/sample-{sample}"
                result = audit(statement, directory / "report.json",
                               directory / "public-only-receiver/verification.json", segmented=segmented)
                command = read(base / f"count-{n}/sample-{sample}-producer.completed.json")
                assert command["exit_code"] == 0 and command["aborted"] is None
                assert command["timeout_s"] == 21600
                assert command["rss_limit_bytes"] in (19 * 1024**3, 20 * 1024**3)
                guards[command["rss_limit_bytes"] // 1024**3] += 1
                environment = command.get("runtime_environment", command.get("environment"))
                assert environment == {"MALLOC_CONF": None,
                    "_RJEM_MALLOC_CONF": "dirty_decay_ms:0,muzzy_decay_ms:0", "LEANVM_NUM_THREADS": "8"}
                receiver_command = read(directory / "public-only-receiver/consumer.completed.json")
                assert receiver_command["exit_code"] == 0 and receiver_command["aborted"] is None
                result["producer_guard_gib"] = command["rss_limit_bytes"] // 1024**3
                result["producer_command_sha256"] = file_hash(base / f"count-{n}/sample-{sample}-producer.completed.json")
                output = HERE / "matrix" / f"{scheme}-N{n}-sample{sample}-final-evidence.json"
                output.write_text(json.dumps(result, indent=2) + "\n")
                accepted.append({"scheme": scheme, "count": n, "sample": sample,
                    "public_root_digest_blake2s": result["public_root_digest_blake2s"],
                    "root_proof_sha256": result["root_proof_sha256"],
                    "evidence": str(output.relative_to(ROOT)), "guard_gib": result["producer_guard_gib"]})
        public_prefixes[scheme] = len(canonical)
    assert len(accepted) == 22 and guards == {19: 17, 20: 5}

    freezes = []
    binaries = ROOT / ".cache/raccoon-optimized-study-target/release"
    for name, folder, binary_fields in [
        ("standard", "raccoon-runtime-study", {"direct_binary_sha256": "riscv-raccoon-optimized-direct", "tree_binary_sha256": "riscv-raccoon-optimized-tree"}),
        ("G", "raccoong-segmented-uniform-trees", {"binary_sha256": "raccoong-segmented-treebench"})]:
        path = ROOT / f"risc-v/results/{folder}/environment.json"
        frozen = read(path)
        assert all(file_hash(ROOT / p) == digest for p, digest in frozen["source_sha256"].items())
        assert all(file_hash(binaries / binary) == frozen[field] for field, binary in binary_fields.items())
        freezes.append({"cohort": name, "source_hashes_checked": len(frozen["source_sha256"]),
                        "environment_sha256": file_hash(path)})
    pins = {}
    for path in ("risc-v/experiments/raccoon-crt32/build-manifest.json", "risc-v/experiments/raccoong-segmented/build-manifest.json"):
        manifest = read(ROOT / path)
        assert file_hash(ROOT / manifest["elf"]) == manifest["elf_sha256"]
        assert all(file_hash(ROOT / p) == digest for p, digest in manifest["source_sha256"].items())
        pins.update(manifest["backend_pins"])
    for path, revision in pins.items():
        assert subprocess.check_output(["git", "-C", str(ROOT / path), "rev-parse", "HEAD"], text=True).strip() == revision
        assert not subprocess.check_output(["git", "-C", str(ROOT / path), "status", "--porcelain"], text=True).strip()
    coordinator = file_hash(ROOT / "risc-v/scripts/raccoon_full_matrix.py")
    assert coordinator == "c117ef5be9437638c5802f109362d4108b822ed3c8d4c97d16da950cae4ab09d"
    old = read(ROOT / "leanISA/archive-manifest.json")
    assert len(old["files"]) == 1277
    assert all(file_hash(ROOT / "leanISA" / p) == digest for p, digest in old["files"].items())
    archives = [archive(ROOT / policy["resource_stop_archive"], 77), archive(ROOT / policy["user_stop_archive"], 12)]
    stop = read(ROOT / policy["user_stop_archive"] / "stop-confirmation.json")
    assert stop["producers_idle"] and stop["no_more_benchmark_authorized"]
    assert stop["new_user_authorized_expected_completed_roots"] == 22
    user = read(ROOT / policy["user_stop_archive"] / "manifest.json")
    assert user["classification"] == "user_requested_stop" and user["saved_leaf_proofs"] == 7
    assert user["saved_merge_proofs"] == 0 and user["sample_2_never_started"]
    assert not user["proof_capacity_failure"] and not user["resident_memory_failure"]
    g100 = ROOT / "risc-v/results/raccoong-segmented-uniform-trees/count-100"
    assert not (g100 / "sample-1").exists() and not (g100 / "sample-2").exists()
    assert not list(g100.glob("sample-2-*"))
    before = read(HERE / "resume-complete-roots-before-20GiB.json")
    for prior in before["roots"]:
        assert file_hash(ROOT / prior["path"]) == prior["marker_sha256"]
        assert file_hash((ROOT / prior["path"]).with_name("root.proof")) == prior["root_sha256"]

    summary = read(MATRIX / "measured-summary.json")
    assert summary["root_count"] == 22 and len(summary["points"]) == 8
    for point in summary["points"]:
        expected_samples = policy["expected_samples"][point["scheme"]][str(point["signatures"])]
        assert point["fresh_complete_samples"] == len(expected_samples)
        n, scheme = point["signatures"], point["scheme"]
        base = ROOT / ("risc-v/results/raccoong-segmented-uniform-trees" if scheme == "raccoon-g"
                       else "risc-v/results/raccoon-runtime-study/raccoon/trees")
        reports = [read(base / f"count-{n}/sample-{s}/report.json") for s in expected_samples]
        assert point["prove_samples_s"] == [r["total_prove_s"] for r in reports]
        close(point["reported_prove_s"], statistics.median(point["prove_samples_s"]))
        assert point["root_bytes_samples"] == [r["root_proof_bytes"] for r in reports]
        assert point["reported_root_bytes"] == statistics.median(point["root_bytes_samples"])
        if len(expected_samples) == 1:
            assert "single" in point["observation_type"] and "median" not in point["observation_type"]

    result = {"schema": 1, "status": "all_22_user_required_saved_pipelines_pass",
              "sampling_policy_sha256": file_hash(MATRIX / "sampling-policy.json"),
              "accepted_roots": accepted, "accepted_guard_counts": dict(guards),
              "cohort_freezes": freezes, "vendor_revisions_clean": pins,
              "coordinator_unchanged_sha256": coordinator, "old_archive_files_checked": 1277,
              "stop_archives": archives, "prior_17_complete_roots_and_markers_unchanged": True,
              "all_public_lists_match_canonical_corpus_prefix": public_prefixes,
              "g100_fresh_producer_samples": 1, "g100_never_label_as_three_run_median": True,
              "no_further_proving_run": True, "measured_summary_matches_actual_reports": True,
              "description": "Read-only final file/provenance/accounting audit. All real leaves and merges are freshly called in the reviewed producer; deterministic plain-proof equality is permitted. Complete native receiver checks and independent N100 mutations are recorded separately. This is not a formal whole-backend security proof.",
              "passed": True}
    (HERE / "FINAL-MATRIX-VALIDATION.json").write_text(json.dumps(result, indent=2) + "\n")
    print("All22actualpipelines, allproofhashes/publicbindings, source/binary/ELFpins,1277legacyfiles,77+12archives and17/5guard split pass")


if __name__ == "__main__":
    main()
