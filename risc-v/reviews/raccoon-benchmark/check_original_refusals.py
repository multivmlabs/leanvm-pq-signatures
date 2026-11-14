#!/usr/bin/env python3
"""Audit original frozen-guest capacity/prover refusal evidence without reruns."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
STUDY = ROOT / "risc-v/results/raccoon-study"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    env = json.loads((STUDY / "environment.json").read_text())
    results = []
    for scheme in ("raccoon", "raccoon-g"):
        counts = []
        for path in (STUDY / scheme / "capacity").glob("count-*.json"):
            match = re.fullmatch(r"count-(\d+)\.json", path.name)
            if not match:
                continue
            report = json.loads(path.read_text())
            completed_path = path.with_name(path.stem + ".completed.json")
            if not completed_path.exists():
                continue
            completed = json.loads(completed_path.read_text())
            assert completed["exit_code"] == 0 and completed["aborted"] is None
            assert completed["binary_sha256"] == env["direct_binary_sha256"]
            assert report["scheme"] == scheme and report["count"] == int(match[1])
            assert report["elf_sha256"] == env["schemes"][scheme]["elf_sha256"]
            assert report["leanvm_revision"] == env["backend_revision"]
            assert report["action"] == "measure"
            assert report["status"] == "rejected" and report["error"] == "TooLong"
            counts.append(int(match[1]))
        direct = []
        for directory in (STUDY / scheme / "direct").glob("count-*"):
            path = directory / "report.json"
            completed_path = directory / "producer.completed.json"
            if not path.exists() or not completed_path.exists():
                continue
            report = json.loads(path.read_text())
            completed = json.loads(completed_path.read_text())
            assert completed["exit_code"] == 0 and completed["aborted"] is None
            assert completed["binary_sha256"] == env["direct_binary_sha256"]
            assert report["scheme"] == scheme and directory.name == f"count-{report['count']}"
            assert report["elf_sha256"] == env["schemes"][scheme]["elf_sha256"]
            assert report["status"] == "rejected" and report["error"] == report["prover_error"] == "TooLong"
            assert report["action"] == "prove" and report["zero_knowledge"] is False
            assert not (directory / "root.proof").exists()
            direct.append(report["count"])
        results.append({"scheme": scheme, "elf_sha256": env["schemes"][scheme]["elf_sha256"],
                        "capacity_refusals_checked": sorted(counts),
                        "all_64_capacity_prefixes_checked": sorted(counts) == list(range(1, 65)),
                        "actual_prover_refusals_checked": sorted(direct),
                        "all_30_direct_attempts_checked": sorted(direct) == list(range(1, 31)),
                        "no_saved_root_proofs": True})
    output = {"schema": 1,
              "scope": "Read-only audit of production refusals for the original frozen guest ELFs; no reruns or inferred proof points",
              "environment_sha256": sha(STUDY / "environment.json"),
              "direct_binary_sha256": env["direct_binary_sha256"],
              "records": results,
              "complete_original_refusal_matrix": all(r["all_64_capacity_prefixes_checked"] and r["all_30_direct_attempts_checked"] for r in results),
              "proof_size_and_accepted_proving_time": None,
              "qualification": "TooLong is a backend refusal, not a successful proof. Diagnostic full-execution layout estimates are separate evidence."}
    target = Path(__file__).with_name("original-rejection-validation.json")
    target.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"complete": output["complete_original_refusal_matrix"],
                      "counts": [{"scheme": r["scheme"], "capacity": len(r["capacity_refusals_checked"]), "actual_prover_refusals": len(r["actual_prover_refusals_checked"])} for r in results]}))


if __name__ == "__main__":
    main()
