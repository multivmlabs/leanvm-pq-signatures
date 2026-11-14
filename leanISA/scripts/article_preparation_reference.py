#!/usr/bin/env python3
"""Extract preparation references from saved metadata; run no new timers/provers.

Original fixture construction is cached setup, not work repeated in each timed
proof run. Its historical Python cost can predate host optimizations. Recorded
merge advice preparation is a different, originally per-pass timer. Keep these
scopes separate rather than adding a cached setup time to every proof sample.
Run only after proving finishes: reading unique tree inputs can scan several GB.
Witnesses are parsed for their metadata but are never copied into the output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/article"
ARTIFACTS = ROOT / "artifacts/article"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=RESULTS / "preparation-reference.json")
    args = parser.parse_args()
    sources, warnings = {}, []

    def label(path):
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return str(path)

    def read(path):
        try:
            encoded = path.read_bytes()
            value = json.loads(encoded)
        except (OSError, ValueError) as error:
            warnings.append({"path": label(path), "error": str(error)})
            return None
        sources[label(path)] = hashlib.sha256(encoded).hexdigest()
        return value

    fixtures = []
    for path in sorted((RESULTS / "direct").glob("*.json")):
        match = re.fullmatch(r"(ethfalcon|falcon|ethdilithium|mldsa|fors)-(\d+)\.json", path.name)
        if not match:
            continue
        report = read(path)
        if report is None:
            continue
        seconds = report.get("metadata", {}).get("fixture_generation_s")
        if seconds is not None:
            count = int(match.group(2))
            fixtures.append({"scheme": match.group(1), "count": count,
                             "original_fixture_generation_s": seconds,
                             "original_fixture_generation_s_per_signature": seconds / count,
                             "input_sha256": report.get("input_sha256"),
                             "source_report": str(path.relative_to(ROOT)),
                             "repeated_in_each_timed_run": False})

    # The same prepared leaf file can be reused across counts, fan-ins and
    # samples. Resolve paths before deduplication and record its setup once.
    manifests = sorted(ARTIFACTS.glob("*/trees/*/manifest.json"))
    mixed = ARTIFACTS / "mixed/manifest.json"
    if mixed.exists():
        manifests.append(mixed)
    leaf_paths = {}
    for path in manifests:
        saved = read(path)
        if saved is None:
            continue
        for leaf in saved.get("leaves", []):
            source = Path(leaf["input_file"])
            if not source.is_absolute():
                source = path.parent / source
            source = source.resolve()
            leaf_paths.setdefault(source, set()).add(label(path))
    tree_fixtures = []
    for path, referenced_by in sorted(leaf_paths.items()):
        fixture = read(path)
        if fixture is None:
            continue
        metadata = fixture.get("metadata", {})
        seconds = metadata.get("fixture_generation_s")
        tree_fixtures.append({"source_path": label(path), "count": metadata.get("count"),
                              "original_fixture_generation_s": seconds,
                              "input_sha256": sources[label(path)],
                              "referenced_by_manifests": sorted(referenced_by),
                              "repeated_in_each_timed_run": False})
        if seconds is None:
            warnings.append({"path": label(path), "error": "no stored fixture_generation_s"})
        del metadata, fixture

    records = []
    for path in sorted((RESULTS / "inputs").glob("*-records.json")):
        saved = read(path)
        if saved is None:
            continue
        samples = [r["record_generation_s"] for r in saved if "record_generation_s" in r]
        records.append({"scheme": path.name.removesuffix("-records.json"), "record_count": len(saved),
                        "recorded_generation_samples": len(samples),
                        "original_generation_total_s": sum(samples),
                        "original_generation_median_s": statistics.median(samples) if samples else None,
                        "source_archive": str(path.relative_to(ROOT)),
                        "repeated_in_each_timed_run": False})

    advice = []
    for path in sorted((RESULTS / "trees").glob("*/sample-*.json")):
        if not re.fullmatch(r"sample-\d+\.json", path.name):
            continue
        report = read(path)
        if report is None:
            continue
        passes = [{"pass": item["pass"],
                   "recorded_merge_advice_preparation_s": sum(node["prepare_s"] for node in item["nodes"])}
                  for item in report.get("merge_passes", [])]
        advice.append({"case": path.parent.name, "source_report": str(path.relative_to(ROOT)),
                       "measurement_scope": report.get("measurement_scope"),
                       "recorded_leaf_input_loading_s": sum(item.get("input_prepare_s", 0)
                                                              for item in report.get("leaf_reports", [])),
                       "recorded_leaf_cache_load_verify_s": sum(item.get("cache_load_verify_s", 0)
                                                                  for item in report.get("leaf_reports", [])),
                       "passes": passes})

    summary = {
        "schema_version": 1, "extraction_only_no_new_measurements": True,
        "fixture_scope": "Historical original Python reference validation, witness/source/PI generation; cached setup, not repeated for each timed proof. May predate later host encoding optimizations.",
        "record_scope": "Original benchmark key/signature generation metadata; not signing/proving samples and not repeated per timed run.",
        "advice_scope": "Extracted original per-pass child-proof checking and recursive witness preparation timers; distinct from cached fixture generation and prove_s. No fresh measurements performed by this script.",
        "fixture_references": fixtures, "unique_tree_leaf_fixture_references": tree_fixtures,
        "record_references": records, "recorded_tree_advice": advice,
        "source_sha256": sources, "warnings": warnings,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"out": str(args.out), "fixtures": len(fixtures), "record_archives": len(records),
                      "unique_tree_leaf_fixtures": len(tree_fixtures), "tree_reports": len(advice),
                      "warnings": len(warnings), "new_measurements": False}))


if __name__ == "__main__":
    main()
