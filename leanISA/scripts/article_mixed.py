#!/usr/bin/env python3
"""One mixed-tree correctness demonstration, using two claims per signature family.

All ten leaves contain one signature, preserving the existing tree's exact-count
rules. This is not a timing curve, topology optimization or gas experiment.
Family-major leaves are interleaved by LEAF_ORDER, placing FORS and lattice
programs with different bytecode sizes in each of the first two parents.
`dry` compiles a public-only plan; `prepare` also creates signature witnesses.
Only explicit `prove` starts proving. Verification derives authorized sources
and leaf PIs from an independently trusted public-claims file, without witnesses.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import article_inputs as ai

FAMILIES = ("ethfalcon", "falcon", "ethdilithium", "mldsa", "fors")
LEAF_ORDER = (0, 8, 2, 4, 6, 9, 1, 3, 5, 7)
SCHEME = "mixed-five-signatures"
ARTIFACTS = ai.ARTIFACTS / "mixed"
RESULTS = ROOT / "results/article/mixed"
RUNNER = ROOT / "target/release/aggregate-tree"
SCOPE = "One mixed correctness demonstration; no timing curve, optimality claim or gas measurement."


def checked_public(bundle):
    if bundle.get("schema_version") != 1 or bundle.get("scheme") != SCHEME:
        raise ValueError("expected the version1 mixed-five-signatures public statement")
    families = bundle.get("families", [])
    if [item.get("scheme") for item in families] != list(FAMILIES):
        raise ValueError("expected the five families in their canonical order")
    if any(len(item.get("records", [])) != 2 for item in families):
        raise ValueError("exactly two intended public claims per family required")
    # Canonicalize from actual key/message fields only. Advisory hashes, source
    # metadata and signature bytes supplied in a public file have no role.
    return {"schema_version": 1, "scheme": SCHEME, "families": [
        {"scheme": item["scheme"], "records": [
            {"public_key_hex": bytes.fromhex(r["public_key_hex"]).hex(),
             "message_hex": bytes.fromhex(r["message_hex"]).hex()} for r in item["records"]]}
        for item in families]}


def saved_inputs():
    records = {}
    for family in FAMILIES:
        path = ai.ARTIFACTS / family / "records.json"
        archive = ROOT / "results/article/inputs" / f"{family}-records.json"
        # Prefer the preserved public dataset over the mutable artifact cache.
        # This is the same archive used by ai.records' clean-checkout fallback,
        # but never extends a partial dataset by creating new random claims.
        if archive.exists():
            values = json.loads(archive.read_text())
        elif path.exists():
            values = json.loads(path.read_text())
        else:
            raise ValueError(f"missing saved {family} records; run the main record preparation first")
        if len(values) < 2:
            raise ValueError(f"need two saved {family} records")
        records[family] = values[:2]
    public = {"schema_version": 1, "scheme": SCHEME, "families": [
        {"scheme": family, "records": [ai.public_record(family, record) for record in records[family]]}
        for family in FAMILIES]}
    return checked_public(public), records


def manifest(public, directory, raw=None):
    public = checked_public(public)
    programs, leaves = [], []
    for item in public["families"]:
        family = item["scheme"]
        family_directory = directory / family
        part = ai.make_manifest(family, 2, 4, 1, directory=family_directory, public_only=item["records"])
        if raw is not None:
            expected = [ai.public_record(family, r) for r in raw[family]]
            if expected != item["records"]:
                raise ValueError(f"{family} records differ from intended public claims")
            for leaf, record in zip(part["leaves"], raw[family]):
                fixture = ai.build(family, [record])
                if ai.pi_hex(fixture["public_input"]) != leaf["public_input_hex"]:
                    raise ValueError(f"{family} fixture differs from independently derived statement")
                ai.write(Path(leaf["input_file"]), fixture)
        names = {p["id"]: family + ":" + p["id"] for p in part["programs"]}
        programs.extend({**p, "id": names[p["id"]]} for p in part["programs"])
        leaves.extend({**leaf, "program_id": names[leaf["program_id"]]} for leaf in part["leaves"])
    if len(leaves) != 10 or any(leaf["signatures"] != 1 for leaf in leaves):
        raise ValueError("mixed tree must contain exactly ten one-signature leaves")
    leaves = [leaves[i] for i in LEAF_ORDER]
    return {"schema_version": 1, "scheme": SCHEME, "signatures": 10,
            "leaf_capacity": 1, "fan_in": 4, "programs": programs, "leaves": leaves}


def inspect(path):
    result = subprocess.run([str(RUNNER), "inspect", "--manifest", str(path)],
                            capture_output=True, text=True, check=True, cwd=ROOT)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("dry", "prepare", "prove", "verify"))
    parser.add_argument("--public", type=Path, default=ARTIFACTS / "public.json",
                        help="independently trusted intended public claims, never selected by a received proof")
    parser.add_argument("--proof", type=Path, default=ARTIFACTS / "run/aggregate.proof")
    args = parser.parse_args()
    if args.action in ("dry", "prepare"):
        public, raw = saved_inputs()
        ai.write(args.public, public)
        expected = manifest(public, ARTIFACTS / "inputs", raw if args.action == "prepare" else None)
        path = ARTIFACTS / "manifest.json"
    else:
        public = checked_public(json.loads(args.public.read_text()))
        # For prove, retain the prepared input paths. For verify, all leaf input
        # paths can be absent; only authorized source and public statements matter.
        directory = ARTIFACTS / ("receiver-inputs" if args.action == "verify" else "inputs")
        expected = manifest(public, directory)
        path = ARTIFACTS / ("receiver.json" if args.action == "verify" else "manifest.json")
    ai.write(path, expected)
    plan = inspect(path)
    ai.write(RESULTS / "plan.json", plan)
    if args.action == "prove":
        if any(not Path(leaf["input_file"]).exists() for leaf in expected["leaves"]):
            raise ValueError("missing prepared signature witnesses; run prepare first")
        RESULTS.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(RUNNER), "prove", "--manifest", str(path), "--expect-plan-hash", plan["plan_hash"],
                        "--leaf-cache-dir", str(ARTIFACTS / "leaves"), "--out-dir", str(ARTIFACTS / "run"),
                        "--rate", "1", "--repeat", "1", "--warmup", "0", "--fresh-leaves",
                        "--report", str(RESULTS / "prove.json")], check=True, cwd=ROOT)
    elif args.action == "verify":
        RESULTS.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(RUNNER), "verify", "--manifest", str(path), "--expect-plan-hash", plan["plan_hash"],
                        "--proof", str(args.proof), "--repeat", "1", "--warmup", "0",
                        "--report", str(RESULTS / "verify.json")], check=True, cwd=ROOT)
    print(json.dumps({"action": args.action, "scope": SCOPE, "scheme": SCHEME,
                      "signatures": 10, "claims_per_family": 2, "leaf_capacity": 1, "fan_in": 4,
                      "leaf_order_family_major_indices": LEAF_ORDER,
                      "leaf_count": plan["leaf_count"], "merge_count": plan["merge_count"],
                      "edge_count": plan["edge_count"], "depth": plan["depth"],
                      "plan_hash": plan["plan_hash"], "root_guest_hash": plan["root_guest_hash"],
                      "public_file": str(args.public), "manifest": str(path)}, indent=2))


if __name__ == "__main__":
    main()
