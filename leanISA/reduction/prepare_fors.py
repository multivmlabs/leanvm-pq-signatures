#!/usr/bin/env python3
"""Prepare unchanged Python-DSL FORS leaves for the reduced recursive tree."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "leanISA/python"))
from pqbench import article_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--leaf-size", type=int, default=5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not (2 <= args.count <= 100 and 1 <= args.leaf_size <= 5
            and args.count % args.leaf_size == 0 and args.count // args.leaf_size >= 2):
        parser.error("require 2..100 signatures, 1..5 per leaf and at least two whole leaves")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    records = json.loads((ROOT / "leanISA/results/article/inputs/fors-records.json").read_text())[:args.count]
    public = [article_inputs.public_record("fors", r) for r in records]
    source = article_inputs.leaf_source("fors", args.leaf_size)
    config = {"schema": 1, "backend_revision": "575df819d9c857f38068cecf7b1640e0ce4bfb29",
              "scheme": "fors", "signatures": args.count, "leaf_size": args.leaf_size,
              "leaf_source": source, "public_records": public}
    for i, start in enumerate(range(0, args.count, args.leaf_size)):
        fixture = article_inputs.build("fors", records[start:start + args.leaf_size])
        if fixture["source"] != source:
            raise ValueError("leaf source mismatch")
        (out / f"leaf-{i}.input.json").write_text(json.dumps(fixture) + "\n")
    path = out / "public.json"
    path.write_text(json.dumps(config, indent=2) + "\n")
    print(json.dumps({"public": str(path), "public_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "signatures": args.count, "leaf_size": args.leaf_size,
                      "real_leaves": args.count // args.leaf_size}))


if __name__ == "__main__":
    main()
