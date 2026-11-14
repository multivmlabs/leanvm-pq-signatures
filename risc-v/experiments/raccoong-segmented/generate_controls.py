#!/usr/bin/env python3
"""Independent byte-hash controls, not cached benchmark witness preparation."""
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "risc-v/raccoon-g"))
import generate_fixtures as reference


def main():
    reference.check_source()
    original = ROOT / "risc-v/raccoon-g"
    cases = []
    for index in range(3):
        value = json.loads((original / f"host/testdata/record-{index}.json").read_text())
        cases.append({"name": f"ordinary-{index}", **value, "expected_integer_accepts": True})
    cases.extend(json.loads((original / "host/testdata/norm-controls.json").read_text())["cases"])
    result = []
    for case in cases:
        pk = bytes.fromhex(case["public_key"])
        message = bytes.fromhex(case["message"])
        signature = bytes.fromhex(case["signature"])
        intermediate = reference.reconstruct(pk, message, signature)
        assert intermediate["challenge_matches"]
        w = b"".join(value.to_bytes(2,"little") for row in intermediate["w"] for value in row)
        assert len(w) == 4608
        binding = b""
        for branch in range(2):
            domain = f"pqbench/rcg-wit/strictv1/hash{branch}v1".encode()
            assert len(domain) == 32
            preimage = domain + (20768).to_bytes(8,"little") + (4608).to_bytes(8,"little") + signature + w
            binding += hashlib.blake2s(preimage).digest()
        domain = b"pqbench/rcg-two/strictv1/d512/v1"
        assert len(domain) == 32
        outputs = []
        for part in range(5):
            preimage = domain + part.to_bytes(8,"little") + (2*part).to_bytes(8,"little") + min(2*part+1,8).to_bytes(8,"little") + pk + message + binding
            outputs.append(hashlib.blake2s(preimage).hexdigest())
        assert intermediate["integer_norm_accepts"] == case["expected_integer_accepts"]
        result.append({**case, "w_le16": w.hex(), "binding": binding.hex(), "expected_part_outputs": outputs})
    path = HERE / "review/codec-controls.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"scope":"Correctness-only controls; never used as benchmark witness preparation", "excluded_from_benchmarks":True, "cases":result}, indent=2)+"\n")
    print(json.dumps({"path":str(path.relative_to(ROOT)),"cases":len(result)}))


if __name__ == "__main__":
    main()
