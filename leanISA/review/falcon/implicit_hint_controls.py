"""Adversarial implicit bit-hint checks against the exact Falcon bytecode.

Computed bit hints are replaced with named witness streams. The honest variant
must execute with the same guest_hash as the original program, demonstrating
that these tests vary advice and preserve the proved bytecode relation.
No proof generation is needed to reject a conflicting execution witness.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import falcon as f


def bit_row(value, n):
    return [f.cell((value >> j) & 1) for j in range(n)]


def main():
    fixture = f.build(1)
    record = fixture["metadata"]["records"][0]
    h = f.decode_key(bytes.fromhex(record["public_key_hex"]))
    s2 = f.decode_signature(bytes.fromhex(record["signature_hex"])[41:])
    salt, message = bytes.fromhex(record["salt_hex"]), bytes.fromhex(record["message_hex"])
    modified = copy.deepcopy(fixture)
    source = modified["source"]
    swaps = (
        ("hint_decompose_bits(bits, value, 8)", 'hint_witness(bits[0:8], "salt_bits")'),
        ("hint_decompose_bits_exponent(bits, value, 14)", 'hint_witness(bits[0:14], "key_bits")'),
        ("hint_decompose_bits_exponent(bits, b, 14)", 'hint_witness(bits[0:14], "mul_bits")'),
        ("hint_decompose_bits(bits, word, 128)", 'hint_witness(bits[0:128], "digest_bits")'),
        ("hint_decompose_bits_exponent(counter_bits, block, 6)", 'hint_witness(counter_bits[0:6], "counter_bits")'),
        ("hint_decompose_bits_exponent(bits, magnitude, 13)", 'hint_witness(bits[0:13], "magnitude_bits")'),
    )
    for before, after in swaps:
        assert source.count(before) == 1, before
        source = source.replace(before, after)
    modified["source"] = source
    w = modified["witness"]
    w["salt_bits"] = [bit_row(x, 8) for x in salt + message]
    w["key_bits"] = [bit_row(x, 14) for x in h]
    transformed = f.Witness().transform([x % f.Q for x in s2])
    w["mul_bits"] = [bit_row(x, 14) for x in transformed]
    w["counter_bits"] = [bit_row(x, 6) for x in range(40)]
    seed = f.digest(salt + message)
    w["digest_bits"] = []
    for counter in range(40):
        digest = f.digest(seed + counter.to_bytes(8, "big"))
        w["digest_bits"] += [bit_row(int.from_bytes(digest[i:i+16], "little"), 128) for i in (0, 16)]
    inverse = {value: exponent for exponent, value in enumerate(f._GPOW)}
    w["magnitude_bits"] = [bit_row(inverse[row[0][0]], 13) for row in w["magnitude"]]

    results = []
    with tempfile.TemporaryDirectory(prefix="falcon-hint-controls-") as directory:
        def execute(value, label, success):
            path = Path(directory) / (label + ".json")
            path.write_text(json.dumps(value))
            run = subprocess.run([str(ROOT / "target/release/pq-leanbench"), "execute", "--input", str(path)],
                                 cwd=ROOT, env={**os.environ, "LEANVM_NUM_THREADS": "1"},
                                 text=True, capture_output=True, timeout=60)
            assert (run.returncode == 0) == success, (label, run.stderr)
            if success:
                return json.loads(run.stdout)
            results.append({"attack": label, "rejected": True, "error": run.stderr.strip()})
        original = execute(fixture, "original", True)
        honest = execute(modified, "honest_explicit_bits", True)
        assert original["guest_hash"] == honest["guest_hash"]
        for name in ("salt_bits", "key_bits", "mul_bits", "digest_bits", "counter_bits", "magnitude_bits"):
            for value, suffix in (([2, 0, 0], "non_boolean"), ([0, 1, 0], "extension")):
                bad = copy.deepcopy(modified)
                bad["witness"][name][0][0] = value
                execute(bad, name + "_" + suffix, False)
    print(json.dumps({"guest_hash": honest["guest_hash"], "bytecode_unchanged": True,
                      "cycles": honest["cycles"], "cases": results}, indent=2))


if __name__ == "__main__":
    main()
