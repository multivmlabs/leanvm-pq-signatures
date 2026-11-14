#!/usr/bin/env python3
"""Count required Keccak permutations from byte-level signature inputs.

The oracle uses hashlib for the independent SHAKE byte streams. It does not
execute a VM, run a prover, or estimate proof sizes. It checks the diagnostic
function-call counts against exact absorbed and consumed byte lengths.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def stream_sample(seed, n, q, bits, rate, algorithm):
    stream = algorithm(seed)
    wanted = 8192
    data = stream.digest(wanted)
    offset = accepted = draws = 0
    while accepted < n:
        if offset + 7 > len(data):
            wanted *= 2
            data = stream.digest(wanted)
        value = int.from_bytes(data[offset:offset + 7], "little") & ((1 << bits) - 1)
        offset += 7
        draws += 1
        accepted += value < q
    return {"draws": draws, "accepted": n, "rejected": draws - n,
            "bytes_consumed": offset, "keccak_permutations": (offset + rate - 1) // rate}


def main():
    rows = []
    for scheme in ("raccoon", "raccoon-g"):
        if scheme == "raccoon":
            fixture = ROOT / "risc-v/raccoon/review/fixture-0.json"
            record = json.loads(fixture.read_text())
            pk = bytes.fromhex(record["compact_public_key_hex"])
            signature = bytes.fromhex(record["compact_signature_hex"])
            k, ell, n, q, bits, rate, weight = 5, 4, 512, 549824583172097, 49, 136, 19
            algorithm = hashlib.shake_256
            commitment_bytes = 8 + 32 + k * n
            diagnostic = ROOT / "risc-v/experiments/raccoon-fit/raccoon-1-layout.json"
        else:
            fixture = ROOT / "risc-v/raccoon-g/host/testdata/record-0.json"
            record = json.loads(fixture.read_text())
            pk = bytes.fromhex(record["public_key"])
            signature = bytes.fromhex(record["signature"])
            k, ell, n, q, bits, rate, weight = 9, 9, 256, 562949953438721, 50, 168, 23
            algorithm = hashlib.shake_128
            commitment_bytes = 8 + 32 + k * n * 7
            diagnostic = ROOT / "risc-v/experiments/raccoon-fit/raccoong-1-layout.json"
        matrices = []
        for i in range(k):
            for j in range(ell):
                header = bytes([ord("A"), i, j, 0, 0, 0, 0, 0])
                matrices.append({"row": i, "column": j,
                    **stream_sample(header + pk[:16], n, q, bits, rate, algorithm)})
        challenge_stream = hashlib.shake_256(bytes([ord("c"), weight, 0, 0, 0, 0, 0, 0]) + signature[:32]).digest(4096)
        positions = set()
        consumed = 0
        while len(positions) < weight:
            sample = int.from_bytes(challenge_stream[consumed:consumed + 2], "little")
            consumed += 2
            positions.add((sample >> 1) & (n - 1))
        components = {
            "public_key_hash": len(pk) // 136 + 1,
            "message_hash": 1,
            "challenge": (consumed + 135) // 136,
            "matrix_expansion": sum(m["keccak_permutations"] for m in matrices),
            "commitment_hash": commitment_bytes // 136 + 1,
        }
        total = sum(components.values())
        observed = json.loads(diagnostic.read_text())
        assert total == observed["keccak_permutation_calls"]
        rows.append({"scheme": scheme, "index": 0, "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                     "diagnostic_sha256": hashlib.sha256(diagnostic.read_bytes()).hexdigest(),
                     "matrix_polynomials": k * ell, "matrix_details": matrices,
                     "component_permutations": components, "total_keccak_permutations": total,
                     "observed_function_calls": observed["keccak_permutation_calls"],
                     "matches_diagnostic": True})
    result = {"schema": 1, "scope": "Independent exact SHAKE byte-consumption count, not a proof or benchmark timing", "records": rows}
    target = Path(__file__).with_name("permutation-oracle.json")
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps([{k: row[k] for k in ("scheme", "component_permutations", "total_keccak_permutations", "matches_diagnostic")} for row in rows]))


if __name__ == "__main__":
    main()
