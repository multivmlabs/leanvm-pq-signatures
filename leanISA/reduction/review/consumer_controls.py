#!/usr/bin/env python3
"""Independent public-record binding and isolated production receipt controls.

Uses no signature advice or child proof files. Run after timed proving jobs.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from Crypto.Hash import keccak


def digest(data):
    return keccak.new(digest_bits=256, data=data).digest()


def intended_semantic(public):
    records = public["public_records"]
    assert public["scheme"] == "fors" and len(records) == public["signatures"]
    pairs = [(bytes.fromhex(r["public_key_hex"]), bytes.fromhex(r["message_hex"])) for r in records]
    assert all(len(k) == 64 and len(m) == 32 for k, m in pairs)
    assert len(set(pairs)) == len(pairs)
    size = public["leaf_size"]
    assert len(pairs) % size == 0
    leaves = [digest(b"FORS:BATCH\0\0" + bytes([1, 32, 16, 8])
                     + b"".join(k + m for k, m in pairs[i:i + size]))
              for i in range(0, len(pairs), size)]
    slots = 1 << (len(leaves) - 1).bit_length()
    level = leaves + [leaves[-1]] * (slots - len(leaves))
    while len(level) > 1:
        level = [digest(b"pq-red-claim/v1\0" + (2).to_bytes(16, "little") + a + b)
                 for a, b in zip(level[::2], level[1::2])]
    return level[0], slots, leaves


def encoded_semantic(root):
    assert root[:8] == b"LIRDT001" and len(root) > 240
    # Fixint bincode Envelope: magic8, three usize/u64 values, three pairs of
    # full E fields, then State.claim_digest as two 24-byte E fields.
    assert root[192:200] == root[216:224] == bytes(8)
    return root[176:192] + root[200:216]


def mutate_hex(text, index=0):
    raw = bytearray.fromhex(text)
    raw[index] ^= 1
    return raw.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--leaf-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    public = json.loads(args.public.read_text())
    proof = args.proof.read_bytes()
    expected, slots, leaves = intended_semantic(public)
    assert expected == encoded_semantic(proof), "root does not bind all independently intended public records"
    assert int.from_bytes(proof[8:16], "little") == public["signatures"]
    assert int.from_bytes(proof[16:24], "little") == slots
    cases = [("honest-public-only", public, proof, True, {})]
    for name, field in (("changed-key-recommitted", "public_key_hex"), ("changed-message-recommitted", "message_hex")):
        changed = copy.deepcopy(public)
        changed["public_records"][0][field] = mutate_hex(changed["public_records"][0][field])
        cases.append((name, changed, proof, False, {}))
    changed = copy.deepcopy(public)
    changed["public_records"][0], changed["public_records"][1] = changed["public_records"][1], changed["public_records"][0]
    cases.append(("reordered-records-recommitted", changed, proof, False, {}))
    changed = copy.deepcopy(public)
    changed["public_records"][-1] = changed["public_records"][0]
    cases.append(("duplicate-pair", changed, proof, False, {}))
    changed = copy.deepcopy(public)
    changed["signatures"] -= changed["leaf_size"]
    changed["public_records"] = changed["public_records"][:changed["signatures"]]
    cases.append(("changed-count-recommitted", changed, proof, False, {}))
    changed = copy.deepcopy(public)
    changed["backend_revision"] = "0" * 40
    cases.append(("changed-backend", changed, proof, False, {}))
    changed = copy.deepcopy(public)
    changed["leaf_source"] = "from snark_lib import *\n\ndef main():\n    return\n"
    cases.append(("unapproved-leaf-source", changed, proof, False, {}))
    cases.append(("wrong-public-pin", public, proof, False, {"public_pin": "0" * 64}))
    cases.append(("wrong-leaf-pin", public, proof, False, {"leaf_pin": "0" * 64}))
    for name, at in (("changed-root-magic", 0), ("changed-root-seed", 128),
                     ("changed-semantic-high-limb", 192), ("changed-accumulator-point-high-limb", 256)):
        changed = bytearray(proof)
        changed[at] ^= 1
        cases.append((name, public, bytes(changed), False, {}))
    n = int.from_bytes(proof[232:240], "little")
    assert 1 <= n <= 32
    changed = bytearray(proof)
    changed[240 + 24 * n + 16] ^= 1
    cases.append(("changed-accumulator-value-high-limb", public, bytes(changed), False, {}))
    changed = bytearray(proof)
    changed[-100] ^= 1
    cases.append(("corrupted-root-transcript", public, bytes(changed), False, {}))
    cases.append(("appended-root-bytes", public, proof + b"unauthenticated", False, {}))
    cases.append(("truncated-root", public, proof[:-17], False, {}))
    results = []
    for name, statement, root_bytes, expect_accept, flags in cases:
        with tempfile.TemporaryDirectory(prefix="leanisa-reduced-public-only-") as directory:
            cwd = Path(directory)
            public_path, proof_path, report_path = cwd / "public.json", cwd / "root.proof", cwd / "verify.json"
            raw = json.dumps(statement, indent=2).encode()
            public_path.write_bytes(raw)
            proof_path.write_bytes(root_bytes)
            command = [str(binary), "verify", "--public", str(public_path), "--proof", str(proof_path),
                       "--out", str(report_path), "--expect-public-sha256", flags.get("public_pin", hashlib.sha256(raw).hexdigest()),
                       "--expect-leaf-guest-hash", flags.get("leaf_pin", args.leaf_pin), "--repeat", "1"]
            ran = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
            accepted = ran.returncode == 0
            assert accepted == expect_accept, (name, ran.stdout, ran.stderr)
            if accepted:
                receipt = json.loads(report_path.read_text())
                assert receipt["verified"] and receipt["all_reduced_claims_settled"]
                assert not receipt["uses_child_proof_files"] and not receipt["uses_signature_witnesses"]
            results.append({"case": name, "expected_accept": expect_accept, "accepted": accepted,
                            "passed": accepted == expect_accept, "stderr": ran.stderr.strip()})
    report = {"schema": 1, "signatures": public["signatures"], "real_leaves": len(leaves), "leaf_slots": slots,
              "independently_recomputed_semantic_digest_hex": expected.hex(),
              "all_public_pairs_bound": True, "public_only_isolated_cwd": True,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "proof_sha256": hashlib.sha256(proof).hexdigest(), "passed": len(results), "cases": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}))


if __name__ == "__main__":
    main()
