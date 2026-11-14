#!/usr/bin/env python3
"""Independent public-only controls for saved RISC-V recursive roots.

This creates no proofs. Each invocation runs the unchanged production consumer
from an isolated directory containing only a public statement and one root.
Changed claims receive freshly computed BLAKE2s outputs and a fresh caller pin,
so rejection cannot be explained merely by an unchanged statement hash.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def digest_leaf(scheme, records):
    data = bytearray()
    if scheme == "mldsa":
        data += b"pqbench/mldsa44/compact/v1".ljust(32, b"\0")
        data += len(records).to_bytes(8, "little")
    elif scheme != "falcon":
        raise ValueError("unsupported scheme")
    for record in records:
        key = bytes.fromhex(record["public_key"])
        message = bytes.fromhex(record["message"])
        assert len(message) == 32
        if scheme == "falcon":
            assert len(key) == 897 and key[0] == 9
            key = key[1:]
            data += b"".join(key[i:i + 8][::-1] for i in range(0, len(key), 8))
        else:
            assert len(key) == 1312
            data += key
        data += message
    digest = hashlib.blake2s(data).digest()
    return [int.from_bytes(digest[i:i + 8], "little") for i in range(0, 32, 8)]


def leaf_outputs(statement):
    size = statement["leaf_size"]
    records = statement["public_records"]
    assert size > 0 and len(records) % size == 0
    return [digest_leaf(statement["scheme"], records[i:i + size])
            for i in range(0, len(records), size)]


def check_root_digest(statement, proof):
    """Independently check the ordered/padded tree digest in the root envelope.

    The protocol stores kind then two F192 digest halves, each with a zero top
    limb. This is a public binding check, not a substitute for STARK verification.
    """
    assert proof[:6] == b"LVMT\x13\0", "unexpected tree protocol envelope"
    assert proof[6] == statement["log_inverse_rate"]
    words = int.from_bytes(proof[7:11], "little")
    assert words >= 3 and len(proof) > 11 + words * 24
    actual = [b"".join(w.to_bytes(8, "little") for w in output)
              for output in leaf_outputs(statement)]
    actual += [actual[-1]] * (statement["leaf_slots"] - len(actual))

    def combine(tag, items):
        header = tag + len(items).to_bytes(8, "little") + b"\0" * 48
        return hashlib.blake2s(header + b"".join(items)).digest()

    level = [combine(b"tree-fst", actual[i:i + statement["arity_0"]])
             for i in range(0, len(actual), statement["arity_0"])]
    expected_kind = 0 if len(level) == 1 else 1
    while len(level) > 1:
        level = [combine(b"tree-nod", level[i:i + statement["arity"]])
                 for i in range(0, len(level), statement["arity"])]
    assert int.from_bytes(proof[11:35], "little") == expected_kind
    assert proof[51:59] == proof[75:83] == b"\0" * 8
    assert proof[35:51] + proof[59:75] == level[0], "independent tree digest differs from root statement"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = args.runner.resolve()
    runner_hash = hashlib.sha256(runner.read_bytes()).hexdigest()
    original = json.loads(args.statement.read_text())
    proof = args.proof.read_bytes()
    assert leaf_outputs(original) == original["expected_leaf_outputs"]
    assert original["signatures"] == len(original["public_records"])
    assert original["actual_leaves"] * original["leaf_size"] == original["signatures"]
    assert original["leaf_slots"] == max(2, 1 << (original["actual_leaves"] - 1).bit_length())
    assert len({bytes.fromhex(r["public_key"]) for r in original["public_records"]}) == original["signatures"]
    check_root_digest(original, proof)
    expected_elf = original["elf_sha256"]
    cases = [("honest", original, proof, True, expected_elf, None)]

    def add_statement(name, changed, *, recommit=False):
        if recommit:
            changed["expected_leaf_outputs"] = leaf_outputs(changed)
        cases.append((name, changed, proof, False, expected_elf, None))

    for field in ("public_key", "message"):
        changed = copy.deepcopy(original)
        value = bytearray.fromhex(changed["public_records"][0][field])
        value[-1] ^= 1
        changed["public_records"][0][field] = value.hex()
        add_statement("changed-" + field + "-recommitted", changed, recommit=True)
    changed = copy.deepcopy(original)
    changed["public_records"][0], changed["public_records"][1] = changed["public_records"][1], changed["public_records"][0]
    add_statement("reordered-records-recommitted", changed, recommit=True)
    if original["actual_leaves"] >= 2:
        changed = copy.deepcopy(original)
        size = changed["leaf_size"]
        changed["public_records"][:2 * size] = changed["public_records"][size:2 * size] + changed["public_records"][:size]
        add_statement("reordered-leaves-recommitted", changed, recommit=True)
    changed = copy.deepcopy(original)
    changed["signatures"] += 1
    add_statement("wrong-signature-count", changed)
    changed = copy.deepcopy(original)
    changed["expected_leaf_outputs"][0][0] ^= 1
    add_statement("wrong-cached-leaf-output", changed)
    changed = copy.deepcopy(original)
    changed["leaf_slots"] *= 2
    add_statement("wrong-padding-slots", changed)
    changed = copy.deepcopy(original)
    changed["arity"] = 4
    add_statement("wrong-node-arity", changed)
    changed = copy.deepcopy(original)
    changed["arity_0"] = 1
    add_statement("wrong-first-arity", changed)
    changed = copy.deepcopy(original)
    changed["backend_revision"] = "00" * 20
    add_statement("wrong-backend-pin", changed)
    changed = copy.deepcopy(original)
    changed["elf_sha256"] = "00" * 32
    add_statement("wrong-statement-elf", changed)
    changed = copy.deepcopy(original)
    changed["log_inverse_rate"] = 2
    add_statement("wrong-tree-rate", changed)
    for name, value in (("zero-height", 0), ("non-power-two-height", 3), ("too-large-height", 1 << 29)):
        changed = copy.deepcopy(original)
        changed["table_rows"][0] = value
        add_statement(name, changed)
    changed = copy.deepcopy(original)
    changed["table_rows"].pop()
    add_statement("missing-height", changed)
    changed = copy.deepcopy(original)
    changed["schema"] += 1
    add_statement("wrong-statement-schema", changed)
    changed = copy.deepcopy(original)
    changed["unrecognized"] = True
    add_statement("unknown-statement-field", changed)
    cases.append(("wrong-trusted-elf", original, proof, False, "00" * 32, None))
    cases.append(("wrong-trusted-statement", original, proof, False, expected_elf, "00" * 32))
    for name, index in (("corrupt-magic", 0), ("corrupt-version", 4), ("corrupt-proof-middle", len(proof) // 2)):
        changed_proof = bytearray(proof)
        changed_proof[index] ^= 1
        cases.append((name, original, changed_proof, False, expected_elf, None))
    cases += [("truncated-root", original, proof[:-1], False, expected_elf, None),
              ("trailing-root-byte", original, proof + b"\0", False, expected_elf, None)]
    controls = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, statement, root, accepts, elf_pin, statement_pin in cases:
        assert hashlib.sha256(runner.read_bytes()).hexdigest() == runner_hash, "reviewed consumer binary changed during controls"
        with tempfile.TemporaryDirectory(prefix="riscv-tree-receiver-") as folder:
            directory = Path(folder)
            public = directory / "statement.json"
            received = directory / "root.proof"
            public.write_text(json.dumps(statement))
            received.write_bytes(root)
            command = [str(runner), "verify", "--outdir", str(directory / "receiver"),
                       "--statement", str(public), "--proof", str(received),
                       "--expect-statement-sha256", statement_pin or hashlib.sha256(public.read_bytes()).hexdigest(),
                       "--expect-elf-sha256", elf_pin]
            completed = subprocess.run(command, cwd=directory, text=True, capture_output=True)
            controls.append({"case": name, "expected_accept": accepts,
                             "returncode": completed.returncode,
                             "passed": (completed.returncode == 0) == accepts,
                             "stderr": completed.stderr.strip()})
            result = {"schema": 1, "scheme": original["scheme"], "signatures": original["signatures"],
                      "runner_sha256": runner_hash,
                      "source_statement_sha256": hashlib.sha256(args.statement.read_bytes()).hexdigest(),
                      "root_proof_sha256": hashlib.sha256(proof).hexdigest(),
                      "independent_leaf_digest_check": True,
                      "independent_root_digest_check": True,
                      "distinct_public_keys": original["signatures"],
                      "description": "No proving. Every receiver process runs in isolation with public records and one root proof only. Recommitted claim mutations use fresh trusted statement pins.",
                      "passed": all(c["passed"] for c in controls), "controls": controls}
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            if not controls[-1]["passed"]:
                raise AssertionError(controls[-1])
    print(f"{len(controls)} public-only tree controls passed for {original['scheme']} N={original['signatures']}")


if __name__ == "__main__":
    main()
