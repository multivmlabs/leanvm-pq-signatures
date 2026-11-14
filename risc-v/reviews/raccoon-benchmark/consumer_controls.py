#!/usr/bin/env python3
"""Public-only controls on a saved proof, using the unchanged native consumer.

No proof or VM workload is produced. Run between timed prover jobs, because the
native tree setup and verification still consume CPU. Statement mutations are
recommitted independently and receive fresh pins from this test caller.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from binding import check_root_digest, digest_leaf, leaf_outputs, validate_statement


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("direct", "tree"), required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--statement", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--expect-elf-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = args.runner.resolve()
    runner_hash = sha(runner.read_bytes())
    original_raw = args.statement.read_bytes()
    original = json.loads(original_raw)
    proof = args.proof.read_bytes()
    tree = args.kind == "tree"
    validate_statement(original, tree=tree)
    assert original["elf_sha256"] == args.expect_elf_sha256
    root_binding = check_root_digest(original, proof) if tree else None
    cases = [("honest", original, proof, True, args.expect_elf_sha256, None)]

    def add_statement(name, changed, *, recommit=False):
        if recommit:
            if tree:
                changed["expected_leaf_outputs"] = leaf_outputs(changed)
            else:
                changed["expected_output"] = digest_leaf(changed["scheme"], changed["public_records"])
        cases.append((name, changed, proof, False, args.expect_elf_sha256, None))

    for field, byte_index in (("public_key", 0), ("message", -1)):
        # The final record matters as much as the first, including when a tree
        # ends in explicit repeated padding slots.
        for record_index in sorted({0, len(original["public_records"]) - 1}):
            changed = copy.deepcopy(original)
            value = bytearray.fromhex(changed["public_records"][record_index][field])
            value[byte_index] ^= 1
            changed["public_records"][record_index][field] = value.hex()
            add_statement(f"changed-{field}-record-{record_index}-recommitted", changed, recommit=True)
    if len(original["public_records"]) >= 2:
        changed = copy.deepcopy(original)
        changed["public_records"][0], changed["public_records"][1] = changed["public_records"][1], changed["public_records"][0]
        add_statement("reordered-records-recommitted", changed, recommit=True)
        changed = copy.deepcopy(original)
        changed["public_records"][1] = copy.deepcopy(changed["public_records"][0])
        add_statement("duplicated-record-recommitted", changed, recommit=True)
    if original["scheme"] == "raccoon-g":
        changed = copy.deepcopy(original)
        pk = bytearray.fromhex(changed["public_records"][-1]["public_key"])
        offset = len(pk) - 7
        value = int.from_bytes(pk[offset:], "little")
        q = 562949953438721
        rounded = lambda x: ((x + 2**34) >> 35) % 16384
        neighbour = next(x for x in (value - 1, value + 1)
                         if 0 <= x < q and rounded(x) == rounded(value))
        pk[offset:] = neighbour.to_bytes(7, "little")
        changed["public_records"][-1]["public_key"] = pk.hex()
        add_statement("full-unrounded-key-low-bit-recommitted", changed, recommit=True)
    changed = copy.deepcopy(original)
    changed["signatures" if tree else "count"] += 1
    add_statement("wrong-signature-count", changed)
    changed = copy.deepcopy(original)
    if tree:
        changed["expected_leaf_outputs"][0][0] ^= 1
    else:
        changed["expected_output"][0] ^= 1
    add_statement("wrong-cached-public-output", changed)
    changed = copy.deepcopy(original)
    changed["elf_sha256"] = "00" * 32
    add_statement("wrong-statement-elf", changed)
    changed = copy.deepcopy(original)
    changed["schema"] += 1
    add_statement("wrong-statement-schema", changed)
    changed = copy.deepcopy(original)
    changed["unrecognized"] = True
    add_statement("unknown-statement-field", changed)
    changed = copy.deepcopy(original)
    changed["scheme"] = "raccoon-g" if original["scheme"] == "raccoon" else "raccoon"
    add_statement("wrong-signature-profile", changed)
    if tree:
        if original["actual_leaves"] >= 2:
            changed = copy.deepcopy(original)
            size = changed["leaf_size"]
            changed["public_records"][:2 * size] = changed["public_records"][size:2 * size] + changed["public_records"][:size]
            add_statement("reordered-leaves-recommitted", changed, recommit=True)
        for field, value in (("leaf_slots", original["leaf_slots"] * 2),
                             ("arity", 4), ("arity_0", 1),
                             ("backend_revision", "00" * 20), ("log_inverse_rate", 2)):
            changed = copy.deepcopy(original)
            changed[field] = value
            add_statement("wrong-" + field, changed)
        for name, value in (("zero-height", 0), ("non-power-two-height", 3), ("too-large-height", 1 << 29)):
            changed = copy.deepcopy(original)
            changed["table_rows"][0] = value
            add_statement(name, changed)
        changed = copy.deepcopy(original)
        changed["table_rows"].pop()
        add_statement("missing-table-height", changed)
    cases += [("wrong-trusted-elf", original, proof, False, "00" * 32, None),
              ("wrong-trusted-statement", original, proof, False, args.expect_elf_sha256, "00" * 32)]
    for name, index in (("corrupt-magic", 0), ("corrupt-version", 4),
                        ("corrupt-proof-middle", len(proof) // 2)):
        changed_proof = bytearray(proof)
        changed_proof[index] ^= 1
        cases.append((name, original, changed_proof, False, args.expect_elf_sha256, None))
    cases += [("truncated-root", original, proof[:-1], False, args.expect_elf_sha256, None),
              ("trailing-root-byte", original, proof + b"\0", False, args.expect_elf_sha256, None)]
    controls = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, statement, received_root, accepts, elf_pin, statement_pin in cases:
        assert sha(runner.read_bytes()) == runner_hash, "consumer binary changed during controls"
        with tempfile.TemporaryDirectory(prefix="raccoon-public-receiver-") as folder:
            directory = Path(folder)
            public = directory / "statement.json"
            received = directory / "root.proof"
            public.write_text(json.dumps(statement))
            received.write_bytes(received_root)
            command = [str(runner), "verify", "--scheme", original["scheme"],
                       "--statement", str(public), "--proof", str(received),
                       "--expect-statement-sha256", statement_pin or sha(public.read_bytes()),
                       "--expect-elf-sha256", elf_pin, "--threads", "8", "--rate", "1"]
            command += ["--outdir", str(directory / "receiver")] if tree else ["--out", str(directory / "verification.json"), "--repeat", "1", "--warmup", "0"]
            completed = subprocess.run(command, cwd=directory, text=True, capture_output=True, timeout=60)
            controls.append({"case": name, "expected_accept": accepts,
                             "returncode": completed.returncode,
                             "passed": (completed.returncode == 0) == accepts,
                             "stderr": completed.stderr.strip(),
                             "statement_sha256": sha(public.read_bytes()),
                             "proof_sha256": sha(received_root)})
        result = {"schema": 1, "kind": args.kind, "scheme": original["scheme"],
                  "signatures": len(original["public_records"]), "runner_sha256": runner_hash,
                  "source_statement_sha256": sha(original_raw), "root_proof_sha256": sha(proof),
                  "approved_elf_sha256": args.expect_elf_sha256,
                  "independent_leaf_digest_check": True,
                  "independent_root_binding": root_binding,
                  "description": "No proving. Every native receiver starts in isolation with only intended public records and one root. Recommitted mutations receive fresh caller pins.",
                  "passed": all(c["passed"] for c in controls), "controls": controls}
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        if not controls[-1]["passed"]:
            raise AssertionError(controls[-1])
    print(f"{len(controls)} controls passed for {original['scheme']} {args.kind}")


if __name__ == "__main__":
    main()
