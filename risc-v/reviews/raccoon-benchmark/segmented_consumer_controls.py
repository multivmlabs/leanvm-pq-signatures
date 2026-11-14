#!/usr/bin/env python3
"""Independent public-only complete Raccoon-G receipt controls. Never proves."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from segmented_binding import check_receipt_binding, decode_receipt, root_digest


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("runner", "statement", "proof", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expect-elf-sha256", required=True)
    args = parser.parse_args()
    runner = args.runner.resolve()
    runner_sha = sha(runner.read_bytes())
    statement_raw, proof = args.statement.read_bytes(), args.proof.read_bytes()
    original = json.loads(statement_raw)
    assert original["elf_sha256"] == args.expect_elf_sha256
    root_check = check_receipt_binding(original, proof)
    n = original["signatures"]
    cases = [("honest-isolated-full-receiver", original, proof, True, None, None, True)]

    def case(name, *, statement=None, receipt=None, elf_pin=None, statement_pin=None):
        cases.append((name, statement or original, proof if receipt is None else receipt,
                      False, elf_pin, statement_pin, False))

    def recommit(receipt, statement):
        # Mutate the public claim header coherently. Full cryptographic checking
        # must still reject, rather than relying only on stale digest mismatch.
        bindings, core = decode_receipt(statement, receipt)
        kind, digest = root_digest(statement, bindings)
        assert int.from_bytes(core[11:35], "little") == kind
        changed = bytearray(receipt)
        offset = 60 + 64 * n
        changed[offset + 35:offset + 51] = digest[:16]
        changed[offset + 59:offset + 75] = digest[16:]
        check_receipt_binding(statement, changed)
        return changed

    for record_index in sorted({0, n - 1}):
        for field in ("public_key", "message"):
            changed = copy.deepcopy(original)
            value = bytearray.fromhex(changed["public_records"][record_index][field])
            value[-1] ^= 1
            changed["public_records"][record_index][field] = value.hex()
            case(f"changed-{field}-{record_index}-fresh-caller-pin", statement=changed)
            case(f"changed-{field}-{record_index}-fresh-pin-recommitted-root-header",
                 statement=changed, receipt=recommit(proof, changed))
        # Every 64-bit binding limb, including both domain-separated hashes.
        for word in range(8):
            changed = bytearray(proof)
            changed[52 + 64 * record_index + word * 8] ^= 1
            case(f"changed-untrusted-D-{record_index}-word-{word}", receipt=changed)
        changed = bytearray(proof)
        changed[52 + 64 * record_index + 63] ^= 1
        case(f"changed-untrusted-D-{record_index}-recommitted-root-header",
             receipt=recommit(changed, original))
    if n >= 2:
        changed = copy.deepcopy(original)
        changed["public_records"][0], changed["public_records"][-1] = changed["public_records"][-1], changed["public_records"][0]
        case("reordered-original-pairs-fresh-pin", statement=changed)
        changed = copy.deepcopy(original)
        changed["public_records"][-1] = copy.deepcopy(changed["public_records"][0])
        case("duplicated-original-key-fresh-pin", statement=changed)
        changed = bytearray(proof)
        changed[52:116], changed[52 + 64 * (n - 1):52 + 64 * n] = changed[52 + 64 * (n - 1):52 + 64 * n], changed[52:116]
        case("swapped-untrusted-witness-bindings", receipt=changed)
    for field, value in (("schema", 2), ("scheme", "raccoon"),
                         ("profile", "raccoong-hd-authors-poc-strict-v1"),
                         ("parts_per_signature", 4), ("rows_per_leaf", 1),
                         ("rows_per_signature", 8), ("signatures", n + 1),
                         ("actual_leaves", original["actual_leaves"] - 1),
                         ("leaf_slots", original["leaf_slots"] * 2), ("arity_0", 1),
                         ("arity", 4), ("log_inverse_rate", 2),
                         ("backend_revision", "00" * 20), ("elf_sha256", "00" * 32)):
        changed = copy.deepcopy(original)
        changed[field] = value
        case("wrong-" + field + "-fresh-pin", statement=changed)
    for field in ("bindings", "expected_leaf_outputs", "sender_part_order"):
        changed = copy.deepcopy(original)
        changed[field] = []
        case("reject-sender-controlled-statement-" + field, statement=changed)
    for name, height in (("zero", 0), ("non-power-two", 3), ("above-cap", 1 << 29)):
        changed = copy.deepcopy(original)
        changed["table_rows"][0] = height
        case("invalid-" + name + "-table-height", statement=changed)
    changed = copy.deepcopy(original)
    changed["table_rows"].pop()
    case("missing-table-height", statement=changed)
    for offset in (0, 8, 12, 16, 20, 52 + 64 * n):
        changed = bytearray(proof)
        changed[offset] ^= 1
        case(f"receipt-codec-byte-{offset}", receipt=changed)
    core_offset = 60 + 64 * n
    changed = bytearray(proof)
    changed[core_offset + (len(proof) - core_offset) // 2] ^= 1
    case("corrupted-inner-STARK-with-valid-outer-framing", receipt=changed)
    case("truncated-receipt", receipt=proof[:-1])
    case("trailing-receipt-byte", receipt=proof + b"\0")
    case("wrong-independent-ELF-pin", elf_pin="00" * 32)
    case("wrong-independent-statement-pin", statement_pin="00" * 32)

    results = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, statement, receipt, accepts, elf_pin, statement_pin, builtin in cases:
        assert sha(runner.read_bytes()) == runner_sha, "native consumer changed during controls"
        with tempfile.TemporaryDirectory(prefix="raccoong-public-only-") as folder:
            directory = Path(folder)
            (directory / "statement.json").write_text(json.dumps(statement))
            (directory / "root.proof").write_bytes(receipt)
            command = [str(runner), "verify", "--statement", str(directory / "statement.json"),
                       "--proof", str(directory / "root.proof"),
                       "--expect-statement-sha256", statement_pin or sha((directory / "statement.json").read_bytes()),
                       "--expect-elf-sha256", elf_pin or args.expect_elf_sha256,
                       "--threads", "8", "--rate", "1", "--outdir", str(directory / "receiver"),
                       "--controls", "true" if builtin else "false"]
            done = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=60)
            result = {"case": name, "expected_accept": accepts,
                      "returncode": done.returncode, "passed": (done.returncode == 0) == accepts,
                      "statement_sha256": sha((directory / "statement.json").read_bytes()),
                      "receipt_sha256": sha(receipt), "stderr": done.stderr.strip()}
            if accepts:
                verified = json.loads((directory / "receiver/verification.json").read_text())
                result["builtin_coverage_controls"] = verified["controls"]
                assert all(verified["controls"].values())
                assert verified["verified"] and verified["all_folded_claims_settled"]
            results.append(result)
        report = {"schema": 1, "scheme": "raccoon-g", "layout": "five linked two-row parts",
                  "signatures": n, "runner_sha256": runner_sha,
                  "approved_elf_sha256": args.expect_elf_sha256,
                  "source_statement_sha256": sha(statement_raw), "receipt_sha256": sha(proof),
                  "independent_raw_byte_root_binding": root_check,
                  "scope": "Public-only native receiver in isolated directory. No proof, witnesses, VM capacity or child files generated. Changed original claims receive fresh caller pins; coherent root-header recommit controls require cryptographic rejection.",
                  "passed": all(r["passed"] for r in results), "controls": results}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        assert results[-1]["passed"], results[-1]
    print(f"{len(results)} independent segmented receipt controls passed")


if __name__ == "__main__":
    main()
