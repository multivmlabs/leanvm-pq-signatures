#!/usr/bin/env python3
"""Independent review controls against arbitrary advice and the unchanged guest ELF.

This runs the interpreter, not a STARK prover. Expected outputs are computed with
Python's BLAKE2s, independently of the SDK output builder.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / ".cache/riscv-host-target/release/mldsa-twiddle64-probe"
FIXTURE = ROOT / "risc-v/mldsa/fixture-0.json"
DOMAIN = b"pqbench/mldsa44/compact/v1".ljust(32, b"\0")


def main():
    embedded = subprocess.check_output([str(HARNESS), "--dump-elf"])
    assert embedded == (ROOT / "risc-v/experiments/mldsa-poly64/twiddle64.elf").read_bytes(), "rebuild review harness after changing the guest ELF"
    item = json.loads(FIXTURE.read_text())
    pk = bytes.fromhex(item["compact_public_key_hex"])
    msg = bytes.fromhex(item["message_hex"])
    sig = bytes.fromhex(item["compact_signature_hex"])
    record = pk + msg + sig + bytes(4)
    assert len(record) == 471 * 8
    cases = []

    def case(name, advice, accepts, public=None):
        cases.append((name, advice, accepts, public))

    def alter(name, at, xor=1):
        changed = bytearray(record)
        changed[at] ^= xor
        case(name, struct.pack("<Q", 1) + changed, False)

    case("honest_one", struct.pack("<Q", 1) + record, True, [pk + msg])
    case("honest_two_same_claim", struct.pack("<Q", 2) + record * 2, True, [pk + msg] * 2)
    # Extra advice has no application meaning under the documented fixed-count relation.
    case("unused_advice", struct.pack("<Q", 1) + record + b"unused!!", True, [pk + msg])
    alter("changed_rho", 0)
    alter("changed_t1", 1311)
    alter("changed_message", 1312)
    alter("changed_challenge", 1344)
    alter("nonzero_signature_transport_padding", len(record) - 1)
    bad = bytearray(sig)
    bad[-1] = 81
    case("hint_count_above_omega", struct.pack("<Q", 1) + pk + msg + bad + bytes(4), False)
    bad = bytearray(sig)
    bad[-84:] = bytes(84)
    bad[-84] = bad[-83] = 7
    bad[-4:] = bytes([2, 2, 2, 2])
    case("duplicate_hint_indices", struct.pack("<Q", 1) + pk + msg + bad + bytes(4), False)
    bad = bytearray(sig)
    bad[-84:] = bytes(84)
    bad[-84] = 7
    case("nonzero_unused_hint_index", struct.pack("<Q", 1) + pk + msg + bad + bytes(4), False)
    bad = bytearray(sig)
    bad[-84:] = bytes(84)
    bad[-4:] = bytes([1, 0, 0, 0])
    case("decreasing_hint_boundaries", struct.pack("<Q", 1) + pk + msg + bad + bytes(4), False)
    bad = bytearray(sig)
    bad[32], bad[33], bad[34] = 78, 0, bad[34] & 0xFC
    case("z_exact_rejection_bound", struct.pack("<Q", 1) + pk + msg + bad + bytes(4), False)
    case("zero_count", struct.pack("<Q", 0) + record, False)
    case("count_above_guest_limit", struct.pack("<Q", 257) + record, False)
    case("missing_second_record", struct.pack("<Q", 2) + record, False)
    results = []
    with tempfile.TemporaryDirectory() as directory:
        for name, advice, accepts, public in cases:
            path = Path(directory) / (name + ".advice")
            path.write_bytes(advice)
            done = subprocess.run([str(HARNESS), str(path)], text=True, capture_output=True)
            expected = None
            if public is not None:
                digest = hashlib.blake2s(DOMAIN + struct.pack("<Q", len(public)) + b"".join(public)).digest()
                expected = "".join(f"{word:016x}" for word in struct.unpack("<4Q", digest))
            success = (done.returncode == 0) == accepts
            if accepts:
                success = success and done.stdout.strip() == expected
            results.append({"name": name, "advice_sha256": hashlib.sha256(advice).hexdigest(),
                            "expected_accepts": accepts, "exit_code": done.returncode,
                            "expected_output_words_hex": expected, "stdout": done.stdout.strip(),
                            "stderr": done.stderr.strip(), "passed": success})
    report = {"scope": "RISC-V interpreter controls, no STARK proof generated",
              "elf_sha256": hashlib.sha256((ROOT / "risc-v/experiments/mldsa-poly64/twiddle64.elf").read_bytes()).hexdigest(),
              "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
              "harness_sha256": hashlib.sha256(HARNESS.read_bytes()).hexdigest(),
              "controls": results}
    out = ROOT / "risc-v/experiments/mldsa-poly64/vm-controls.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": sum(r["passed"] for r in results), "total": len(results),
                      "elf_sha256": report["elf_sha256"]}))
    if not all(r["passed"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
