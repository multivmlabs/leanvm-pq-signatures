#!/usr/bin/env python3
"""Separate the official internal-interface ACVP controls from the pure guest profile."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from pqbench import mldsa


def main():
    fixture_path = ROOT / "risc-v/mldsa/fixture-0.json"
    item = json.loads(fixture_path.read_text())
    pk = bytes.fromhex(item["compact_public_key_hex"])
    msg = bytes.fromhex(item["message_hex"])
    sig = bytes.fromhex(item["compact_signature_hex"])
    pure = []
    cases = [("honest", pk, msg, sig, False, True),
             ("changed_message", pk, bytes([msg[0] ^ 1]) + msg[1:], sig, False, False),
             ("changed_key", bytes([pk[0] ^ 1]) + pk[1:], msg, sig, False, False),
             ("changed_challenge", pk, msg, bytes([sig[0] ^ 1]) + sig[1:], False, False),
             ("pure_matches_internal_prefixed_message", pk, b"\0\0" + msg, sig, True, True),
             ("pure_is_not_unprefixed_internal", pk, msg, sig, True, False)]
    for name, key, message, signature, internal, expected in cases:
        native = mldsa.native_accepts(key, message, signature, internal=internal)
        python = mldsa.verify_python(key, message, signature, internal=internal)
        pure.append({"name": name, "native": native, "python": python,
                     "expected": expected, "passed": native == python == expected})
    acvp_path = ROOT / "vendor/ETHDILITHIUM/pythonref/assets/ML-DSA-sigVer-FIPS204/internalProjection.json"
    vectors = json.loads(acvp_path.read_text())
    acvp = []
    for group in vectors["testGroups"]:
        if group["parameterSet"] != "ML-DSA-44":
            continue
        for test in group["tests"]:
            key = bytes.fromhex(group["pk"])
            message = bytes.fromhex(test["message"])
            signature = bytes.fromhex(test["signature"])
            native = mldsa.native_accepts(key, message, signature, internal=True)
            python = mldsa.verify_python(key, message, signature, internal=True)
            acvp.append({"tcId": test["tcId"], "reason": test["reason"],
                         "expected": test["testPassed"], "native": native, "python": python,
                         "passed": native == python == test["testPassed"]})
    report = {"scope": "Native C and independent Python checks, not direct ACVP execution under the fixed-32-byte pure guest",
              "fixture_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
              "acvp_internal_projection_sha256": hashlib.sha256(acvp_path.read_bytes()).hexdigest(),
              "pure_profile_controls": pure, "acvp_internal_controls": acvp}
    (ROOT / "risc-v/reviews/mldsa-oracles.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pure_profile": f"{sum(r['passed'] for r in pure)}/{len(pure)}",
                      "acvp_internal": f"{sum(r['passed'] for r in acvp)}/{len(acvp)}"}))
    if not all(r["passed"] for r in pure + acvp):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
