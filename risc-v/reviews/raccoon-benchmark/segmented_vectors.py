#!/usr/bin/env python3
"""Make raw-advice controls from previous independent Python W and record bytes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

from segmented_binding import part_output, witness_binding

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / "segmented-elf-vectors"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-corpus-index3", action="store_true",
                        help="Independently reconstruct W from the existing original corpus record3")
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    raw = (ROOT / "risc-v/raccoon-g/review/independent-vectors/first-one.bin").read_bytes()
    oracle = json.loads((ROOT / "risc-v/raccoon-g/review/oracle-record-0.json").read_text())
    pk, msg, sig = raw[:16144], raw[16144:16176], raw[16176:]
    w = b"".join(struct.pack("<H", c) for row in oracle["intermediate"]["w"] for c in row)
    assert hashlib.sha256(pk).hexdigest() == oracle["public_key_sha256"]
    assert hashlib.sha256(sig).hexdigest() == oracle["signature_sha256"]
    cases = {}

    def save(name, part, *, signature=sig, encoded_w=w, key=pk, message=msg, accepts=False):
        data = struct.pack("<Q", part) + key + message + signature + encoded_w
        expected = None
        if accepts:
            d = witness_binding(signature, encoded_w)
            expected = part_output({"public_key": key.hex(), "message": message.hex()}, part, d).hex()
        (OUT / (name + ".bin")).write_bytes(data)
        cases[name + ".bin"] = {"accepted": accepts, "expected_output": expected,
                                "advice_sha256": hashlib.sha256(data).hexdigest()}

    for part in range(5):
        save(f"honest-part-{part}", part, accepts=True)
    for part, row in enumerate((1, 3, 5, 7)):
        changed = bytearray(sig)
        at = 32 + 9 * 256 * 7 + 2 * (row * 256 + 255)
        hint, = struct.unpack_from("<H", changed, at)
        struct.pack_into("<H", changed, at, hint - 1 if hint else 1)
        save(f"second-row-{row}-hint-part-{part}", part, signature=changed)
    changed = bytearray(sig)
    at = 32 + 9 * 256 * 7 + 2 * (8 * 256 + 255)
    hint, = struct.unpack_from("<H", changed, at)
    struct.pack_into("<H", changed, at, hint - 1 if hint else 1)
    save("unselected-row8-hint-part0-partial-accept", 0, signature=changed, accepts=True)
    save("selected-row8-hint-part4-reject", 4, signature=changed)
    bad_w = bytearray(w)
    struct.pack_into("<H", bad_w, len(w) - 2, 2048)
    save("unselected-last-w-noncanonical", 0, encoded_w=bad_w)
    changed = bytearray(pk)
    changed[-7] ^= 1
    save("full-unrounded-key-low-bit", 0, key=changed)
    save("part-index5", 5)
    if args.include_corpus_index3:
        generator = ROOT / "risc-v/raccoon-g/generate_fixtures.py"
        spec = importlib.util.spec_from_file_location("raccoong_audit_fixtures", generator)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        module.check_source()
        source = ROOT / ".cache/raccoong-fixtures/record-3.json"
        record = json.loads(source.read_text())
        key, message, signature = [bytes.fromhex(record[k]) for k in ("public_key", "message", "signature")]
        intermediate = module.reconstruct(key, message, signature)
        assert intermediate["challenge_matches"] and intermediate["integer_norm_accepts"]
        encoded = b"".join(struct.pack("<H", c) for row in intermediate["w"] for c in row)
        save("original-corpus-index3-part4-high-SD", 4, key=key, message=message,
             signature=signature, encoded_w=encoded, accepts=True)
        cases["original-corpus-index3-part4-high-SD.bin"].update(
            source_record_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            independent_python_w=True)
    result = {"schema": 1, "source": "Previous independent original Python oracle W and bytes",
              "binding": witness_binding(sig, w).hex(), "vectors": cases,
              "oracle_sha256": hashlib.sha256(json.dumps(oracle, sort_keys=True).encode()).hexdigest()}
    (OUT / "expectations.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {len(cases)} independent raw-advice controls")


if __name__ == "__main__":
    main()
