"""Distinct fixed-message-length ETHFALCON inputs for the recursion experiment.

Keys and signing randomness are publicly reproducible benchmark material. No
private key is serialized. The saved public records can reconstruct every leaf.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
from time import perf_counter

from . import falcon as f

TAG = b"pqbench/ethfalcon-recursion-30/v1"
LEAF_SIZE = 5
LEAVES = 6
MESSAGE_BYTES = 32


def _bytes(seed_kind: bytes, index: int, length: int) -> bytes:
    if index < 0:
        raise ValueError("record index must be nonnegative")
    return hashlib.shake_256(TAG + b"/" + seed_kind + index.to_bytes(8, "little")).digest(length)


def generate_record(index: int) -> dict:
    """Generate a real native ETHFALCON signature, independently check it."""
    library = f._native_c()
    keygen = library.crypto_sign_keypair_from_seed
    keygen.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    keygen.restype = ctypes.c_int
    seed_rng = library.randombytes_init
    seed_rng.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    seed_rng.restype = None
    sign = library.crypto_sign
    sign.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_char_p,
                     ctypes.c_ulonglong, ctypes.c_void_p]
    sign.restype = ctypes.c_int
    message = hashlib.sha256(TAG + b"/message/" + index.to_bytes(8, "little")).digest()
    key_seed = _bytes(b"key", index, 48)
    signing_entropy = ctypes.create_string_buffer(_bytes(b"sign", index, 48))
    seed_rng(signing_entropy, None, 256)
    pk, sk = ctypes.create_string_buffer(897), ctypes.create_string_buffer(1281)
    if keygen(pk, sk, key_seed, len(key_seed)) != 0:
        raise RuntimeError(f"ETHFALCON key generation failed for fixture {index}")
    signed = ctypes.create_string_buffer(2 + 40 + MESSAGE_BYTES + 690)
    size = ctypes.c_ulonglong()
    attempts = 0
    try:
        # The native signer's output buffer can reject an unusually long sample.
        while attempts < 16:
            attempts += 1
            if sign(signed, ctypes.byref(size), message, len(message), sk) == 0:
                break
        else:
            raise RuntimeError(f"ETHFALCON signer exhausted retries for fixture {index}")
        signed_message = signed.raw[:size.value]
    finally:
        ctypes.memset(ctypes.addressof(sk), 0, len(sk))
    record = {"index": index, "message_hex": message.hex(), "public_key_hex": pk.raw.hex(),
              "signed_message_hex": signed_message.hex(), "native_sign_attempts": attempts,
              "provenance": "pinned upstream C ETHFALCON, deterministic public benchmark seeds"}
    decoded_record(record)
    return record


def decoded_record(record: dict) -> tuple[list[int], list[int], bytes, bytes]:
    """Check the complete native codec and the independent signature equation."""
    public_key = bytes.fromhex(record["public_key_hex"])
    message = bytes.fromhex(record["message_hex"])
    signed_message = bytes.fromhex(record["signed_message_hex"])
    if len(message) != MESSAGE_BYTES:
        raise ValueError("recursive experiment messages must have exactly 32 bytes")
    if len(signed_message) < 43 + len(message) or signed_message[42:42 + len(message)] != message:
        raise ValueError("signed message framing does not match the declared message")
    if signed_message[42 + len(message)] != 0x29:
        raise ValueError("expected the Falcon-512 compressed signature header")
    declared_signature_bytes = int.from_bytes(signed_message[:2], "big")
    if len(signed_message) != 42 + len(message) + declared_signature_bytes:
        raise ValueError("incorrect signed message length")
    if f.native_c_verify(signed_message, public_key) != message:
        raise ValueError("upstream C rejected the ETHFALCON record")
    h = f.decode_key(public_key)
    salt = signed_message[2:42]
    s2 = f.decode_signature(signed_message[43 + len(message):])
    if not f.native_verify(h, s2, salt, message):
        raise ValueError("independent ETHFALCON verification rejected the record")
    return h, s2, salt, message


def claim_record(record: dict) -> dict:
    """Derive a public claim from the key/message, without trusting saved hashes."""
    message = bytes.fromhex(record["message_hex"])
    h = f.decode_key(bytes.fromhex(record["public_key_hex"]))
    if len(message) != MESSAGE_BYTES:
        raise ValueError("expected a 32-byte message")
    key_hash = f.digest(b"".join(coefficient.to_bytes(2, "little") for coefficient in h))
    message_hash = f.digest(message)
    claim = f.digest(f.DOMAIN + key_hash + message_hash)
    return {"index": record["index"], "public_key_hex": record["public_key_hex"],
            "message_hex": record["message_hex"], "key_hash": key_hash.hex(),
            "message_hash": message_hash.hex(), "claim_hash": claim.hex()}


def expected_leaf_digest(records: list[dict]) -> bytes:
    if len(records) != LEAF_SIZE:
        raise ValueError("this experiment uses five signatures per leaf")
    accumulator = f.digest(f.DOMAIN + len(records).to_bytes(8, "big"))
    for record in records:
        accumulator = f.digest(accumulator + bytes.fromhex(claim_record(record)["claim_hash"]))
    return accumulator


def build_leaf(records: list[dict]) -> dict:
    if len(records) != LEAF_SIZE:
        raise ValueError("this experiment uses five signatures per leaf")
    witness = f.Witness()
    public_records = []
    started = perf_counter()
    raw_signature_bytes = 0
    messages = []
    for record in records:
        h, s2, salt, message = decoded_record(record)
        witness.signature(h, s2, salt, message)
        messages.append(message)
        public_records.append({**record, **claim_record(record)})
        raw_signature_bytes += len(bytes.fromhex(record["signed_message_hex"])) - MESSAGE_BYTES - 2
    initial = f.digest(f.DOMAIN + LEAF_SIZE.to_bytes(8, "big"))
    return {"scheme": "ethfalcon-512-keccak", "source": f.guest_source(messages, initial),
            "witness": witness.streams, "public_input": f.halves(expected_leaf_digest(records)),
            "metadata": {"count": LEAF_SIZE, "signature_bytes": raw_signature_bytes,
                         "raw_signature_bytes": raw_signature_bytes, "raw_key_bytes": LEAF_SIZE * 897,
                         "public_key_bytes": LEAF_SIZE * 897, "message_bytes": LEAF_SIZE * MESSAGE_BYTES,
                         "parameters": {"degree": f.N, "modulus": f.Q, "norm_bound": f.BOUND,
                                        "message_lengths": [MESSAGE_BYTES] * LEAF_SIZE},
                         "fixture_generation_s": perf_counter() - started,
                         "records": public_records,
                         "encoding": "canonical expanded uint16 key commitment and expanded signature witness",
                         "benchmark_note": "Publicly reproducible test keys and randomness; do not use for funds."}}


def generate_experiment(directory: Path, records: list[dict] | None = None) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    leaf_directory = directory / "leaves"
    leaf_directory.mkdir(exist_ok=True)
    if records is None:
        records = [generate_record(index) for index in range(LEAVES * LEAF_SIZE)]
    if len(records) != LEAVES * LEAF_SIZE:
        raise ValueError("expected exactly thirty signatures")
    identities = {(record["public_key_hex"], record["message_hex"]) for record in records}
    if len(identities) != LEAVES * LEAF_SIZE or len({record["public_key_hex"] for record in records}) != 30:
        raise ValueError("the experiment requires thirty distinct keys and claims")
    leaves = []
    source = None
    for index in range(LEAVES):
        group = records[index * LEAF_SIZE:(index + 1) * LEAF_SIZE]
        fixture = build_leaf(group)
        if source is not None and fixture["source"] != source:
            raise AssertionError("leaf program source depends on signature contents")
        source = fixture["source"]
        path = leaf_directory / f"leaf-{index}.json"
        path.write_text(json.dumps(fixture) + "\n")
        leaves.append({"leaf": index, "signature_count": LEAF_SIZE,
                       "input_file": str(path.relative_to(directory)), "public_input_hex": expected_leaf_digest(group).hex(),
                       "claims": [claim_record(record) for record in group]})
        print(path, flush=True)
    manifest = {"schema_version": 1, "experiment": "ethfalcon-30-recursive", "scheme": "ethfalcon-512-keccak",
                "signatures": 30, "leaves": leaves, "signatures_per_leaf": LEAF_SIZE, "leaf_size": LEAF_SIZE,
                "records": [claim_record(record) for record in records],
                "message_bytes": MESSAGE_BYTES, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "claim_order": "leaf order, then signature order within each leaf",
                "claim_encoding": "initial H(domain16||BE64(5)); fold H(acc32||H(domain16||keyhash32||H(message)))",
                "key_hash_encoding": "Keccak256(LE16(h0)||...||LE16(h511))",
                "benchmark_note": "All deterministic fixture private keys are publicly reproducible and unsuitable for funds."}
    (directory / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (directory / "public.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (directory / "leaf-program.py").write_text(source)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="artifacts/falcon-30-recursive")
    parser.add_argument("--records", help="replay saved public records instead of generating signatures")
    args = parser.parse_args()
    records = json.loads(Path(args.records).read_text()) if args.records else None
    manifest = generate_experiment(Path(args.out), records)
    print(json.dumps({key: manifest[key] for key in ("signatures", "signatures_per_leaf", "source_sha256")}))


if __name__ == "__main__":
    main()
