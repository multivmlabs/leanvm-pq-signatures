#!/usr/bin/env python3
"""Independent fixed-byte commitments for the five-part Raccoon-G receipt.

This contains no signature implementation or leanVM SDK. Hashes use hashlib;
the original independently saved Python commitment W supplies correctness vectors.
The root digest check authenticates the public claim header only, not its STARK.
"""
from __future__ import annotations

import hashlib
import struct

PARTS = ((0, 1), (2, 3), (4, 5), (6, 7), (8, 8))
PUBLIC_DOMAIN = b"pqbench/rcg-two/strictv1/d512/v1"
WITNESS_DOMAINS = [b"pqbench/rcg-wit/strictv1/hash0v1",
                   b"pqbench/rcg-wit/strictv1/hash1v1"]


def words(raw):
    assert len(raw) % 8 == 0
    return list(struct.unpack("<" + "Q" * (len(raw) // 8), raw))


def packed_words(value):
    return struct.pack("<" + "Q" * len(value), *value)


def witness_binding(signature, encoded_w):
    assert len(signature) == 20768 and len(encoded_w) == 4608
    assert all(c[0] < 2048 for c in struct.iter_unpack("<H", encoded_w))
    prefix = struct.pack("<QQ", len(signature), len(encoded_w))
    assert all(len(domain) == 32 for domain in WITNESS_DOMAINS)
    return b"".join(hashlib.blake2s(domain + prefix + signature + encoded_w).digest()
                    for domain in WITNESS_DOMAINS)


def part_output(record, part, binding):
    pk, message = bytes.fromhex(record["public_key"]), bytes.fromhex(record["message"])
    assert len(pk) == 16144 and len(message) == 32 and len(binding) == 64
    assert 0 <= part < 5 and len(PUBLIC_DOMAIN) == 32
    preimage = PUBLIC_DOMAIN + struct.pack("<QQQ", part, *PARTS[part]) + pk + message + binding
    return hashlib.blake2s(preimage).digest()


def validate_statement(s):
    # Strictly independent enumeration. D and expected outputs must never appear
    # in this caller-authorized statement.
    assert set(s) == {"schema", "backend_revision", "scheme", "profile", "signatures",
                      "elf_sha256", "parts_per_signature", "rows_per_leaf", "rows_per_signature",
                      "actual_leaves", "leaf_slots", "arity_0", "arity", "log_inverse_rate",
                      "table_rows", "public_records"}
    assert s["schema"] == 1 and s["scheme"] == "raccoon-g"
    assert s["backend_revision"] == "06e5c9cd6981103786f9d0a17324241b559a50d3"
    assert s["profile"] == "raccoong-hd-authors-poc-strict-segmented-v1"
    n = s["signatures"]
    assert n in (1, 2, 10, 30, 70, 100) and len(s["public_records"]) == n
    assert (s["parts_per_signature"], s["rows_per_leaf"], s["rows_per_signature"]) == (5, 2, 9)
    assert s["actual_leaves"] == 5 * n
    assert s["leaf_slots"] == max(2, 1 << (5 * n - 1).bit_length())
    assert s["arity_0"] == s["arity"] == 2 and s["log_inverse_rate"] == 1
    assert len(s["table_rows"]) == 11
    assert all(0 < h <= 1 << 28 and h & (h - 1) == 0 for h in s["table_rows"])
    keys = set()
    for record in s["public_records"]:
        assert set(record) == {"public_key", "message"}
        key, msg = bytes.fromhex(record["public_key"]), bytes.fromhex(record["message"])
        assert len(key) == 16144 and len(msg) == 32
        keys.add(key)
    assert len(keys) == n


def decode_receipt(s, receipt):
    validate_statement(s)
    n = s["signatures"]
    assert len(receipt) <= 16 * 1024 * 1024 and receipt[:8] == b"RGSTK001"
    assert struct.unpack_from("<III", receipt, 8) == (n, 5, s["leaf_slots"])
    assert receipt[20:52].hex() == s["elf_sha256"]
    bindings = [receipt[52 + 64 * i:52 + 64 * (i + 1)] for i in range(n)]
    at = 52 + 64 * n
    length, = struct.unpack_from("<Q", receipt, at)
    core = receipt[at + 8:]
    assert len(core) == length and len(receipt) - len(core) == 60 + 64 * n
    return bindings, core


def root_digest(s, bindings):
    outputs = [part_output(record, part, binding)
               for record, binding in zip(s["public_records"], bindings)
               for part in range(5)]
    actual = len(outputs)
    outputs.extend([outputs[-1]] * (s["leaf_slots"] - actual))

    def combine(tag, children):
        return hashlib.blake2s(tag + struct.pack("<Q", len(children)) + bytes(48)
                               + b"".join(children)).digest()

    level = [combine(b"tree-fst", outputs[i:i + 2]) for i in range(0, len(outputs), 2)]
    kind = int(len(level) > 1)
    while len(level) > 1:
        level = [combine(b"tree-nod", level[i:i + 2]) for i in range(0, len(level), 2)]
    return kind, level[0]


def check_receipt_binding(s, receipt):
    bindings, core = decode_receipt(s, receipt)
    actual = s["signatures"] * 5
    kind, digest = root_digest(s, bindings)
    assert core[:6] == b"LVMT\x13\0" and core[6] == 1
    statement_words, = struct.unpack_from("<I", core, 7)
    assert statement_words >= 3 and len(core) > 11 + statement_words * 24
    assert int.from_bytes(core[11:35], "little") == kind
    assert core[51:59] == core[75:83] == bytes(8)
    assert core[35:51] + core[59:75] == digest
    return {"protocol": 19, "original_signatures": s["signatures"],
            "actual_parts": actual, "unique_rows": 9 * s["signatures"],
            "row_computations": 10 * s["signatures"],
            "leaf_slots": s["leaf_slots"], "padding_slots": s["leaf_slots"] - actual,
            "root_digest": digest.hex(), "root_kind": kind,
            "core_bytes": len(core), "receipt_bytes": len(receipt),
            "overhead_bytes": 60 + 64 * s["signatures"]}
