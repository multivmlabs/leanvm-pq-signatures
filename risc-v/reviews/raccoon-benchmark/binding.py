#!/usr/bin/env python3
"""Independent raw-byte public commitments for the pinned Raccoon study."""
from __future__ import annotations

import hashlib

PROFILES = {
    "raccoon": (2256, b"pqbench/racc1281/compact/v1".ljust(32, b"\0")),
    "raccoon-g": (16144, b"pqbench/raccoong/hd-poc/strictv1"),
}


def digest_leaf(scheme, records):
    key_bytes, domain = PROFILES[scheme]
    assert len(domain) == 32
    assert 1 <= len(records) <= 64
    data = bytearray(domain)
    data += len(records).to_bytes(8, "little")
    for record in records:
        key = bytes.fromhex(record["public_key"])
        message = bytes.fromhex(record["message"])
        assert len(key) == key_bytes and len(message) == 32
        data += key + message
    digest = hashlib.blake2s(data).digest()
    return [int.from_bytes(digest[i:i + 8], "little") for i in range(0, 32, 8)]


def leaf_outputs(statement):
    size = statement["leaf_size"]
    records = statement["public_records"]
    assert size in (1, 2, 5, 10)
    assert len(records) % size == 0
    return [digest_leaf(statement["scheme"], records[i:i + size])
            for i in range(0, len(records), size)]


def validate_statement(statement, *, tree):
    scheme = statement["scheme"]
    assert scheme in PROFILES
    records = statement["public_records"]
    count = len(records)
    if not tree:
        assert statement["schema"] == 1 and statement["count"] == count
        assert digest_leaf(scheme, records) == statement["expected_output"]
        return
    assert statement["schema"] == 1
    assert statement["backend_revision"] == "06e5c9cd6981103786f9d0a17324241b559a50d3"
    assert statement["signatures"] == count
    assert count in (10, 30, 70, 100)
    actual = count // statement["leaf_size"]
    assert actual * statement["leaf_size"] == count
    assert statement["actual_leaves"] == actual
    assert statement["leaf_slots"] == max(2, 1 << (actual - 1).bit_length())
    assert statement["arity_0"] == statement["arity"] == 2
    assert len({bytes.fromhex(r["public_key"]) for r in records}) == count
    assert statement["expected_leaf_outputs"] == leaf_outputs(statement)
    heights = statement["table_rows"]
    assert len(heights) == 11
    assert all(0 < h <= 1 << 28 and h & (h - 1) == 0 for h in heights)


def root_digest(statement):
    actual = [b"".join(w.to_bytes(8, "little") for w in output)
              for output in leaf_outputs(statement)]
    actual += [actual[-1]] * (statement["leaf_slots"] - len(actual))

    def combine(tag, items):
        # The pinned native protocol uses a full 64-byte header block.
        header = tag + len(items).to_bytes(8, "little") + b"\0" * 48
        return hashlib.blake2s(header + b"".join(items)).digest()

    level = [combine(b"tree-fst", actual[i:i + 2]) for i in range(0, len(actual), 2)]
    kind = 0 if len(level) == 1 else 1
    while len(level) > 1:
        level = [combine(b"tree-nod", level[i:i + 2]) for i in range(0, len(level), 2)]
    return kind, level[0]


def check_root_digest(statement, proof):
    """Check the public binding in protocol-19 envelope, not its STARK proof."""
    assert proof[:6] == b"LVMT\x13\0", "foreign tree proof envelope"
    assert proof[6] == statement["log_inverse_rate"]
    n_words = int.from_bytes(proof[7:11], "little")
    assert n_words >= 3 and len(proof) > 11 + n_words * 24
    expected_kind, digest = root_digest(statement)
    assert int.from_bytes(proof[11:35], "little") == expected_kind
    assert proof[51:59] == proof[75:83] == b"\0" * 8
    assert proof[35:51] + proof[59:75] == digest
    return {"protocol": 19, "statement_words": n_words,
            "root_kind": expected_kind, "ordered_root_digest": digest.hex()}
