#!/usr/bin/env python3
"""Independent small-field-table oracle for the leanISA reduction transcript.

This is a reference protocol checker, not a STARK verifier. It independently
implements the pinned binary fields using Python polynomial arithmetic.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path

from Crypto.Hash import keccak

MASK = (1 << 64) - 1
INSTANCE_DOMAIN = 1003201680331580587326919884501360
ROUND_DOMAIN = 256819625207113016318433485441036656


def k_mul(a, b):
    product = 0
    while b:
        if b & 1:
            product ^= a
        a <<= 1
        b >>= 1
    while product.bit_length() > 64:
        product ^= ((1 << 64) | 0x1B) << (product.bit_length() - 65)
    return product


def limbs(value):
    return [(value >> (64 * i)) & MASK for i in range(3)]


def e_mul(a, b):
    aa, bb = limbs(a), limbs(b)
    p = [0] * 5
    for i in range(3):
        for j in range(3):
            p[i + j] ^= k_mul(aa[i], bb[j])
    # y^3 = y + 1; y^4 = y^2 + y.
    return (p[0] ^ p[3]) | ((p[1] ^ p[3] ^ p[4]) << 64) | ((p[2] ^ p[4]) << 128)


def eq(a, b):
    assert len(a) == len(b)
    value = 1
    for x, y in zip(a, b):
        value = e_mul(value, 1 ^ x ^ y)
    return value


def fold(table, challenge):
    return [a ^ e_mul(challenge, a ^ b) for a, b in zip(table[::2], table[1::2])]


def evaluate(table, point):
    assert len(table) == 1 << len(point)
    table = list(table)
    for challenge in point:
        table = fold(table, challenge)
    return table[0]


def hash256(data):
    return keccak.new(digest_bits=256, data=data).digest()


def instance(poly_id, context, points, values):
    assert len(poly_id) == len(context) == 32 and points
    n, m = len(points[0]), len(points)
    assert n > 0 and len(values) == m and all(len(p) == n for p in points)
    words = [x for p, value in zip(points, values) for x in [*p, value]]
    if len(words) & 1:
        words.append(0)
    prefix = b"".join(x.to_bytes(16, "little") for x in [INSTANCE_DOMAIN, n, m])
    return hash256(prefix + poly_id + context + b"".join(x.to_bytes(24, "little") for x in words))


def step(state, c0, c2, index):
    return hash256(ROUND_DOMAIN.to_bytes(16, "little") + index.to_bytes(16, "little")
                   + state + c0.to_bytes(24, "little") + c2.to_bytes(24, "little"))


def prove(table, points, poly_id, context):
    values = [evaluate(table, p) for p in points]
    state = instance(poly_id, context, points, values)
    initial_digest = state
    theta = int.from_bytes(state[:24], "little")
    coefficients = [1]
    for _ in points[1:]:
        coefficients.append(e_mul(coefficients[-1], theta))
    weights = []
    for x in range(len(table)):
        bits = [(x >> j) & 1 for j in range(len(points[0]))]
        value = 0
        for coefficient, point in zip(coefficients, points):
            value ^= e_mul(coefficient, eq(point, bits))
        weights.append(value)
    target = 0
    for coefficient, value in zip(coefficients, values):
        target ^= e_mul(coefficient, value)
    working = list(table)
    rounds, new_point = [], []
    for i in range(len(points[0])):
        c0, c2 = 0, 0
        for a, b, wa, wb in zip(working[::2], working[1::2], weights[::2], weights[1::2]):
            c0 ^= e_mul(a, wa)
            c2 ^= e_mul(a ^ b, wa ^ wb)
        state = step(state, c0, c2, i)
        z = int.from_bytes(state[:24], "little")
        target = c0 ^ e_mul(z, target ^ c2) ^ e_mul(e_mul(z, z), c2)
        rounds.append([c0, c2])
        new_point.append(z)
        working, weights = fold(working, z), fold(weights, z)
    assert target == e_mul(working[0], weights[0])
    assert working[0] == evaluate(table, new_point)
    return {"n": len(points[0]), "m": len(points), "poly_id_hex": poly_id.hex(),
            "context_hex": context.hex(), "table": [limbs(x) for x in table],
            "points": [[limbs(x) for x in p] for p in points],
            "values": [limbs(x) for x in values],
            "instance_digest_hex": initial_digest.hex(),
            "rounds": [[limbs(x) for x in pair] for pair in rounds],
            "new_point": [limbs(x) for x in new_point], "new_value": limbs(working[0])}


def verify(vector):
    scalar = lambda v: v[0] | (v[1] << 64) | (v[2] << 128)
    points = [[scalar(x) for x in p] for p in vector["points"]]
    values = [scalar(x) for x in vector["values"]]
    if len(points) != vector["m"] or any(len(p) != vector["n"] for p in points):
        return False
    state = instance(bytes.fromhex(vector["poly_id_hex"]), bytes.fromhex(vector["context_hex"]), points, values)
    theta = int.from_bytes(state[:24], "little")
    target, coefficient = 0, 1
    for value in values:
        target ^= e_mul(coefficient, value)
        coefficient = e_mul(coefficient, theta)
    point = []
    for i, pair in enumerate(vector["rounds"]):
        c0, c2 = map(scalar, pair)
        state = step(state, c0, c2, i)
        z = int.from_bytes(state[:24], "little")
        target = c0 ^ e_mul(z, target ^ c2) ^ e_mul(e_mul(z, z), c2)
        point.append(z)
    if len(point) != vector["n"] or point != [scalar(x) for x in vector["new_point"]]:
        return False
    weight, coefficient = 0, 1
    for old in points:
        weight ^= e_mul(coefficient, eq(old, point))
        coefficient = e_mul(coefficient, theta)
    value = scalar(vector["new_value"])
    return target == e_mul(value, weight) and evaluate([scalar(x) for x in vector["table"]], point) == value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rng = random.Random(0x5A4B2026)
    vectors = []
    mutations = 0
    for n in range(1, 5):
        for m in (1, 2, 3):
            table = [rng.getrandbits(64) for _ in range(1 << n)]
            points = [[rng.getrandbits(192) for _ in range(n)] for _ in range(m)]
            v = prove(table, points, rng.randbytes(32), rng.randbytes(32))
            assert verify(v)
            vectors.append(v)
            for field in ("point", "value", "round0", "terminal_point", "terminal_value", "poly_id", "context"):
                bad = copy.deepcopy(v)
                if field == "point":
                    bad["points"][0][0][2] ^= 1
                elif field == "value":
                    bad["values"][0][2] ^= 1
                elif field == "round0":
                    bad["rounds"][0][0][2] ^= 1
                elif field == "terminal_point":
                    bad["new_point"][0][2] ^= 1
                elif field == "terminal_value":
                    bad["new_value"][2] ^= 1
                else:
                    key = "poly_id_hex" if field == "poly_id" else "context_hex"
                    raw = bytearray.fromhex(bad[key])
                    raw[-1] ^= 1
                    bad[key] = raw.hex()
                assert not verify(bad), field
                mutations += 1
    result = {"schema": 1, "description": "Independent Python GF(2^192) arithmetic and Keccak transcript vectors, not a STARK verification", "reference_acceptances": len(vectors), "reference_mutation_rejections": mutations, "vectors": vectors}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
