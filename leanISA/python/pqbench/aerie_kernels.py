"""Constrained feasibility kernels for Aerie's p = 2^64 - 59 base field.

This is not an Aerie verifier. Each kernel proves a canonical modular product
and commits to its ordered (a,b,result) records. It uses three radix-2^22 limbs
instead of encoding a 128-bit product in the GF(2^64) exponent directly.

For q=floor(a*b/p), a*b+59*q = result + q*2^64. Both nonnegative sides are
normalized into the SAME radix digits, with separate nonnegative carry chains.
Every checked exponent is below 2^47, versus generator order 2^64-1. Four left
carries have 24 bits, two right carries have 20, and the shared terminal digit
has 18. No unchecked integer quotient, carry, result or multiplier is trusted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from Crypto.Hash import keccak

P = (1 << 64) - 59
B = 1 << 22
WIDTHS = (22, 22, 20)
TAG = b"pq-leanbench/aerie/fp64mul/v1".ljust(32, b"\0")


def kh(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def cell(value: int) -> list[int]:
    return [value & ((1 << 64) - 1), value >> 64, 0]


def cells(data: bytes) -> list[list[int]]:
    return [cell(int.from_bytes(data[i:i + 16], "little")) for i in range(0, len(data), 16)]


def limb_values(value: int) -> list[int]:
    return [(value >> (22 * i)) & ((1 << width) - 1) for i, width in enumerate(WIDTHS)]


def normalize(coefficients: list[int]) -> tuple[list[int], list[int]]:
    digits, carries, carry = [], [], 0
    for coefficient in coefficients:
        assert coefficient >= 0
        total = coefficient + carry
        digits.append(total % B)
        carry = total // B
        carries.append(carry)
    assert carry == 0
    return digits, carries


def arithmetic_advice(a: int, b: int) -> dict:
    if not (0 <= a < P and 0 <= b < P):
        raise ValueError("canonical p-field inputs required")
    quotient, result = divmod(a * b, P)
    aa, bb, qq, rr = map(limb_values, (a, b, quotient, result))
    left = [0] * 6
    right = [0] * 6
    for i in range(3):
        left[i] += 59 * qq[i]
        right[i] += rr[i]
        right[i + 2] += qq[i] << 20
        for j in range(3):
            left[i + j] += aa[i] * bb[j]
    ld, lc = normalize(left)
    rd, rc = normalize(right)
    assert ld == rd and ld[:2] == rr[:2]
    assert lc[4] == rc[4] == ld[5] < 1 << 18
    assert all(c < 1 << 24 for c in lc[:4])
    assert all(c < 1 << 20 for c in rc[2:4])
    assert max(left + right + [digit + B * carry for digit, carry in zip(ld, lc)]) < 1 << 47
    return {"a": a, "b": b, "q": quotient, "r": result,
            "left_carries": lc[:4], "right_carries": rc[2:4], "high_digits": ld[2:]}


def public_input(records: list[dict]) -> list[list[int]]:
    digest = kh(TAG)
    for record in records:
        digest = kh(digest + record["a"].to_bytes(8, "little") + record["b"].to_bytes(8, "little")
                    + record["r"].to_bytes(8, "little") + bytes(8))
    return cells(digest)


def generated_records(count: int) -> list[dict]:
    if count < 1:
        raise ValueError("positive kernel count required")
    boundaries = [(P - 1, P - 1), (0, 0), (1, P - 1), (P - 2, P - 3),
                  ((1 << 22) - 1, (1 << 44) - 1), ((1 << 63), (1 << 63) + 1)]
    result = []
    for i in range(count):
        if i < len(boundaries):
            a, b = boundaries[i]
        else:
            raw = hashlib.shake_256(TAG + i.to_bytes(8, "little")).digest(16)
            a, b = int.from_bytes(raw[:8], "little") % P, int.from_bytes(raw[8:], "little") % P
        result.append(arithmetic_advice(a, b))
    return result


def source(count: int) -> str:
    if count < 1:
        raise ValueError("positive kernel count required")
    initial = [int.from_bytes(kh(TAG)[i:i + 16], "little") for i in (0, 16)]
    dsl = f'''from snark_lib import *

COUNT = {count}


def main():
    batch = StackBuf(2)
    batch[0] = {initial[0]}
    batch[1] = {initial[1]}
    for index in unroll(0, COUNT):
        ab, result = verify_product()
        record = StackBuf(2)
        record[0] = ab
        record[1] = result
        nxt = StackBuf(2)
        keccak(batch, record, nxt, len=64)
        batch = nxt
    public = GEN ** 0
    public[1] = batch[0]
    public[GEN] = batch[1]
    return


def checked_bits(width: Const):
    bits = StackBuf(width)
    hint_witness(bits, "aerie_bits")
    for i in unroll(0, width):
        assert bits[i] * bits[i] == bits[i]
    return bits


def canonical(bits):
    # p = 2^64 - 64 + 5. If all upper 58 bits are one, low6 must be <5.
    upper_ones = 1
    for i in unroll(6, 64):
        upper_ones = upper_ones * bits[GEN ** i]
    assert upper_ones * bits[GEN ** 5] == 0
    assert upper_ones * bits[GEN ** 4] == 0
    assert upper_ones * bits[GEN ** 3] == 0
    assert upper_ones * bits[GEN ** 2] * bits[GEN] == 0
    assert upper_ones * bits[GEN ** 2] * bits[1] == 0
    return


def encode(bits, start: Const, width: Const):
    value = 1
    for i in unroll(0, width):
        value = value * (1 + (GEN ** (2 ** i) + 1) * bits[GEN ** (start + i)])
    return value


def raw64(bits):
    value = 0
    for i in unroll(0, 64):
        value = value + const(2 ** i) * bits[GEN ** i]
    return value


def powers(value):
    out = HeapBuf(22)
    out[1] = value
    for i in unroll(1, 22):
        out[GEN ** i] = out[GEN ** (i - 1)] * out[GEN ** (i - 1)]
    return out


def multiply_limb(power, bits, start: Const, width: Const):
    result = 1
    for i in unroll(0, width):
        result = result * (1 + (power[GEN ** i] + 1) * bits[GEN ** (start + i)])
    return result


def verify_product():
    aa = checked_bits(64)
    bb = checked_bits(64)
    qq = checked_bits(64)
    rr = checked_bits(64)
    canonical(aa)
    canonical(bb)
    canonical(qq)
    canonical(rr)
    c0_bits = checked_bits(24)
    c1_bits = checked_bits(24)
    c2_bits = checked_bits(24)
    c3_bits = checked_bits(24)
    d2_bits = checked_bits(20)
    d3_bits = checked_bits(20)
    t2_bits = checked_bits(22)
    t3_bits = checked_bits(22)
    t4_bits = checked_bits(22)
    t5_bits = checked_bits(18)
    a0 = encode(aa, 0, 22)
    a1 = encode(aa, 22, 22)
    a2 = encode(aa, 44, 20)
    q0 = encode(qq, 0, 22)
    q1 = encode(qq, 22, 22)
    q2 = encode(qq, 44, 20)
    r0 = encode(rr, 0, 22)
    r1 = encode(rr, 22, 22)
    r2 = encode(rr, 44, 20)
    c0 = encode(c0_bits, 0, 24)
    c1 = encode(c1_bits, 0, 24)
    c2 = encode(c2_bits, 0, 24)
    c3 = encode(c3_bits, 0, 24)
    d2 = encode(d2_bits, 0, 20)
    d3 = encode(d3_bits, 0, 20)
    t2 = encode(t2_bits, 0, 22)
    t3 = encode(t3_bits, 0, 22)
    t4 = encode(t4_bits, 0, 22)
    t5 = encode(t5_bits, 0, 18)
    ap0 = powers(a0)
    ap1 = powers(a1)
    ap2 = powers(a2)
    p00 = multiply_limb(ap0, bb, 0, 22)
    p01 = multiply_limb(ap0, bb, 22, 22)
    p02 = multiply_limb(ap0, bb, 44, 20)
    p10 = multiply_limb(ap1, bb, 0, 22)
    p11 = multiply_limb(ap1, bb, 22, 22)
    p12 = multiply_limb(ap1, bb, 44, 20)
    p20 = multiply_limb(ap2, bb, 0, 22)
    p21 = multiply_limb(ap2, bb, 22, 22)
    p22 = multiply_limb(ap2, bb, 44, 20)
    # Separate positive carry chains share EVERY normalized output digit.
    assert p00 * q0 ** 59 == r0 * c0 ** {B}
    assert p01 * p10 * q1 ** 59 * c0 == r1 * c1 ** {B}
    assert p02 * p11 * p20 * q2 ** 59 * c1 == t2 * c2 ** {B}
    assert p12 * p21 * c2 == t3 * c3 ** {B}
    assert p22 * c3 == t4 * t5 ** {B}
    assert r2 * q0 ** {1 << 20} == t2 * d2 ** {B}
    assert q1 ** {1 << 20} * d2 == t3 * d3 ** {B}
    assert q2 ** {1 << 20} * d3 == t4 * t5 ** {B}
    ab = raw64(aa) + const(2 ** 64) * raw64(bb)
    result = raw64(rr)
    return ab, result
'''
    # StackBuf allocation sizes are resolved before Const specialization in
    # this compiler pin, so emit the five concrete buffer-return helpers.
    start = dsl.index("def checked_bits(width: Const):")
    stop = dsl.index("def canonical(bits):")
    helpers = []
    for width in (18, 20, 22, 24, 64):
        helpers.append(f'''def checked_bits_{width}():
    bits = StackBuf({width})
    hint_witness(bits, "aerie_bits")
    out = HeapBuf({width})
    for i in unroll(0, {width}):
        assert bits[i] * bits[i] == bits[i]
        out[GEN ** i] = bits[i]
    return out


''')
        dsl = dsl.replace(f"checked_bits({width})", f"checked_bits_{width}()")
    dsl = dsl[:start] + "".join(helpers) + dsl[stop:]
    return dsl


def build(count: int = 1, records: list[dict] | None = None) -> dict:
    records = generated_records(count) if records is None else records
    if len(records) != count:
        raise ValueError("record count mismatch")
    rows = []
    for record in records:
        expected = arithmetic_advice(record["a"], record["b"])
        if record != expected:
            raise ValueError("record differs from independently recomputed quotient/carries")
        encoded = [(record[name], 64) for name in ("a", "b", "q", "r")]
        encoded += [(v, 24) for v in record["left_carries"]]
        encoded += [(v, 20) for v in record["right_carries"]]
        encoded += [(v, w) for v, w in zip(record["high_digits"], (22, 22, 22, 18))]
        rows.extend([[cell((value >> bit) & 1) for bit in range(width)] for value, width in encoded])
    return {"scheme": "aerie-fp64mul-feasibility-kernel-v1", "source": source(count),
            "witness": {"aerie_bits": rows}, "public_input": public_input(records),
            "metadata": {"scope": "Constrained base-field multiplication kernel, NOT an Aerie verifier or aggregate",
                         "modulus": P, "count": count, "base_modular_multiplications": count,
                         "radix_bits": 22, "limb_widths": list(WIDTHS), "checked_bits_per_multiplication": 476,
                         "record_binding": "One Keccak-256 ordered fold per (a,b,result), included in measured VM/proving cost",
                         "maximum_column_exponent_exclusive": 1 << 47,
                         "encoding_generator_order": (1 << 64) - 1,
                         "records": records}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(build(args.count)) + "\n")


if __name__ == "__main__":
    main()
