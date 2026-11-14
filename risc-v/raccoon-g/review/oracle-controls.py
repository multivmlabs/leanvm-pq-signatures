#!/usr/bin/env python3
"""Independent ring and exact-norm correctness controls, no performance study."""
from hashlib import sha256, shake_256
from math import isqrt
from pathlib import Path
import json
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import generate_fixtures as fixtures
from polyr import RACC_N as N, RACC_Q as Q, RACC_W, ntt, intt, mul_ntt, vec_intt, vec_rshift, vec_add, mul_mat_vec_ntt


def naive_negacyclic(left, right):
    result = [0] * N
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            if i + j < N:
                result[i + j] += a * b
            else:
                result[i + j - N] -= a * b
    return [x % Q for x in result]


def arithmetic_controls():
    random = shake_256(b"Raccoon-G independent arithmetic controls v1").digest(2 * N * 8)
    random_a = [int.from_bytes(random[8*i:8*i+8], "little") % Q for i in range(N)]
    random_b = [int.from_bytes(random[8*(N+i):8*(N+i)+8], "little") % Q for i in range(N)]
    unit0, unit1, unit255 = [0] * N, [0] * N, [0] * N
    unit0[0], unit1[1], unit255[-1] = 1, 1, 1
    pairs = [("zero", [0] * N, [0] * N), ("unit", unit0, unit0),
             ("negacyclic-wrap", unit255, unit1),
             ("all-minus-one", [Q - 1] * N, [Q - 1] * N),
             ("deterministic-dense", random_a, random_b)]
    cases = []
    for name, a, b in pairs:
        transformed_a, transformed_b = ntt(a.copy()), ntt(b.copy())
        assert intt(transformed_a.copy()) == a
        expected = naive_negacyclic(a, b)
        assert intt(mul_ntt(transformed_a, transformed_b)) == expected
        cases.append({"name": name, "a": a, "b": b,
                      "ntt_a": transformed_a, "ntt_b": transformed_b,
                      "negacyclic_product": expected})
    return {"schema": 1, "profile": fixtures.PROFILE, "modulus": Q, "degree": N,
            "twiddles_sha256": sha256(b"".join(int(x).to_bytes(7, "little") for x in RACC_W)).hexdigest(),
            "cases": cases, "benchmarks_run": False}


def four_squares(value):
    # A bounded deterministic search for these specific 95-bit norm boundaries.
    # Every candidate is checked by exact integer squaring before use.
    for offset in range(1024):
        a = isqrt(value) - offset
        rem_a = value - a * a
        b = isqrt(rem_a)
        rem_b = rem_a - b * b
        for c in range(isqrt(rem_b) + 1):
            rem_c = rem_b - c * c
            d = isqrt(rem_c)
            if d * d == rem_c:
                result = [a, b, c, d]
                assert sum(x*x for x in result) == value
                return result
    raise ValueError("no exact four-square control found within declared search")


def norm_controls():
    reference = fixtures.reference
    scheme = fixtures.TRaccoon(kappa=128)
    threshold = int(fixtures.norm_profile()["squared_threshold"])
    at, above = four_squares(threshold), four_squares(threshold + 1)
    public_key = reference.serialize_public_key((bytes(16), [[0] * N for _ in range(scheme.k)]))
    message = sha256(b"norm parser controls, excluded from benchmark corpus").digest()
    vk = reference.deserialize_public_key(public_key)
    mu = reference._compute_buff_mu(scheme, vk, message)
    matrix = scheme._expand_a(bytes(16))
    cases = []
    for name in ["zero-positive", "exact-bound-positive", "one-above-bound-negative", "negative-sign-exact-bound-positive",
                 "negative-sign-one-above-bound-negative", "single-radius-plus-one-negative", "hint-midpoint-negative"]:
        z = [[0] * N for _ in range(scheme.ell)]
        h = [[0] * N for _ in range(scheme.k)]
        if name in ("exact-bound-positive", "negative-sign-exact-bound-positive"):
            z[0][:4] = at
        elif name in ("one-above-bound-negative", "negative-sign-one-above-bound-negative"):
            z[0][:4] = above
        elif name == "single-radius-plus-one-negative":
            z[0][0] = isqrt(threshold) + 1
        elif name == "hint-midpoint-negative":
            h[0][0] = scheme.q_w // 2
        if name.startswith("negative-sign-"):
            z[0][:4] = [-x % Q for x in z[0][:4]]
        # t=0 makes c*t=0 independently of the challenge, so recomputing this
        # hash gives an algebraically valid challenge even in norm-fail cases.
        w = vec_intt(mul_mat_vec_ntt(matrix, fixtures.vec_ntt(z)))
        w = vec_add(vec_rshift(w, scheme.nu_w, scheme.q_w), h, scheme.q_w)
        challenge = scheme._hash_vec(mu, w)
        signature = reference.serialize_signature((challenge, z, h))
        intermediate = fixtures.reconstruct(public_key, message, signature)
        assert intermediate["challenge_matches"]
        expected = name.endswith("positive")
        assert intermediate["integer_norm_accepts"] == expected
        cases.append({"name": name, "public_key": public_key.hex(), "message": message.hex(),
                      "signature": signature.hex(), "expected_integer_accepts": expected,
                      "norm_squared": intermediate["combined_squared_norm"],
                      "source_accepts": intermediate["upstream_accepts"],
                      "challenge_matches": True})
    return {"schema": 1, "profile": fixtures.PROFILE,
            "squared_threshold": str(threshold), "excluded_from_benchmarks": True,
            "four_squares_at_bound": at, "four_squares_one_above_bound": above,
            "note": "Algebraic zero keys isolate norm checks. Float-reference and exact-integer boundary differences are intentional and recorded.",
            "cases": cases, "benchmarks_run": False}


def main():
    fixtures.check_source()
    arithmetic = arithmetic_controls()
    fixtures.write(HERE / "oracle-arithmetic.json", arithmetic)
    norm = norm_controls()
    fixtures.write(HERE.parent / "host/testdata/norm-controls.json", norm)
    print(json.dumps({"arithmetic_cases": len(arithmetic["cases"]),
                      "norm_cases": [{"name": case["name"], "norm_squared": case["norm_squared"],
                                      "expected_integer_accepts": case["expected_integer_accepts"],
                                      "source_accepts": case["source_accepts"]} for case in norm["cases"]],
                      "benchmarks_run": False}, indent=2))


if __name__ == "__main__":
    main()
