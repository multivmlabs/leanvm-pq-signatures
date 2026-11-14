#!/usr/bin/env python3
"""Bound the selected source-profile norm threshold using rational arithmetic.

This is a correctness certificate for the expression in SPEC.md, not a security
estimate or evidence that the expression matches the paper. No benchmark runs.
"""
from fractions import Fraction as F
from math import isqrt
import argparse
import json
from pathlib import Path


def sqrt_interval(n, scale):
    root = isqrt(n * scale * scale)
    low = F(root, scale)
    high = low if root * root == n * scale * scale else F(root + 1, scale)
    assert low * low <= n <= high * high
    return low, high


def exp_quarter_interval(terms):
    # Positive Taylor series. After the omitted term, every next-term ratio is
    # at most 1/(4*(terms+2)); its geometric series bounds the entire tail.
    term = F(1)
    partial = term
    for k in range(1, terms + 1):
        term /= 4 * k
        partial += term
    omitted = term / (4 * (terms + 1))
    ratio = F(1, 4 * (terms + 2))
    return partial, partial + omitted / (1 - ratio)


def floor(value):
    return value.numerator // value.denominator


def certificate():
    scale, terms = 10**80, 128
    exp_low, exp_high = exp_quarter_interval(terms)
    depth_low, depth_high = sqrt_interval(1000, scale)
    dimension_low, dimension_high = sqrt_interval(256 * 18, scale)
    tail = F((23 * 2**35 + 2**39) * 48)
    low = exp_low * (depth_low * 23 * 2**7 + 2**40) * dimension_low + tail
    high = exp_high * (depth_high * 23 * 2**7 + 2**40) * dimension_high + tail
    lower_squared, upper_squared = low * low, high * high
    threshold = floor(lower_squared)
    assert threshold == floor(upper_squared)
    assert threshold == 25650475979193785709999263840
    return {
        "schema": 1,
        "scope": "Exact floor of the SPEC.md reference-profile expression squared; paper conformance pending",
        "method": "Positive rational Taylor series with geometric tail bound; rational square-root intervals from integer isqrt",
        "sqrt_scale": str(scale),
        "exp_taylor_last_power": terms,
        "expression": "(exp(1/4)*(sqrt(1000)*23*2^7+2^40)*sqrt(256*18)+(23*2^35+2^39)*48)^2",
        "floor_lower_bound": str(threshold),
        "floor_upper_bound": str(floor(upper_squared)),
        "integer_threshold": str(threshold),
        "lower_squared_numerator": str(lower_squared.numerator),
        "lower_squared_denominator": str(lower_squared.denominator),
        "upper_squared_numerator": str(upper_squared.numerator),
        "upper_squared_denominator": str(upper_squared.denominator),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = certificate()
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("scope", "integer_threshold", "floor_lower_bound", "floor_upper_bound")}))
