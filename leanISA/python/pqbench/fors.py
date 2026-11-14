"""Few-time Keccak FORS research variant and real leanVM proof fixtures.

This intentionally is neither FIPS 205 nor leanSPHINCS. A fresh deterministic
benchmark key is generated for every record; production signing is out of scope.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from time import perf_counter
from typing import Any

from Crypto.Hash import keccak

N = 32
DEFAULT_K = 16
DEFAULT_A = 8
SCHEME = "fors-keccak-research"
ROOT = Path(__file__).resolve().parents[2]


def hash256(data: bytes) -> bytes:
    return keccak.new(data=data, digest_bits=256).digest()


def domain(name: str, k: int, a: int) -> bytes:
    # 12-byte ASCII label followed by the full fixed parameter tuple.
    return ("FORS:" + name).encode("ascii").ljust(12, b"\0") + bytes([1, N, k, a])


def address(tree: int, height: int, index: int) -> bytes:
    return tree.to_bytes(4, "little") + height.to_bytes(4, "little") + index.to_bytes(8, "little")


def cells(data: bytes) -> list[list[int]]:
    if len(data) % 16:
        raise ValueError("cell encoding requires a multiple of 16 bytes")
    return [[int.from_bytes(data[i:i + 8], "little"), int.from_bytes(data[i + 8:i + 16], "little"), 0]
            for i in range(0, len(data), 16)]


def _check_params(k: int, a: int) -> None:
    if not (1 <= k <= 128 and 1 <= a <= 12 and k * a <= 128):
        raise ValueError("require 1 <= a <= 12, 1 <= k and k*a <= 128")


def _indices(seed: bytes, root: bytes, message: bytes, k: int, a: int) -> list[int]:
    digest = int.from_bytes(hash256(domain("MSG", k, a) + seed + root + message), "little")
    return [(digest >> (tree * a)) & ((1 << a) - 1) for tree in range(k)]


def generate_record(number: int, k: int = DEFAULT_K, a: int = DEFAULT_A) -> dict[str, Any]:
    """Deterministic public test data; its seeds are not secret wallet keys."""
    _check_params(k, a)
    tag = b"pqbench-fors-fixture-v1" + number.to_bytes(8, "little") + bytes([k, a])
    sk_seed = hashlib.sha256(tag + b":sk").digest()
    seed = hashlib.sha256(tag + b":pk").digest()
    message = hashlib.sha256(tag + b":message").digest()
    tree_nodes = []
    tree_secrets = []
    roots = []
    for tree in range(k):
        secrets = [hash256(b"TEST-SECRET:" + sk_seed + address(tree, 0, index)) for index in range(1 << a)]
        leaves = [hash256(domain("LEAF", k, a) + seed + address(tree, 0, index) + secret)
                  for index, secret in enumerate(secrets)]
        levels = [leaves]
        for height in range(1, a + 1):
            previous = levels[-1]
            levels.append([hash256(domain("NODE", k, a) + seed + address(tree, height, index // 2)
                                   + previous[index] + previous[index + 1])
                           for index in range(0, len(previous), 2)])
        tree_nodes.append(levels)
        tree_secrets.append(secrets)
        roots.append(levels[-1][0])
    root = hash256(domain("ROOT", k, a) + seed + b"".join(roots))
    indices = _indices(seed, root, message, k, a)
    signature = []
    for tree, index in enumerate(indices):
        auth = [tree_nodes[tree][height][(index >> height) ^ 1] for height in range(a)]
        signature.append({"secret": tree_secrets[tree][index], "auth": auth})
    return {"seed": seed, "root": root, "message": message, "signature": signature}


def native_verify(record: dict[str, Any], k: int = DEFAULT_K, a: int = DEFAULT_A) -> bool:
    """Independent host verifier of precisely the research guest's byte relation."""
    _check_params(k, a)
    try:
        seed, root, message = (record[name] for name in ("seed", "root", "message"))
        if any(len(value) != N for value in (seed, root, message)) or len(record["signature"]) != k:
            return False
        roots = []
        for tree, index in enumerate(_indices(seed, root, message, k, a)):
            opening = record["signature"][tree]
            if len(opening["secret"]) != N or len(opening["auth"]) != a:
                return False
            node = hash256(domain("LEAF", k, a) + seed + address(tree, 0, index) + opening["secret"])
            for height, sibling in enumerate(opening["auth"]):
                if len(sibling) != N:
                    return False
                left, right = (sibling, node) if (index >> height) & 1 else (node, sibling)
                node = hash256(domain("NODE", k, a) + seed + address(tree, height + 1, index >> (height + 1)) + left + right)
            roots.append(node)
        return hash256(domain("ROOT", k, a) + seed + b"".join(roots)) == root
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def build(count: int, k: int = DEFAULT_K, a: int = DEFAULT_A, mutation: str | None = None,
          start: int = 0) -> dict[str, Any]:
    if count < 1:
        raise ValueError("count must be positive")
    _check_params(k, a)
    if start < 0 or start + count > 2 ** 64:
        raise ValueError("fixture identifiers must fit unsigned 64 bits")
    records = [generate_record(start + i, k, a) for i in range(count)]
    native_started = perf_counter()
    if not all(native_verify(record, k, a) for record in records):
        raise AssertionError("generated invalid FORS test data")
    native_verify_seconds = perf_counter() - native_started
    source = (ROOT / "guests" / "fors.py").read_text()
    for name, value in {"COUNT": count, "K": k, "A": a}.items():
        source = source.replace(name + "_PLACEHOLDER", str(value))
    for name in ("LEAF", "NODE", "ROOT", "MSG", "BATCH"):
        source = source.replace("DS_" + name + "_PLACEHOLDER", str(int.from_bytes(domain(name, k, a), "little")))
    statement = domain("BATCH", k, a) + b"".join(r["seed"] + r["root"] + r["message"] for r in records)
    public_input = cells(hash256(statement))
    witness: dict[str, list[list[list[int]]]] = {"fors_header": [], "fors_secret": [], "fors_auth": []}
    for record in records:
        witness["fors_header"].append(cells(record["seed"] + record["root"] + record["message"]))
        for opening in record["signature"]:
            witness["fors_secret"].append(cells(opening["secret"]))
            witness["fors_auth"].extend(cells(sibling) for sibling in opening["auth"])
    result = {"scheme": SCHEME, "source": source, "witness": witness, "public_input": public_input,
              "count": count, "parameters": {"n": N, "k": k, "a": a},
              "fixture_start": start,
              "signature_bytes": count * N * k * (a + 1), "public_key_bytes": count * 2 * N,
              "raw_signature_bytes": count * N * k * (a + 1), "raw_key_bytes": count * 2 * N,
              "signature_bytes_per_signature": N * k * (a + 1),
              "public_key_bytes_per_signature": 2 * N,
              "baseline_native_verify_s": native_verify_seconds,
              "native_verify_seconds": native_verify_seconds,
              "native_implementation": "Python reference FORS verifier using PyCryptodome Keccak; not an optimized native baseline",
              "security_note": "Unreviewed few-time FORS variant; not FIPS 205 or leanSPHINCS; benchmark keys are deterministic and distinct."}
    result["metadata"] = {key: value for key, value in result.items()
                          if key not in ("source", "witness", "public_input")}
    if mutation:
        result = mutate_fixture(result, mutation)
    return result


def mutate_fixture(fixture: dict[str, Any], mutation: str) -> dict[str, Any]:
    """Negative witnesses preserve the intended public statement."""
    bad = copy.deepcopy(fixture)
    if mutation == "auth":
        bad["witness"]["fors_auth"][0][0][0] ^= 1
    elif mutation == "secret":
        bad["witness"]["fors_secret"][0][0][0] ^= 1
    elif mutation == "message":
        bad["witness"]["fors_header"][0][4][0] ^= 1
    elif mutation == "public-key":
        bad["witness"]["fors_header"][0][2][0] ^= 1
    elif mutation == "noncanonical":
        bad["witness"]["fors_auth"][0][0][2] = 1
    elif mutation == "statement":
        bad["public_input"][0][0] ^= 1
    else:
        raise ValueError("unknown FORS mutation: " + mutation)
    bad["mutation"] = mutation
    bad.setdefault("metadata", {})["mutation"] = mutation
    return bad
