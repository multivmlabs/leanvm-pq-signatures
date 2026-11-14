#!/usr/bin/env python3
"""Independent byte-oriented FORS oracle using PyCryptodome's Keccak implementation.

Run the Rust exporter first, then pass its JSON filename. This does not import
Rust code or the prior guest and checks complete deterministic fixture equality.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path
from Crypto.Hash import keccak

N, K, A = 32, 16, 8


def h(data):
    return keccak.new(data=data, digest_bits=256).digest()


def domain(label):
    return (b"FORS:" + label).ljust(12, b"\0") + bytes([1, N, K, A])


def address(tree, height, index):
    return tree.to_bytes(4, "little") + height.to_bytes(4, "little") + index.to_bytes(8, "little")


def indices(seed, root, message):
    return h(domain(b"MSG") + seed + root + message)[:K]


def generate(number):
    tag = b"pqbench-fors-fixture-v1" + number.to_bytes(8, "little") + bytes([K, A])
    derive = lambda label: hashlib.sha256(tag + label).digest()
    sk, seed, message = map(derive, (b":sk", b":pk", b":message"))
    roots, all_levels, all_secrets = [], [], []
    for tree in range(K):
        secrets = [h(b"TEST-SECRET:" + sk + address(tree, 0, i)) for i in range(1 << A)]
        levels = [[h(domain(b"LEAF") + seed + address(tree, 0, i) + secret) for i, secret in enumerate(secrets)]]
        for height in range(1, A + 1):
            prev = levels[-1]
            levels.append([h(domain(b"NODE") + seed + address(tree, height, i // 2) + prev[i] + prev[i + 1]) for i in range(0, len(prev), 2)])
        roots.append(levels[-1][0])
        all_levels.append(levels)
        all_secrets.append(secrets)
    root = h(domain(b"ROOT") + seed + b"".join(roots))
    signature = []
    for tree, index in enumerate(indices(seed, root, message)):
        signature.append({"secret": all_secrets[tree][index].hex(), "auth": [all_levels[tree][height][(index >> height) ^ 1].hex() for height in range(A)]})
    return {"seed": seed.hex(), "root": root.hex(), "message": message.hex(), "signature": signature}


def verify(record, node_domain=domain(b"NODE")):
    seed, root, message = (bytes.fromhex(record[key]) for key in ("seed", "root", "message"))
    if any(len(value) != 32 for value in (seed, root, message)) or len(record["signature"]) != K:
        return False
    roots = []
    for tree, index in enumerate(indices(seed, root, message)):
        opening = record["signature"][tree]
        secret = bytes.fromhex(opening["secret"])
        if len(secret) != N or len(opening["auth"]) != A:
            return False
        current = h(domain(b"LEAF") + seed + address(tree, 0, index) + secret)
        for height, encoded in enumerate(opening["auth"]):
            sibling = bytes.fromhex(encoded)
            if len(sibling) != N:
                return False
            left, right = (sibling, current) if index & 1 else (current, sibling)
            index >>= 1
            current = h(node_domain + seed + address(tree, height + 1, index) + left + right)
        roots.append(current)
    return root == h(domain(b"ROOT") + seed + b"".join(roots))


def main():
    records = json.loads(Path(sys.argv[1]).read_text())
    assert records
    for number, record in enumerate(records):
        assert record == generate(number), f"fixture {number} differs from independent byte oracle"
        assert verify(record)
    bad = copy.deepcopy(records[0])
    value = bytearray.fromhex(bad["signature"][0]["auth"][0])
    value[0] ^= 1
    bad["signature"][0]["auth"][0] = value.hex()
    assert not verify(bad)
    assert not verify(records[0], domain(b"LEAF"))
    print(json.dumps({"records": len(records), "complete_fixture_equality": True, "valid_paths": True, "mutated_path_rejected": True, "wrong_node_domain_rejected": True}))


if __name__ == "__main__":
    main()
