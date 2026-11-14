#!/usr/bin/env python3
"""Deterministic Raccoon-G correctness fixtures using the pinned authors' code.

This generates a requested record, never selects a favorable signature and never
retries after verification failure. Signing and key generation stay outside the
VM statement. It does not produce a STARK or run any performance experiment.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256, sha512, shake_256
import hmac
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "sources/lattice-hd-wallets"
PIN = "461a5ed9b6d57e3bf8c381be3bb79325ab21d906"
PROFILE = "raccoong-hd-authors-poc-461a5ed9-v1"
sys.path.insert(0, str(SOURCE / "src/raccoon/thrc-py"))

import mpmath as mp
import raccoon_primitives as reference
from thrc_api import TRaccoon
from polyr import (RACC_Q, RACC_N, ntt, intt, vec_ntt, vec_intt,
                   vec_rshift, vec_lshift, vec_mul_ntt, vec_sub, vec_add,
                   mul_mat_vec_ntt)


def check_source():
    actual = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip()
    if actual != PIN:
        raise ValueError("wrong authors' reference revision: " + actual)
    patch = subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain"], text=True).strip()
    if patch:
        raise ValueError("modified authors' reference checkout")
    if mp.__version__ != "1.3.0":
        raise ValueError("fixture Gaussian sampler is pinned to mpmath==1.3.0")


def centered(value, modulus):
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def norm_profile():
    # Directed interval arithmetic, not a binary64 approximation of the bound.
    # The floors of both endpoints must agree before a constant is emitted.
    mp.iv.prec = 512
    iv = mp.iv
    bound = (iv.exp(iv.mpf(1) / 4)
             * (iv.sqrt(iv.mpf(1000)) * 23 * 2**7 + 2**40)
             * iv.sqrt(iv.mpf(256 * (9 + 9)))
             + (23 * 2**35 + 2**39) * iv.sqrt(iv.mpf(256 * 9)))
    squared = bound * bound
    low, high = int(squared.a), int(squared.b)
    if low != high:
        raise ValueError("interval precision does not establish a unique squared floor")
    reference_bound = TRaccoon(kappa=128).b2
    # The original expression rounds both the sum-to-float conversion and sqrt.
    # Locate its actual integer acceptance boundary, separately from B*B.
    lo, hi = 0, 1 << 128
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**0.5 <= reference_bound:
            lo = mid
        else:
            hi = mid
    return {
        "schema": 1,
        "profile": PROFILE,
        "expression": "exp(1/4)*(sqrt(1000)*23*2^7+2^40)*sqrt(256*(9+9))+(23*2^35+2^39)*sqrt(256*9)",
        "interval_precision_bits": 512,
        "squared_floor_lower": str(low),
        "squared_floor_upper": str(high),
        "squared_threshold": str(low),
        "upstream_binary64_radius_hex": reference_bound.hex(),
        "upstream_binary64_radius_squared_as_integer": str(int(reference_bound * reference_bound)),
        "upstream_binary64_sqrt_actual_largest_accepted_integer": str(lo),
        "upstream_binary64_sqrt_next_integer_rejected": str(hi),
        "paper_conformance": "provisional executable reference profile; paper review pending",
        "benchmarks_run": False,
    }


def sha(value):
    return sha256(value).hexdigest()


def serialized_residues(vector, modulus=RACC_Q, size=7):
    return b"".join(int(x % modulus).to_bytes(size, "little") for row in vector for x in row)


def reconstruct(public_key, message, signature):
    """Independently expose every major verifier intermediate from source math."""
    raccoon = TRaccoon(kappa=128)
    vk = reference.deserialize_public_key(public_key)
    c_hash, z, h = reference.deserialize_signature(signature)
    if reference.serialize_public_key(vk) != public_key or reference.serialize_signature((c_hash, z, h)) != signature:
        raise ValueError("input is not a canonical serializer output")
    tr = shake_256(public_key).digest(32)
    mu = shake_256(tr + message).digest(32)
    if mu != reference._compute_buff_mu(raccoon, vk, message):
        raise AssertionError("BUFF byte mismatch")
    challenge = raccoon._chal_poly(c_hash)
    challenge_ntt = ntt(challenge.copy())
    matrix = raccoon._expand_a(vk[0])
    t_rounded = vec_rshift(vk[1], raccoon.nu_t, raccoon.q_t)
    scaled = vec_lshift(t_rounded, raccoon.nu_t)
    product = vec_mul_ntt(challenge_ntt, vec_ntt(scaled))
    w_ntt = vec_sub(mul_mat_vec_ntt(matrix, vec_ntt(z)), product)
    w = vec_intt(w_ntt)
    w = vec_add(vec_rshift(w, raccoon.nu_w, raccoon.q_w), h, raccoon.q_w)
    recomputed = raccoon._hash_vec(mu, w)
    z_squared = sum(centered(x, raccoon.q)**2 for row in z for x in row)
    h_squared = sum(centered(x, raccoon.q_w)**2 for row in h for x in row)
    squared = z_squared + (1 << (2 * raccoon.nu_w)) * h_squared
    threshold = int(norm_profile()["squared_threshold"])
    upstream_accepts = reference.verify_signature(public_key, message, signature)
    return {
        "tr": tr.hex(), "mu": mu.hex(), "challenge": challenge,
        "challenge_hash": c_hash.hex(), "recomputed_challenge_hash": recomputed.hex(),
        "matrix_a00_ntt": matrix[0][0],
        "matrix_ntt_sha256": sha(serialized_residues([row for block in matrix for row in block])),
        "t_rounded": t_rounded,
        "scaled_t_sha256": sha(serialized_residues(scaled)),
        "w": w,
        "z_squared": str(z_squared), "h_squared": str(h_squared),
        "combined_squared_norm": str(squared),
        "squared_threshold": str(threshold),
        "challenge_matches": recomputed == c_hash,
        "integer_norm_accepts": squared <= threshold,
        "upstream_accepts": upstream_accepts,
    }


def sign_fixed(public_key, signing_key, message, signing_coins):
    if len(signing_coins) != 32 or len(message) != 32:
        raise ValueError("fixed correctness profile uses 32-byte message and signing coins")
    raccoon = TRaccoon(kappa=128)
    calls = []

    def random_bytes(length):
        calls.append(length)
        if calls != [32]:
            raise ValueError("unexpected reference signing randomness request")
        return signing_coins

    raccoon.set_random(random_bytes)
    vk, s = reference.deserialize_signing_key(signing_key)
    if reference.serialize_public_key(vk) != public_key:
        raise ValueError("signing key does not embed the intended public key")
    mu = reference._compute_buff_mu(raccoon, vk, message)
    signature = reference.serialize_signature(reference._sign_with_unrounded_public_key(raccoon, vk, s, mu))
    if calls != [32]:
        raise ValueError("reference did not consume exactly the fixed signing randomness")
    intermediate = reconstruct(public_key, message, signature)
    # A failing sample is reported, never silently re-signed with new coins.
    if not (intermediate["upstream_accepts"] and intermediate["integer_norm_accepts"] and intermediate["challenge_matches"]):
        raise ValueError("deterministic signing failed verification; no retry: " + json.dumps(intermediate))
    return {"public_key": public_key.hex(), "message": message.hex(), "signature": signature.hex()}, intermediate


def record(index):
    if not 0 <= index < 1 << 64:
        raise ValueError("index must fit u64")
    encoded_index = index.to_bytes(8, "little")
    entropy = shake_256(b"pqbench/raccoong-hd/key/v1\0" + encoded_index).digest(32)
    signing_coins = shake_256(b"pqbench/raccoong-hd/sign/v1\0" + encoded_index).digest(32)
    message = sha256(b"pqbench/raccoong-hd/message/v1\0" + encoded_index).digest()
    public_key, signing_key = reference.generate_keypair_from_seed(entropy)
    data, intermediate = sign_fixed(public_key, signing_key, message, signing_coins)
    oracle = {"schema": 1, "profile": PROFILE, "source_commit": PIN, "index": index,
              "key_entropy": entropy.hex(), "signing_coins": signing_coins.hex(),
              "signing_attempts": 1, "retries": 0, "key_generation": "standalone independent key, no HD path",
              "public_key_sha256": sha(public_key), "signature_sha256": sha(bytes.fromhex(data["signature"])),
              "intermediate": intermediate, "benchmarks_run": False}
    return data, oracle


@dataclass
class Node:
    public_key: bytes
    signing_key: bytes
    derivation_seed: bytes
    chain_code: bytes


def master_node(master_seed):
    material = hmac.new(b"Raccoon-HD-wallet", master_seed, sha512).digest()
    public_key, signing_key = reference.generate_keypair_from_seed(material[:32])
    return Node(public_key, signing_key, material[:32], material[32:])


def child_public_only(public_key, chain_code, index):
    material = hmac.new(chain_code, public_key + index.to_bytes(4, "big"), sha512).digest()
    tweak_pk, _ = reference.generate_tweak_keypair_from_seed(material[:32], public_key[:16])
    return reference.add_public_keys(public_key, tweak_pk), material[32:]


def nonhardened(parent, index):
    material = hmac.new(parent.chain_code, parent.public_key + index.to_bytes(4, "big"), sha512).digest()
    tweak_pk, tweak_sk = reference.generate_tweak_keypair_from_seed(material[:32], parent.public_key[:16])
    child_pk = reference.add_public_keys(parent.public_key, tweak_pk)
    child_sk = reference.add_signing_keys(parent.signing_key, tweak_sk)
    if reference.get_public_key_from_signing_key(child_sk) != child_pk:
        raise AssertionError("private/public child addition mismatch")
    return Node(child_pk, child_sk, material[:32], material[32:])


def hardened(parent, index):
    # This is the pinned executable body, including stored derivation_seed.
    # No BIP32 high-bit rewrite is applied to the independently marked index.
    data = b"\0" + parent.signing_key[len(parent.public_key):] + parent.derivation_seed + index.to_bytes(4, "big")
    material = hmac.new(parent.chain_code, data, sha512).digest()
    public_key, signing_key = reference.generate_keypair_from_seed(material[:32])
    return Node(public_key, signing_key, material[:32], material[32:])


def hd_controls():
    master_seed = sha256(b"Raccoon-G HD correctness controls, public test seed").digest()
    root = master_node(master_seed)
    child = nonhardened(root, 7)
    grandchild = nonhardened(child, 9)
    hardened_child = hardened(root, 11)
    mixed = hardened(child, 11)
    watch_pk, watch_chain = child_public_only(root.public_key, root.chain_code, 7)
    if (watch_pk, watch_chain) != (child.public_key, child.chain_code):
        raise AssertionError("watch-only derivation differs from private derivation")
    watch_grand_pk, watch_grand_chain = child_public_only(watch_pk, watch_chain, 9)
    if (watch_grand_pk, watch_grand_chain) != (grandchild.public_key, grandchild.chain_code):
        raise AssertionError("watch-only grandchild differs from private derivation")
    if root.public_key[:16] != child.public_key[:16] or child.public_key[:16] != grandchild.public_key[:16]:
        raise AssertionError("non-hardened derivation changed matrix seed")
    if root.public_key[:16] == hardened_child.public_key[:16]:
        raise AssertionError("hardened child unexpectedly kept the old matrix seed")
    try:
        reference.add_public_keys(root.public_key, hardened_child.public_key)
    except ValueError:
        matrix_mismatch_rejected = True
    else:
        raise AssertionError("matrix mismatch was accepted")
    nodes = {"m": root, "m/7": child, "m/7/9": grandchild, "m/11'": hardened_child, "m/7/11'": mixed}
    out = {}
    for path, node in nodes.items():
        entry = {"public_key": node.public_key.hex(), "signing_key": node.signing_key.hex(),
                 "derivation_seed": node.derivation_seed.hex(), "chain_code": node.chain_code.hex()}
        if path in ("m", "m/7", "m/11'"):
            message = sha256(b"HD signature correctness control: " + path.encode()).digest()
            coins = shake_256(b"HD fixed signing coins: " + path.encode()).digest(32)
            signed, intermediate = sign_fixed(node.public_key, node.signing_key, message, coins)
            entry.update({"signed_record": signed, "signing_coins": coins.hex(), "intermediate": intermediate})
        out[path] = entry
    return {"schema": 1, "profile": PROFILE, "source_commit": PIN,
            "master_seed": master_seed.hex(), "nodes": out,
            "controls": {"private_public_child_matches": True, "private_public_grandchild_matches": True,
                         "nonhardened_keeps_matrix_seed": True, "hardened_changes_matrix_seed": True,
                         "matrix_mismatch_rejected": matrix_mismatch_rejected,
                         "hardened_after_nonhardened_exercised": True},
            "scope": "host derivation controls; the signature guest proves no derivation history",
            "benchmarks_run": False}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2) + "\n"
    if path.exists() and path.read_text() != encoded:
        raise ValueError("refusing to overwrite a different fixture: " + str(path))
    path.write_text(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--index", type=int)
    mode.add_argument("--hd-controls", action="store_true")
    mode.add_argument("--norm-profile", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--oracle-out", type=Path)
    args = parser.parse_args()
    check_source()
    if args.norm_profile:
        write(args.out, norm_profile())
    elif args.hd_controls:
        write(args.out, hd_controls())
    else:
        data, oracle = record(args.index)
        write(args.out, data)
        if args.oracle_out:
            write(args.oracle_out, oracle)
    print(json.dumps({"output": str(args.out), "sha256": sha(args.out.read_bytes()), "benchmarks_run": False}))


if __name__ == "__main__":
    main()
