"""Round-3 Falcon-512/SHAKE256 verification on the current custom leanISA.

Arithmetic and canonical expanded witnesses share the reviewed ETHFALCON
relation. Only hash-to-point and the claim domain differ. This does not change
the existing ETH guest or its identity. Private benchmark keys are never saved.
"""
from __future__ import annotations

import ctypes
import hashlib
import re
import subprocess
from time import perf_counter_ns

from . import falcon as f, shake

ROOT = f.ROOT
SCHEME = "falcon-512-shake256"
DOMAIN = b"pqbench/falconS\0"
TAG = b"pqbench/standard-falcon-512/v1"
MESSAGE_BYTES = 32
XOF_BYTES = 1280
NATIVE_C_FLAGS = ["-shared", "-fPIC", "-O3", "-DETHFALCON=0"]
_LIBRARY = None
NATIVE_BUILD_INFO = {}
assert len(DOMAIN) == 16


def _native_c():
    global _LIBRARY
    if _LIBRARY is not None:
        return _LIBRARY
    src = ROOT / "vendor/ETHFALCON/falcon/nistfalcon/src"
    names = "codec common fft fpr keygen nist rng shake sign vrfy keccak_prng keccak256 katrng".split()
    fingerprint = hashlib.sha256(" ".join(NATIVE_C_FLAGS).encode())
    for path in sorted([src / f"{name}.c" for name in names] + list(src.glob("*.h"))):
        fingerprint.update(path.name.encode() + b"\0" + path.read_bytes())
    identity = fingerprint.hexdigest()
    directory = ROOT / "build/falcon"
    dest = directory / f"libfalcon-standard-{identity[:24]}.so"
    if not dest.exists():
        directory.mkdir(parents=True, exist_ok=True)
        subprocess.run(["clang", *NATIVE_C_FLAGS, f"-I{src}",
                        *[str(src / f"{name}.c") for name in names], "-o", str(dest)], check=True)
    lib = ctypes.CDLL(str(dest))
    lib.crypto_sign_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
                                    ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p]
    lib.crypto_sign_open.restype = ctypes.c_int
    NATIVE_BUILD_INFO.update({"source_and_flags_sha256": identity, "compile_flags": NATIVE_C_FLAGS,
                             "implementation": "pinned ETHFALCON C standard SHAKE branch"})
    _LIBRARY = lib
    return lib


def native_c_verify(signed: bytes, public_key: bytes) -> bytes | None:
    if len(public_key) != 897:
        return None
    out = ctypes.create_string_buffer(max(len(signed), 1))
    size = ctypes.c_ulonglong()
    if _native_c().crypto_sign_open(out, ctypes.byref(size), signed, len(signed), public_key) != 0:
        return None
    return out.raw[:size.value]


def native_c_timing(signed: bytes, public_key: bytes, message: bytes, repeats: int = 30) -> float:
    if repeats < 1 or native_c_verify(signed, public_key) != message:
        raise ValueError("invalid standard Falcon timing input")
    verify = _native_c().crypto_sign_open
    out = ctypes.create_string_buffer(max(len(signed), 1))
    size = ctypes.c_ulonglong()
    started = perf_counter_ns()
    for _ in range(repeats):
        if verify(out, ctypes.byref(size), signed, len(signed), public_key) != 0:
            raise ValueError("standard Falcon verification failed during timing")
    return (perf_counter_ns() - started) / repeats


def point(salt: bytes, message: bytes) -> list[int]:
    out = []
    data = shake.digest(salt + message, XOF_BYTES)
    for offset in range(0, len(data), 2):
        candidate = int.from_bytes(data[offset:offset + 2], "big")
        if candidate < 5 * f.Q:
            out.append(candidate % f.Q)
            if len(out) == f.N:
                return out
    raise ValueError("Falcon hash-to-point exhausted the bounded SHAKE stream")


def native_verify(h, s2, salt, message) -> bool:
    if len(h) != f.N or len(s2) != f.N or len(salt) != 40:
        return False
    if any(not 0 <= x < f.Q for x in h) or any(abs(x) > 2047 for x in s2):
        return False
    challenge = point(salt, message)
    product = f.convolution_schoolbook(h, s2)
    centered = [(x - y + f.Q // 2) % f.Q - f.Q // 2 for x, y in zip(challenge, product)]
    return sum(x * x for x in centered + list(s2)) <= f.BOUND


def generate_record(index: int) -> dict:
    if index < 0:
        raise ValueError("record index must be nonnegative")
    lib = _native_c()
    lib.crypto_sign_keypair_from_seed.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.crypto_sign_keypair_from_seed.restype = ctypes.c_int
    lib.randombytes_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.randombytes_init.restype = None
    lib.crypto_sign.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_char_p,
                               ctypes.c_ulonglong, ctypes.c_void_p]
    lib.crypto_sign.restype = ctypes.c_int
    label = index.to_bytes(8, "little")
    message = hashlib.sha256(TAG + b"/message/" + label).digest()
    seed = hashlib.shake_256(TAG + b"/key/" + label).digest(48)
    entropy = ctypes.create_string_buffer(hashlib.shake_256(TAG + b"/sign/" + label).digest(48))
    lib.randombytes_init(entropy, None, 256)
    pk, sk = ctypes.create_string_buffer(897), ctypes.create_string_buffer(1281)
    started = perf_counter_ns()
    if lib.crypto_sign_keypair_from_seed(pk, sk, seed, len(seed)):
        raise RuntimeError("standard Falcon key generation failed")
    keygen_ns = perf_counter_ns() - started
    signed, size = ctypes.create_string_buffer(2 + 40 + len(message) + 690), ctypes.c_ulonglong()
    started = perf_counter_ns()
    try:
        for attempts in range(1, 17):
            if lib.crypto_sign(signed, ctypes.byref(size), message, len(message), sk) == 0:
                break
        else:
            raise RuntimeError("standard Falcon signing exhausted retries")
    finally:
        ctypes.memset(ctypes.addressof(sk), 0, len(sk))
    sign_ns = perf_counter_ns() - started
    record = {"index": index, "public_key_hex": pk.raw.hex(), "message_hex": message.hex(),
              "signed_message_hex": signed.raw[:size.value].hex(), "native_sign_attempts": attempts,
              "native_keygen_ns": keygen_ns, "native_sign_ns": sign_ns,
              "provenance": "native standard Falcon512 SHAKE; public deterministic benchmark seeds"}
    decoded_record(record)
    return record


def decoded_record(record: dict):
    pk, message, signed = (bytes.fromhex(record[k]) for k in
                           ("public_key_hex", "message_hex", "signed_message_hex"))
    if len(message) != MESSAGE_BYTES:
        raise ValueError("standard benchmark messages must contain exactly 32 bytes")
    if len(signed) < 43 + len(message) or signed[42:42 + len(message)] != message:
        raise ValueError("signed message does not match the declared message")
    if signed[42 + len(message)] != 0x29 or len(signed) != 42 + len(message) + int.from_bytes(signed[:2], "big"):
        raise ValueError("invalid standard Falcon framing")
    if native_c_verify(signed, pk) != message:
        raise ValueError("native C rejected the standard Falcon signature")
    h, s2, salt = f.decode_key(pk), f.decode_signature(signed[43 + len(message):]), signed[2:42]
    if not native_verify(h, s2, salt, message):
        raise ValueError("independent standard Falcon equation rejected")
    return h, s2, salt, message


def public_claim(record: dict) -> dict:
    pk = bytes.fromhex(record["public_key_hex"])
    message = bytes.fromhex(record["message_hex"])
    if len(message) != MESSAGE_BYTES:
        raise ValueError("expected a 32-byte public message")
    h = f.decode_key(pk)
    key_hash = f.digest(b"".join(x.to_bytes(2, "little") for x in h))
    message_hash = f.digest(message)
    claim = f.digest(DOMAIN + key_hash + message_hash)
    return {"public_key_hex": pk.hex(), "message_hex": message.hex(),
            "key_hash": key_hash.hex(), "message_hash": message_hash.hex(), "claim_hash": claim.hex()}


claim_record = public_claim


def expected_digest(records: list[dict]) -> bytes:
    if not records:
        raise ValueError("at least one signature is required")
    accumulator = f.digest(DOMAIN + len(records).to_bytes(8, "big"))
    for record in records:
        accumulator = f.digest(accumulator + bytes.fromhex(public_claim(record)["claim_hash"]))
    return accumulator


def expected_public_input(records: list[dict]) -> list[list[int]]:
    return f.halves(expected_digest(records))


class Witness(f.Witness):
    def hash_to_point(self, salt: bytes, message: bytes):
        out = []
        data = shake.digest(salt + message, XOF_BYTES)
        for offset in range(0, len(data), 2):
            if len(out) == f.N:
                break
            candidate = int.from_bytes(data[offset:offset + 2], "big")
            accepted = candidate < 5 * f.Q
            self.put("accepted", int(accepted))
            if accepted:
                out.append(self.mod(candidate, 5))
        if len(out) != f.N:
            raise ValueError("bounded standard Falcon SHAKE stream exhausted")
        return out


def source(count: int) -> str:
    if count < 1:
        raise ValueError("at least one signature is required")
    initial = f.digest(DOMAIN + count.to_bytes(8, "big"))
    text = f.guest_source([bytes(MESSAGE_BYTES)] * count, initial)
    text = re.sub(r"^DOMAIN = .*", f"DOMAIN = {int.from_bytes(DOMAIN, 'little')}", text, flags=re.M)
    text = text.replace("    initial = hash_bytes_0_72(data)\n", "")
    text = text.replace("verify_signature(initial, key, sig)", "verify_signature(data, key, sig)")
    text = text.replace("def verify_signature(initial: StackBuf(2), key, sig):", "def verify_signature(data, key, sig):")
    text = text.replace("    point = hash_to_point(initial)", "    point = standard_hash_to_point(data)")
    return text + shake.dsl_helpers() + shake.dsl_function("standard_shake", 72, XOF_BYTES) + '''
def standard_candidate(high, low):
    bits = StackBuf(16)
    raw = low + high * 256
    hint_decompose_bits(bits, raw, 16)
    value = 0
    exponent = 1
    for j in unroll(0, 16):
        b = bits[j]
        bits[j] = b * b
        value = value + b * const(2 ** j)
        exponent = exponent * (1 + b * (GEN ** (2 ** j) + 1))
    assert value == raw
    return exponent


def standard_hash_to_point(data):
    stream = standard_shake(data)
    point = HeapBuf(N)
    indices = HeapBuf(641)
    indices[1] = 1
    for pair in mul_range(1, GEN ** 640):
        candidate = standard_candidate(stream[pair ** 2], stream[pair ** 2 * GEN])
        indices[pair * GEN] = take_candidate(candidate, indices[pair], point)
    assert indices[GEN ** 640] == GEN ** N
    return point
'''


def build_records(records: list[dict]) -> dict:
    if not records:
        raise ValueError("at least one standard Falcon signature is required")
    witness = Witness()
    signature_bytes = 0
    native_ns = 0
    for record in records:
        h, s2, salt, message = decoded_record(record)
        witness.signature(h, s2, salt, message)
        signed = bytes.fromhex(record["signed_message_hex"])
        signature_bytes += len(signed) - MESSAGE_BYTES - 2
        native_ns += native_c_timing(signed, bytes.fromhex(record["public_key_hex"]), message)
    return {"scheme": SCHEME, "source": source(len(records)), "witness": witness.streams,
            "public_input": expected_public_input(records),
            "metadata": {"count": len(records), "records": records, "raw_signature_bytes": signature_bytes,
                         "signature_bytes": signature_bytes, "raw_key_bytes": len(records) * 897,
                         "public_key_bytes": len(records) * 897, "message_bytes": len(records) * MESSAGE_BYTES,
                         "native_verify_ns_per_signature": native_ns / len(records),
                         "native_C_timing_repeats": 30, "native_build": dict(NATIVE_BUILD_INFO),
                         "hash_to_point_xof_byte_cap": XOF_BYTES,
                         "encoding": "canonical expanded uint16 key commitment and expanded s2 witness",
                         "parameters": {"degree": f.N, "modulus": f.Q, "norm_bound": f.BOUND,
                                        "message_lengths": [MESSAGE_BYTES] * len(records)},
                         "benchmark_note": "Public deterministic keys/randomness; do not use for funds."}}


def build(count: int) -> dict:
    if count < 1:
        raise ValueError("at least one signature is required")
    return build_records([generate_record(index) for index in range(count)])
