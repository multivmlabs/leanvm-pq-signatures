"""ETHFALCON-512 KAT inputs and constrained leanVM witness generation.

The signature relation is the Keccak-PRNG ETHFALCON relation. The proof's key
codec is 512 canonical uint16 little-endian coefficients, not a NIST key blob.
Only the signature's expanded signed polynomial is witnessed in the guest.
"""
from __future__ import annotations

import ctypes
import hashlib
import subprocess
import re
from pathlib import Path
from time import perf_counter, perf_counter_ns

from Crypto.Hash import keccak

ROOT = Path(__file__).resolve().parents[2]
Q, N, BOUND = 12289, 512, 34034726
PSI = pow(11, 12, Q)
OMEGA = PSI * PSI % Q
DOMAIN = b"pqbench/falcon1\0"
assert len(DOMAIN) == 16
_GPOW = [1]
for _ in range(65535):
    _x = _GPOW[-1]
    _GPOW.append(((_x << 1) & ((1 << 64) - 1)) ^ (0x1B if _x >> 63 else 0))


def digest(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def cell(x: int) -> list[int]:
    return [x & ((1 << 64) - 1), x >> 64, 0]


def halves(data: bytes) -> list[list[int]]:
    assert len(data) == 32
    return [cell(int.from_bytes(data[:16], "little")), cell(int.from_bytes(data[16:], "little"))]


def kat_vectors() -> list[dict[str, str]]:
    path = ROOT / "vendor/ETHFALCON/test/ethfalcon512-KAT.rsp"
    vectors, record = [], {}
    for line in path.read_text().splitlines() + [""]:
        if " = " in line:
            key, value = line.split(" = ", 1)
            record[key] = value
        elif not line.strip() and record:
            vectors.append(record)
            record = {}
    return vectors


def decode_key(encoded: bytes) -> list[int]:
    if len(encoded) != 897 or encoded[0] != 9:
        raise ValueError("expected a Falcon-512 public key")
    payload = int.from_bytes(encoded[1:], "big")
    values = [(payload >> (14 * (511 - i))) & 16383 for i in range(N)]
    if any(v >= Q for v in values):
        raise ValueError("noncanonical Falcon key coefficient")
    return values


def decode_signature(encoded: bytes) -> list[int]:
    bits = "".join(f"{b:08b}" for b in encoded)
    out, pos = [], 0
    for _ in range(N):
        if pos + 9 > len(bits):
            raise ValueError("truncated Falcon signature")
        negative = bits[pos] == "1"
        low = int(bits[pos + 1:pos + 8], 2)
        pos += 8
        high = 0
        while pos < len(bits) and bits[pos] == "0":
            high += 1
            pos += 1
        if pos == len(bits) or high > 15:
            raise ValueError("invalid Falcon signature coefficient")
        pos += 1
        value = low + 128 * high
        if negative and value == 0:
            raise ValueError("negative zero in Falcon signature")
        out.append(-value if negative else value)
    if (pos + 7) // 8 != len(encoded):
        raise ValueError("trailing bytes in Falcon signature")
    if "1" in bits[pos:]:
        raise ValueError("nonzero Falcon signature padding")
    return out


def point(salt: bytes, message: bytes) -> list[int]:
    seed, out = digest(salt + message), []
    counter = 0
    while len(out) < N:
        block = digest(seed + counter.to_bytes(8, "big"))
        counter += 1
        for i in range(0, 32, 2):
            candidate = int.from_bytes(block[i:i + 2], "big")
            if candidate < 5 * Q:
                out.append(candidate % Q)
                if len(out) == N:
                    break
    return out


def convolution_schoolbook(a: list[int], b: list[int]) -> list[int]:
    out = [0] * N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            ij = i + j
            if ij < N:
                out[ij] += x * y
            else:
                out[ij - N] -= x * y
    return [x % Q for x in out]


def native_verify(h: list[int], s2: list[int], salt: bytes, message: bytes) -> bool:
    if len(h) != N or len(s2) != N or len(salt) != 40:
        return False
    if any(not 0 <= x < Q for x in h) or any(abs(x) > 2047 for x in s2):
        return False
    c = point(salt, message)
    product = convolution_schoolbook(h, s2)
    s0 = [((x - y + Q // 2) % Q) - Q // 2 for x, y in zip(c, product)]
    return sum(x * x for x in s0 + s2) <= BOUND


_NATIVE_LIBRARY = None
NATIVE_C_FLAGS = ["-shared", "-fPIC", "-O3", "-DETHFALCON=1"]


def _native_c():
    global _NATIVE_LIBRARY
    if _NATIVE_LIBRARY is not None:
        return _NATIVE_LIBRARY
    source = ROOT / "vendor/ETHFALCON/falcon/nistfalcon/src"
    names = "codec common fft fpr keygen nist rng shake sign vrfy keccak_prng keccak256 katrng".split()
    inputs = [source / (name + ".c") for name in names] + sorted(source.glob("*.h"))
    fingerprint = hashlib.sha256((" ".join(NATIVE_C_FLAGS)).encode())
    for path in inputs:
        fingerprint.update(path.name.encode())
        fingerprint.update(path.read_bytes())
    expected = fingerprint.hexdigest()
    directory = ROOT / "build/falcon"
    destination, stamp = directory / "libethfalcon.so", directory / "source.sha256"
    if not destination.exists() or not stamp.exists() or stamp.read_text().strip() != expected:
        directory.mkdir(parents=True, exist_ok=True)
        subprocess.run(["clang", *NATIVE_C_FLAGS, f"-I{source}", *[str(source / (name + ".c")) for name in names], "-o", str(destination)], check=True)
        stamp.write_text(expected + "\n")
    library = ctypes.CDLL(str(destination))
    library.crypto_sign_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p]
    library.crypto_sign_open.restype = ctypes.c_int
    _NATIVE_LIBRARY = library
    return library


def native_c_verify(signed_message: bytes, public_key: bytes) -> bytes | None:
    """Run the pinned upstream C decoder and ETHFALCON verifier."""
    if len(public_key) != 897:
        return None
    output = ctypes.create_string_buffer(max(len(signed_message), 1))
    length = ctypes.c_ulonglong()
    result = _native_c().crypto_sign_open(output, ctypes.byref(length), signed_message, len(signed_message), public_key)
    if result != 0:
        return None
    return output.raw[:length.value]


def native_c_timing(signed_message: bytes, public_key: bytes, expected_message: bytes, repeats: int = 30) -> float:
    if repeats <= 0 or len(public_key) != 897:
        raise ValueError("invalid native C benchmark parameters")
    verify = _native_c().crypto_sign_open
    output = ctypes.create_string_buffer(max(len(signed_message), 1))
    length = ctypes.c_ulonglong()
    if verify(output, ctypes.byref(length), signed_message, len(signed_message), public_key) != 0 or output.raw[:length.value] != expected_message:
        raise ValueError("upstream C ETHFALCON verifier disagrees with KAT")
    start = perf_counter_ns()
    for _ in range(repeats):
        if verify(output, ctypes.byref(length), signed_message, len(signed_message), public_key) != 0:
            raise ValueError("upstream C ETHFALCON verification failed during benchmark")
    return (perf_counter_ns() - start) / repeats


class Witness:
    def __init__(self):
        self.streams: dict[str, list[list[list[int]]]] = {}

    def put(self, name: str, value: int, *, exponent: bool = False):
        if exponent:
            if not 0 <= value < len(_GPOW):
                raise ValueError(f"exponent out of fixture range: {value}")
            value = _GPOW[value]
        self.streams.setdefault(name, []).append([cell(value)])

    def mod(self, value: int, bound: int) -> int:
        quotient, remainder = divmod(value, Q)
        assert 0 <= quotient < bound
        self.put("remainder", remainder, exponent=True)
        self.put("quotient", quotient, exponent=True)
        return remainder

    def transform(self, data: list[int], inverse: bool = False) -> list[int]:
        if inverse:
            stage = list(data)
        else:
            stage = [self.mod(value * pow(PSI, i, Q), Q) for i, value in enumerate(data)]
        stage = [stage[int(f"{i:09b}"[::-1], 2)] for i in range(N)]
        for level in range(9):
            half = 1 << level
            step = pow(pow(OMEGA, -1, Q) if inverse else OMEGA, N // (2 * half), Q)
            out = [0] * N
            for group in range(N // (2 * half)):
                for j in range(half):
                    lo, hi = group * 2 * half + j, group * 2 * half + j + half
                    u = stage[lo]
                    v = self.mod(stage[hi] * pow(step, j, Q), Q)
                    out[lo] = self.mod(u + v, 2)
                    out[hi] = self.mod(u - v + Q, 2)
            stage = out
        if inverse:
            stage = [self.mod(value * (pow(N, -1, Q) * pow(PSI, -i, Q) % Q), Q) for i, value in enumerate(stage)]
        return stage

    def hash_to_point(self, salt: bytes, message: bytes) -> list[int]:
        seed, out = digest(salt + message), []
        for counter in range(40):
            block = digest(seed + counter.to_bytes(8, "big"))
            for i in range(0, 32, 2):
                if len(out) == N:
                    break
                candidate = int.from_bytes(block[i:i + 2], "big")
                accepted = candidate < 5 * Q
                self.put("accepted", int(accepted))
                if accepted:
                    out.append(self.mod(candidate, 5))
        if len(out) != N:
            raise ValueError("KAT requires more than the guest's 40 Keccak blocks")
        return out

    def signature(self, h: list[int], s2: list[int], salt: bytes, message: bytes):
        for byte in salt + message:
            self.put("salt_msg", byte)
        for value in h:
            self.put("h", value, exponent=True)
        for value in s2:
            self.put("s2", value % Q, exponent=True)
        c = self.hash_to_point(salt, message)
        fh = self.transform(h)
        fs = self.transform([x % Q for x in s2])
        prod = [self.mod(x * y, Q) for x, y in zip(fh, fs)]
        convolution = self.transform(prod, True)
        assert convolution == convolution_schoolbook(h, s2)
        norm = 0
        for challenge, product, sig in zip(c, convolution, s2):
            s0 = self.mod(challenge - product + Q, 2)
            for value in (s0, sig % Q):
                centered = (value + Q // 2) % Q - Q // 2
                self.put("magnitude", abs(centered), exponent=True)
                self.put("negative", int(centered < 0))
                norm += centered * centered
        if norm > BOUND:
            raise ValueError("invalid Falcon signature norm")
        complement = BOUND - norm
        self.put("norm_complement_low", complement % 65536, exponent=True)
        self.put("norm_complement_high", complement // 65536, exponent=True)


def guest_source(messages: list[bytes], initial: bytes) -> str:
    text = (ROOT / "guests/ethfalcon.py").read_text()
    fw, bw = [], []
    for level in range(9):
        half = 1 << level
        for j in range(half):
            fw.append(pow(OMEGA, N * j // (2 * half), Q))
            bw.append(pow(OMEGA, -N * j // (2 * half), Q))
    values = {
        "TWIST_VALUES": [pow(PSI, i, Q) for i in range(N)],
        "UNTWIST_VALUES": [pow(N, -1, Q) * pow(PSI, -i, Q) % Q for i in range(N)],
        "FW_VALUES": fw,
        "BW_VALUES": bw,
        "REV_VALUES": [int(f"{i:09b}"[::-1], 2) for i in range(N)],
        "DOMAIN_VALUE": int.from_bytes(DOMAIN, "little"),
    }
    for key in sorted(values, key=len, reverse=True):
        text = text.replace(key, str(values[key]))
    def specialize_function(template_name, specializations):
        nonlocal text
        match = re.search(r"\ndef " + template_name + r"\(.*?(?=\ndef |\Z)", text, re.S)
        template = match.group(0)
        replacements = []
        for new_name, parameters, bindings in specializations:
            variant = template.replace("def " + template_name, "def " + new_name, 1)
            variant = re.sub(r"\(.*?\):", "(" + parameters + "):", variant, count=1)
            for name, value in bindings.items():
                variant = re.sub(r"\b" + name + r"\b", str(value), variant)
            replacements.append(variant)
        text = text[:match.start()] + "".join(replacements) + text[match.end():]

    lengths = sorted(set(len(m) for m in messages))
    specialize_function("load_bytes", [(f"load_bytes_{40 + n}", "", {"n": 40 + n}) for n in lengths])
    specialize_function("hash_bytes", [(f"hash_bytes_{start}_{size}", "data", {"start": start, "length": size}) for n in lengths for start, size in ((40, n), (0, 40 + n))])
    specialize_function("reduce", [(f"reduce_{bound}", "value", {"bound": bound}) for bound in (2, 5, Q)])
    text = re.sub(r"reduce\((.*?), Q\)", r"reduce_12289(\1)", text)
    text = re.sub(r"reduce\((.*?), 2\)", r"reduce_2(\1)", text)
    text = re.sub(r"reduce\((.*?), 5\)", r"reduce_5(\1)", text)
    acc = [int.from_bytes(initial[i:i + 16], "little") for i in (0, 16)]
    body = [f"acc0 = {acc[0]}", f"acc1 = {acc[1]}"]
    for msg in messages:
        body += [f"data = load_bytes_{40 + len(msg)}()", f"message_hash = hash_bytes_40_{len(msg)}(data)", f"initial = hash_bytes_0_{40 + len(msg)}(data)", "key, key_hash = read_key()", "sig = read_signature()", "verify_signature(initial, key, sig)", "claim = StackBuf(2)", "keccak_cells([DOMAIN, key_hash[0], key_hash[1], message_hash[0], message_hash[1]], claim)", "next = StackBuf(2)", "keccak([acc0, acc1], claim, next)", "acc0 = next[0]", "acc1 = next[1]"]
    body += ["p = GEN ** 0", "p[1] = acc0", "p[GEN] = acc1"]
    return text.replace("    MAIN_BODY", "\n".join("    " + line for line in body))


def build(count: int) -> dict:
    if count <= 0:
        raise ValueError("signature count must be positive")
    vectors = kat_vectors()
    witness, messages, records = Witness(), [], []
    initial = digest(DOMAIN + count.to_bytes(8, "big"))
    accumulator = initial
    native_time = 0.0
    native_c_ns = 0.0
    raw_signature_bytes = key_bytes = message_bytes = 0
    for i in range(count):
        vector = vectors[i % len(vectors)]
        message = bytes.fromhex(vector["msg"])
        encoded_key = bytes.fromhex(vector["pk"])
        h = decode_key(encoded_key)
        sm = bytes.fromhex(vector["sm"])
        salt = sm[2:42]
        compressed = sm[43 + len(message):]
        verify_ns = native_c_timing(sm, encoded_key, message)
        native_c_ns += verify_ns
        s2 = decode_signature(compressed)
        start = perf_counter()
        valid = native_verify(h, s2, salt, message)
        native_time += perf_counter() - start
        if not valid:
            raise ValueError(f"upstream ETHFALCON KAT {vector['count']} failed independent verification")
        witness.signature(h, s2, salt, message)
        key_hash = digest(b"".join(x.to_bytes(2, "little") for x in h))
        message_hash = digest(message)
        claim = digest(DOMAIN + key_hash + message_hash)
        accumulator = digest(accumulator + claim)
        signature_size = 41 + len(compressed)
        raw_signature_bytes += signature_size
        key_bytes += len(encoded_key)
        message_bytes += len(message)
        messages.append(message)
        records.append({"kat": int(vector["count"]), "message_hex": message.hex(), "salt_hex": salt.hex(), "public_key_hex": encoded_key.hex(), "signature_hex": (b"\x29" + salt + compressed).hex(), "key_hash": key_hash.hex(), "message_hash": message_hash.hex(), "claim_hash": claim.hex(), "signature_bytes": signature_size, "native_C_verify_ns": verify_ns})
    return {"scheme": "ethfalcon-512-keccak", "source": guest_source(messages, initial), "witness": witness.streams, "public_input": halves(accumulator), "metadata": {"count": count, "signatures": count, "signature_bytes": raw_signature_bytes, "public_key_bytes": key_bytes, "raw_signature_bytes": raw_signature_bytes, "raw_key_bytes": key_bytes, "encoding": "expanded Falcon-512 relation with canonical uint16 key commitment", "baseline_native_verify_s": native_c_ns / 1e9, "message_bytes": message_bytes, "python_reference_verify_seconds": native_time, "native_verify_ns_per_signature": native_c_ns / count, "native_C_verify_seconds": native_c_ns / 1e9, "native_C_implementation": "pinned upstream ETHFALCON C crypto_sign_open; compressed key/signature decoding and Python ctypes call included", "native_C_flags": NATIVE_C_FLAGS, "native_C_timing_repeats": 30, "native_implementation": "independent Python schoolbook verifier; not an optimized native baseline", "public_key_codec": "512 canonical uint16 little-endian coefficients", "signature_codec": "expanded s2 witness; canonical coefficients abs<=2047 and norm enforced; raw compressed bytes parsed by host; no total payload limit, matching upstream crypto_sign_open", "hash_to_point_block_cap": 40, "parameters": {"degree": N, "modulus": Q, "norm_bound": BOUND, "message_lengths": [len(m) for m in messages]}, "signature_bytes_per_signature": [r["signature_bytes"] for r in records], "records": records, "upstream_kat_sha256": hashlib.sha256((ROOT / "vendor/ETHFALCON/test/ethfalcon512-KAT.rsp").read_bytes()).hexdigest()}}
