"""ETH-PRNG Dilithium2 native reference and expanded-key leanVM fixtures.

The proving key encoding is deliberately distinct from compressed ML-DSA keys.
All arithmetic inputs are encoded in the exponent of leanVM's GF(2^64)
generator. Native signatures retain their upstream compact wire encoding.
"""
from __future__ import annotations
import ctypes
import contextlib
import os
import sys
import functools
import hashlib
import json
import pathlib
import subprocess
import time
from collections import defaultdict

from Crypto.Hash import keccak

ROOT = pathlib.Path(__file__).resolve().parents[2]
Q = 8380417
GAMMA2 = 95232
MASK64 = (1 << 64) - 1
TAG = b"pq-leanbench/ethdilithium2/v1".ljust(32, b"\0")


def kh(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def gm(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a >> 64:
            a ^= (1 << 64) | 27
    return out


GP = [1]
for _ in range(65536):
    x = GP[-1] << 1
    GP.append((x & MASK64) ^ (27 if x >> 64 else 0))

# Public coefficient encoding used to hash expanded keys. Splitting an exponent
# into two 16-bit limbs avoids thousands of Python field operations per key.
# This changes host preprocessing only, not the guest or its enforced relation.
GP_HIGH = [1]
for _ in range(255):
    GP_HIGH.append(gm(GP_HIGH[-1], GP[65536]))


@functools.lru_cache(maxsize=65536)
def gpow(e: int) -> int:
    if e < 0:
        raise ValueError("coefficient exponent must be nonnegative")
    if e < len(GP):
        return GP[e]
    if e < 1 << 24:
        return gm(GP[e & 65535], GP_HIGH[e >> 16])
    x, out = 2, 1
    while e:
        if e & 1:
            out = gm(out, x)
        x = gm(x, x)
        e >>= 1
    return out


def cell(v: int) -> list[int]:
    return [v & MASK64, (v >> 64) & MASK64, 0]


def ec(v: int) -> list[int]:
    return [gpow(v), 0, 0]


def cells(data: bytes) -> list[list[int]]:
    return [cell(int.from_bytes(data[i:i + 16], "little")) for i in range(0, len(data), 16)]


def raw(cs: list[list[int]]) -> bytes:
    return b"".join((c[0] | (c[1] << 64)).to_bytes(16, "little") for c in cs)


def prng(data: bytes, n: int) -> bytes:
    seed = kh(data)
    return b"".join(kh(seed + i.to_bytes(8, "big")) for i in range((n + 31) // 32))[:n]


NATIVE_BUILD_INFO = {}


def _native():
    src = ROOT / "vendor/ETHDILITHIUM/c-ref"
    names = "sign packing polyvec poly ntt reduce rounding fips202 symmetric-shake keccak_prng keccak256 randombytes".split()
    flags = ["-shared", "-fPIC", "-O3", "-DDILITHIUM_MODE=2", "-DETHDILITHIUM=1"]
    compiler = subprocess.run(["clang", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    source_digest = hashlib.sha256()
    paths = [src / f"{n}.c" for n in names] + sorted(src.glob("*.h"))
    for path in sorted(paths):
        source_digest.update(path.name.encode() + b"\0" + path.read_bytes())
    source_hash = source_digest.hexdigest()
    fingerprint = hashlib.sha256(json.dumps([source_hash, compiler, flags], separators=(",", ":")).encode()).hexdigest()
    dest = ROOT / "build/dilithium" / f"libethdilithium-{fingerprint[:24]}.so"
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["clang", *flags, f"-I{src}", *[str(src / f"{n}.c") for n in names], "-o", str(dest)], check=True)
    NATIVE_BUILD_INFO.clear()
    NATIVE_BUILD_INFO.update({"source_sha256": source_hash, "build_fingerprint": fingerprint, "compiler": compiler, "compile_flags": flags, "ethdilithium_revision": subprocess.run(["git", "-C", str(src.parent), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()})
    return ctypes.CDLL(str(dest))


@contextlib.contextmanager
def _quiet_c_stdout():
    """Hide the reference signer's public-MU debug print, restoring fd 1."""
    libc = ctypes.CDLL(None)
    libc.fflush.argtypes = [ctypes.c_void_p]
    libc.fflush.restype = ctypes.c_int
    sys.stdout.flush()
    libc.fflush(None)
    saved = os.dup(1)
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(sink, 1)
        yield
    finally:
        libc.fflush(None)
        os.dup2(saved, 1)
        os.close(sink)
        os.close(saved)


def native_fixture(message: bytes) -> tuple[bytes, bytes, float]:
    lib = _native()
    pk, sk, sig = ctypes.create_string_buffer(1312), ctypes.create_string_buffer(2560), ctypes.create_string_buffer(2420)
    n = ctypes.c_size_t()
    assert lib.pqcrystals_dilithium2_ref_keypair(pk, sk) == 0
    with _quiet_c_stdout():
        assert lib.pqcrystals_dilithium2_ref_signature(sig, ctypes.byref(n), message, len(message), b"", 0, sk) == 0
    assert n.value == 2420
    return pk.raw, sig.raw, native_verify(pk.raw, message, sig.raw, lib=lib)


def native_verify(pk: bytes, message: bytes, sig: bytes, lib=None) -> float:
    """Validate saved compact inputs and measure the native verifier afresh."""
    if len(pk) != 1312 or len(sig) != 2420 or len(message) != 32:
        raise ValueError("ethDilithium2 replay requires 1312-byte keys, 2420-byte signatures and 32-byte messages")
    if lib is None:
        lib = _native()
    verify = lib.pqcrystals_dilithium2_ref_verify
    start = time.perf_counter_ns()
    for _ in range(30):
        if verify(sig, len(sig), message, len(message), b"", 0, pk) != 0:
            raise ValueError("upstream C verifier rejected the ethDilithium2 input")
    ns = (time.perf_counter_ns() - start) / 30
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    assert verify(bad, len(bad), message, len(message), b"", 0, pk) != 0
    assert verify(sig, len(sig), bytes([message[0] ^ 1]) + message[1:], len(message), b"", 0, pk) != 0
    return ns



ZETAS = [pow(1753, int(f"{i:08b}"[::-1], 2), Q) for i in range(256)]


def ntt(a: list[int]) -> list[int]:
    a = [x % Q for x in a]
    k, length = 0, 128
    while length:
        for start in range(0, 256, length * 2):
            k += 1
            z = ZETAS[k]
            for j in range(start, start + length):
                t = z * a[j + length] % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
        length //= 2
    return a


def intt(a: list[int]) -> list[int]:
    a = a[:]
    k, length = 256, 1
    while length < 256:
        for start in range(0, 256, length * 2):
            k -= 1
            z = -ZETAS[k] % Q
            for j in range(start, start + length):
                x, y = a[j], a[j + length]
                a[j] = (x + y) % Q
                a[j + length] = z * (x - y) % Q
        length *= 2
    inv = pow(256, -1, Q)
    return [x * inv % Q for x in a]


def unpack(pk: bytes, sig: bytes):
    r = int.from_bytes(pk[32:], "little")
    t1 = [[(r >> (10 * (256 * row + j))) & 1023 for j in range(256)] for row in range(4)]
    A = []
    for row in range(4):
        for col in range(4):
            data = prng(pk[:32] + bytes([col, row]), 1200)
            vals = []
            for i in range(0, len(data) - 2, 3):
                x = int.from_bytes(data[i:i + 3], "little") & 0x7fffff
                if x < Q:
                    vals.append(x)
                if len(vals) == 256:
                    break
            assert len(vals) == 256
            A.append(vals)
    zraw = int.from_bytes(sig[32:32 + 2304], "little")
    z = [[131072 - ((zraw >> (18 * (256 * row + j))) & ((1 << 18) - 1)) for j in range(256)] for row in range(4)]
    h = []
    hraw = sig[-84:]
    pos = 0
    for stop in hraw[-4:]:
        assert pos <= stop <= 80
        inds = hraw[pos:stop]
        assert list(inds) == sorted(set(inds))
        h.append([int(j in inds) for j in range(256)])
        pos = stop
    assert not any(hraw[pos:80])
    tr = prng(pk, 64)
    return A, [ntt([x * 8192 for x in p]) for p in t1], tr, z, h


def challenge(seed: bytes):
    data = prng(seed, 128)
    signs = int.from_bytes(data[:8], "little")
    poly = [0] * 256
    used, js, accepted = 0, [], []
    for i in range(217, 256):
        while True:
            j = data[8 + used]
            used += 1
            accepted.append(int(j <= i))
            if j <= i:
                break
        js.append(j)
        poly[i] = poly[j]
        poly[j] = 1 - 2 * (signs & 1)
        signs >>= 1
    return poly, used, js, accepted


def use_hint(h: int, r: int):
    r0 = r % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if r - r0 == Q - 1:
        r1, r0 = 0, r0 - 1
    else:
        r1 = (r - r0) // (2 * GAMMA2)
    w = (r1 + (1 if r0 > 0 else -1)) % 44 if h else r1
    return w, r1, r0


class Recorder:
    def __init__(self):
        self.witness = defaultdict(list)

    def put(self, name, values):
        self.witness[name].append(values)

    def rq(self, v):
        assert 0 <= v < Q
        c = Q - 1 - v
        self.put("q", [ec(v & 4095), ec(v >> 12), ec(c & 4095), ec(c >> 12)])
        return v

    def bound(self, v, maximum):
        assert 0 <= v <= maximum < 131072
        c = maximum - v
        self.put("bounded17", [ec(v & 255), ec(v >> 8), ec(c & 255), ec(c >> 8)])
        return v

    def mc(self, a, b):
        r, t = a * b % Q, a * b // Q
        self.rq(r)
        self.rq(t)
        return r

    def mm(self, a, b):
        self.put("mul_bits", [cell((b >> j) & 1) for j in range(23)])
        return self.mc(a, b)

    def add(self, a, b):
        r = (a + b) % Q
        self.rq(r)
        self.put("reduce", [cell((a + b) // Q)])
        return r

    def sub(self, a, b):
        r = (a - b) % Q
        self.rq(r)
        self.put("reduce", [cell((a + Q - b - r) // Q)])
        return r

    def ntt(self, a):
        a = a[:]
        length, k = 128, 0
        while length:
            nxt = [0] * 256
            for start in range(0, 256, length * 2):
                k += 1
                for j in range(start, start + length):
                    t = self.mc(a[j + length], ZETAS[k])
                    nxt[j] = self.add(a[j], t)
                    nxt[j + length] = self.sub(a[j], t)
            a = nxt
            length //= 2
        return a

    def intt(self, a):
        a = a[:]
        length, k = 1, 256
        while length < 256:
            nxt = [0] * 256
            for start in range(0, 256, length * 2):
                k -= 1
                for j in range(start, start + length):
                    nxt[j] = self.add(a[j], a[j + length])
                    diff = self.sub(a[j], a[j + length])
                    nxt[j + length] = self.mc(diff, -ZETAS[k] % Q)
            a = nxt
            length *= 2
        return [self.mc(x, pow(256, -1, Q)) for x in a]


def _ntt_source(inverse=False):
    lines = [f"def {'intt' if inverse else 'ntt'}(inp):", "    current = inp"]
    length, k = (1, 256) if inverse else (128, 0)
    while (length < 256) if inverse else (length > 0):
        lines.append("    nxt = HeapBuf(256)")
        for start in range(0, 256, length * 2):
            k += -1 if inverse else 1
            z = -ZETAS[k] % Q if inverse else ZETAS[k]
            lines.append(f"    butterfly_{'inverse' if inverse else 'forward'}(current, nxt, GEN ** {start}, {length}, {z})")
        lines.append("    current = nxt")
        length = length * 2 if inverse else length // 2
    if inverse:
        lines.extend(["    result = HeapBuf(256)", "    for i in mul_range(1, GEN ** 256):", f"        result[i] = mod_const(current[i], {pow(256, -1, Q)})", "    return result"])
    else:
        lines.append("    return current")
    return "\n".join(lines)


def _packing_source():
    lines = ["def pack_w(r, hints):", "    packed = StackBuf(48)"]
    # Six bits per coefficient; 64 coefficients occupy exactly three cells.
    for group in range(16):
        for out in range(3):
            lines.append(f"    word_{out} = 0")
        for j in range(64):
            idx = 64 * group + j
            lines += [f"    v = corrected_high(r[GEN ** {idx}], hints[GEN ** {idx}])", "    wb = StackBuf(6)", "    hint_decompose_bits_exponent(wb, v, 6)", "    exponent = 1"]
            for b in range(6):
                out, bit = divmod(j * 6 + b, 128)
                lines += [f"    assert wb[{b}] * wb[{b}] == wb[{b}]", f"    exponent = exponent * (1 + const({gpow(1 << b) ^ 1}) * wb[{b}])", f"    word_{out} = word_{out} + const({1 << bit}) * wb[{b}]"]
            lines.append("    assert exponent == v")
        for out in range(3):
            lines.append(f"    packed[{3 * group + out}] = word_{out}")
    lines.append("    return packed")
    return "\n".join(lines)


def source(count: int) -> str:
    template = (ROOT / "guests/ethdilithium.py").read_text()
    template = template.replace("BATCH_0_PLACEHOLDER", str(int.from_bytes(kh(TAG)[:16], "little"))).replace("BATCH_1_PLACEHOLDER", str(int.from_bytes(kh(TAG)[16:], "little")))
    return template.replace("COUNT_PLACEHOLDER", str(count)).replace("NTT_FUNCTIONS_PLACEHOLDER", _ntt_source() + "\n\n" + _ntt_source(True)).replace("PACK_FUNCTION_PLACEHOLDER", _packing_source())


def build(count: int, records: list[dict] | None = None) -> dict:
    if count < 1:
        raise ValueError("count must be positive")
    if records is not None and len(records) != count:
        raise ValueError("replay record count must match the requested batch count")
    rec = Recorder()
    batch = kh(TAG)
    output_records = []
    total_verify_ns = 0
    for index in range(count):
        if records is None:
            message = hashlib.sha256(f"ethdilithium-wallet-{index}".encode()).digest()
            pk, sig, verify_ns = native_fixture(message)
        else:
            saved = records[index]
            message = bytes.fromhex(saved["message_hex"])
            pk = bytes.fromhex(saved["compact_public_key_hex"])
            sig = bytes.fromhex(saved["compact_signature_hex"])
            verify_ns = native_verify(pk, message, sig)
        total_verify_ns += verify_ns
        A, t1, tr, z, h = unpack(pk, sig)
        for a in A + t1:
            for v in a:
                rec.rq(v)
        rec.put("tr", cells(tr))
        rec.put("message", cells(message))
        rec.put("ctilde", cells(sig[:32]))
        c, used, js, accepted = challenge(sig[:32])
        rec.put("used", [ec(used)])
        for b in accepted:
            rec.put("accept", [cell(b)])
        c_hat = rec.ntt([v % Q for v in c])
        zs = []
        for poly in z:
            zp = []
            for v in poly:
                rec.bound(abs(v), 130993)
                rec.put("zsign", [cell(int(v < 0))])
                zp.append(v % Q)
            zs.append(rec.ntt(zp))
        for hp in h:
            for v in hp:
                rec.put("hint", [cell(v)])
        r_polys = []
        for row in range(4):
            vals = []
            for j in range(256):
                total = 0
                for col in range(4):
                    total = rec.add(total, rec.mm(A[row * 4 + col][j], zs[col][j]))
                vals.append(rec.sub(total, rec.mm(c_hat[j], t1[row][j])))
            r_polys.append(rec.intt(vals))
        w = []
        for row, rs in enumerate(r_polys):
            for j, v in enumerate(rs):
                out, r1, r0 = use_hint(h[row][j], v)
                rec.put("r1", [ec(r1)])
                rec.bound(abs(r0), 95232 if r1 == 0 else 95231 if r0 < 0 else 95232)
                rec.put("r0sign", [cell(int(r0 < 0))])
                rec.put("wrap", [cell(int(r1 == 0 and r0 < 0))])
                w.append(out)
        wp = sum(v << (6 * j) for j, v in enumerate(w)).to_bytes(768, "little")
        mu = prng(tr + b"\0\0" + message, 64)
        assert prng(mu + wp, 32) == sig[:32], "independent Python verification disagrees with upstream C"
        keycells = [ec(v) for p in A + t1 for v in p] + cells(tr)
        keyhash = kh(raw(keycells))
        if records is not None and "expanded_key_hash_hex" in records[index]:
            if records[index]["expanded_key_hash_hex"].lower() != keyhash.hex():
                raise ValueError("saved expanded key hash disagrees with replayed compact key")
        batch = kh(batch + keyhash + message)
        output_records.append({"message_hex": message.hex(), "compact_public_key_hex": pk.hex(), "compact_signature_hex": sig.hex(), "expanded_key_hash_hex": keyhash.hex(), "signature_bytes": len(sig), "compact_key_bytes": len(pk), "expanded_key_encoding_bytes": len(keycells) * 16, "native_verify_ns": verify_ns})
    return {"scheme": "ethdilithium2-expanded-keccak-prng-v1", "source": source(count), "witness": dict(rec.witness), "public_input": cells(batch), "metadata": {"count": count, "raw_signature_bytes": count * 2420, "raw_key_bytes": count * 1312, "raw_expanded_key_bytes": count * 81984, "signature_bytes": count * 2420, "public_key_bytes": count * 1312, "expanded_public_key_bytes": count * 81984, "signature_bytes_per_signature": 2420, "public_key_bytes_per_signature": 1312, "expanded_public_key_bytes_per_signature": 81984, "native_verify_ns_per_signature": total_verify_ns / count, "native_build": dict(NATIVE_BUILD_INFO), "claim_encoding": "Keccak-256 ordered fold of expanded exponent-key hash and 32-byte message", "records": output_records}}


def replay(report: dict) -> dict:
    """Rebuild the exact circuit witness from a saved fixture or benchmark report."""
    expected = "ethdilithium2-expanded-keccak-prng-v1"
    if report.get("scheme", expected) != expected:
        raise ValueError("report does not contain this ethDilithium2 scheme")
    metadata = report.get("metadata", report)
    return build(int(metadata["count"]), records=metadata["records"])


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    fixture = build(a.count)
    pathlib.Path(a.out).write_text(json.dumps(fixture))
    print(json.dumps({"out": a.out, "count": a.count, "entries": sum(map(len, fixture["witness"].values())), "metadata": {k:v for k,v in fixture['metadata'].items() if k != 'records'}}))
