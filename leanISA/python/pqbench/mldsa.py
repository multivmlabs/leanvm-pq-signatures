"""FIPS 204 ML-DSA-44 with SHAKE and registered expanded verification keys.

The VM proves the ML-DSA verification relation over a 32-byte message and empty
context. Compact-key expansion and compact-signature decoding happen on the host;
the authorized key identity is the expanded-key digest, exactly as in the ETH
comparison guest. No signing secret is included in a fixture.
"""
from __future__ import annotations
import argparse
import ctypes
import functools
import hashlib
import json
import pathlib
import subprocess
import time

from . import dilithium as d
from . import shake

ROOT = d.ROOT
Q = d.Q
GAMMA2 = d.GAMMA2
TAG = b"pq-leanbench/mldsa44-fips204/v1".ljust(32, b"\0")
SCHEME = "mldsa44-fips204-shake-expanded-v1"
SAMPLE_BYTES = 136
kh, cells, raw, ec, cell = d.kh, d.cells, d.raw, d.ec, d.cell
ntt, intt, use_hint, Recorder = d.ntt, d.intt, d.use_hint, d.Recorder
NATIVE_BUILD_INFO = {}


@functools.lru_cache(maxsize=1)
def _native():
    src = ROOT / "vendor/ETHDILITHIUM/c-ref"
    names = "sign packing polyvec poly ntt reduce rounding fips202 symmetric-shake keccak_prng keccak256 randombytes".split()
    flags = ["-shared", "-fPIC", "-O3", "-DDILITHIUM_MODE=2", "-DETHDILITHIUM=0"]
    compiler = subprocess.run(["clang", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    # ACVP sigVer vectors exercise the internal verification algorithm, whose
    # message is already formatted. Expose a host-only copy of the pinned C
    # verifier with only its external 00||ctxlen||ctx prefix absorption removed.
    # Production fixtures always use the original public C entry point.
    text = (src / "sign.c").read_text()
    begin = text.index("int crypto_sign_verify(")
    body = text[begin:text.index("/*************************************************", begin)]
    body = body.replace("int crypto_sign_verify(", "int pqbench_mldsa44_verify_internal(", 1)
    body = body.replace("  shake256_absorb(&state, mu, 2);", "")
    body = body.replace("  shake256_absorb(&state, ctx, ctxlen);", "")
    header = text[:text.index("/*************************************************")]
    kat_source = "/* Test adapter derived from pinned c-ref/sign.c; see vendor/ETHDILITHIUM/LICENSE. */\n" + header + body
    source_digest = hashlib.sha256()
    paths = [src / f"{n}.c" for n in names] + sorted(src.glob("*.h"))
    for path in sorted(paths):
        source_digest.update(path.name.encode() + b"\0" + path.read_bytes())
    source_digest.update(b"acvp_internal_adapter\0" + kat_source.encode())
    source_hash = source_digest.hexdigest()
    fingerprint = hashlib.sha256(json.dumps([source_hash, compiler, flags], separators=(",", ":")).encode()).hexdigest()
    dest = ROOT / "build/mldsa" / f"libmldsa44-{fingerprint[:24]}.so"
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        adapter = dest.with_suffix(".acvp.c")
        adapter.write_text(kat_source)
        subprocess.run(["clang", *flags, f"-I{src}", *[str(src / f"{n}.c") for n in names], str(adapter), "-o", str(dest)], check=True)
    NATIVE_BUILD_INFO.update({"source_sha256": source_hash, "build_fingerprint": fingerprint, "compiler": compiler, "compile_flags": flags,
        "ethdilithium_revision": subprocess.run(["git", "-C", str(src.parent), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip(),
        "production_entry_point": "pqcrystals_dilithium2_ref_verify", "kat_adapter": "internal FIPS204 ACVP interface only"})
    return ctypes.CDLL(str(dest))


def native_accepts(pk: bytes, message: bytes, sig: bytes, *, internal=False) -> bool:
    if len(pk) != 1312 or len(sig) != 2420:
        return False
    lib = _native()
    fn = lib.pqbench_mldsa44_verify_internal if internal else lib.pqcrystals_dilithium2_ref_verify
    return fn(sig, len(sig), message, len(message), b"", 0, pk) == 0


def native_verify(pk: bytes, message: bytes, sig: bytes, lib=None) -> float:
    if len(pk) != 1312 or len(sig) != 2420 or len(message) != 32:
        raise ValueError("ML-DSA-44 fixtures require 1312-byte keys, 2420-byte signatures and 32-byte messages")
    if lib is None:
        lib = _native()
    verify = lib.pqcrystals_dilithium2_ref_verify
    start = time.perf_counter_ns()
    for _ in range(30):
        if verify(sig, len(sig), message, len(message), b"", 0, pk) != 0:
            raise ValueError("upstream SHAKE C verifier rejected the ML-DSA-44 input")
    return (time.perf_counter_ns() - start) / 30


def native_fixture(message: bytes) -> tuple[bytes, bytes, float]:
    record = _generate_native(message)
    return bytes.fromhex(record["compact_public_key_hex"]), bytes.fromhex(record["compact_signature_hex"]), record["native_verify_ns"]


def _generate_native(message: bytes) -> dict:
    lib = _native()
    pk, sk, sig = ctypes.create_string_buffer(1312), ctypes.create_string_buffer(2560), ctypes.create_string_buffer(2420)
    n = ctypes.c_size_t()
    start = time.perf_counter_ns()
    if lib.pqcrystals_dilithium2_ref_keypair(pk, sk) != 0:
        raise ValueError("ML-DSA-44 key generation failed")
    keygen_ns = time.perf_counter_ns() - start
    with d._quiet_c_stdout():
        start = time.perf_counter_ns()
        status = lib.pqcrystals_dilithium2_ref_signature(sig, ctypes.byref(n), message, len(message), b"", 0, sk)
        sign_ns = time.perf_counter_ns() - start
    if status != 0 or n.value != 2420:
        raise ValueError("ML-DSA-44 signing failed")
    verify_ns = native_verify(pk.raw, message, sig.raw, lib)
    if not verify_python(pk.raw, message, sig.raw):
        raise ValueError("independent SHAKE Python verification disagrees with C")
    return {"message_hex": message.hex(), "compact_public_key_hex": pk.raw.hex(), "compact_signature_hex": sig.raw.hex(),
            "expanded_key_hash_hex": key_identity(pk.raw).hex(), "native_verify_ns": verify_ns,
            "native_keygen_ns": keygen_ns, "native_sign_ns": sign_ns}


def generate_record(index: int) -> dict:
    if index < 0:
        raise ValueError("record index must be nonnegative")
    record = _generate_native(hashlib.sha256(f"mldsa44-wallet-{index}".encode()).digest())
    record["index"] = index
    return record


def expand_public_key(pk: bytes):
    if len(pk) != 1312:
        raise ValueError("ML-DSA-44 compact public key must contain 1312 bytes")
    packed = int.from_bytes(pk[32:], "little")
    t1 = [[(packed >> (10 * (256 * row + j))) & 1023 for j in range(256)] for row in range(4)]
    matrix = []
    for row in range(4):
        for col in range(4):
            data = hashlib.shake_128(pk[:32] + bytes([col, row])).digest(1200)
            values = []
            for offset in range(0, len(data) - 2, 3):
                value = int.from_bytes(data[offset:offset + 3], "little") & 0x7fffff
                if value < Q:
                    values.append(value)
                if len(values) == 256:
                    break
            if len(values) != 256:
                raise ValueError("host matrix-expansion buffer exhausted")
            matrix.append(values)
    return matrix, [ntt([value * 8192 for value in poly]) for poly in t1], hashlib.shake_256(pk).digest(64)


def unpack(pk: bytes, sig: bytes):
    if len(sig) != 2420:
        raise ValueError("ML-DSA-44 compact signature must contain 2420 bytes")
    matrix, t1, tr = expand_public_key(pk)
    packed = int.from_bytes(sig[32:2336], "little")
    z = [[131072 - ((packed >> (18 * (256 * row + j))) & ((1 << 18) - 1)) for j in range(256)] for row in range(4)]
    hints, pos = [], 0
    tail = sig[-84:]
    for stop in tail[-4:]:
        if not pos <= stop <= 80:
            raise ValueError("noncanonical hint endpoints")
        indices = tail[pos:stop]
        if list(indices) != sorted(set(indices)):
            raise ValueError("noncanonical hint indices")
        hints.append([int(j in indices) for j in range(256)])
        pos = stop
    if any(tail[pos:80]):
        raise ValueError("nonzero hint padding")
    return matrix, t1, tr, z, hints


def challenge(seed: bytes):
    if len(seed) != 32:
        raise ValueError("ML-DSA-44 challenge seed must contain 32 bytes")
    data = hashlib.shake_256(seed).digest(SAMPLE_BYTES)
    signs = int.from_bytes(data[:8], "little")
    poly = [0] * 256
    used, selected, accepted = 0, [], []
    for boundary in range(217, 256):
        while True:
            if used >= len(data) - 8:
                raise ValueError("ML-DSA-44 guest SampleInBall completeness cap exhausted")
            candidate = data[8 + used]
            used += 1
            accepted.append(int(candidate <= boundary))
            if candidate <= boundary:
                break
        selected.append(candidate)
        poly[boundary] = poly[candidate]
        poly[candidate] = 1 - 2 * (signs & 1)
        signs >>= 1
    return poly, used, selected, accepted


def verify_python(pk: bytes, message: bytes, sig: bytes, *, internal=False) -> bool:
    try:
        matrix, t1, tr, z, hints = unpack(pk, sig)
        if any(abs(value) >= 130994 for poly in z for value in poly):
            return False
        c_hat = ntt(challenge(sig[:32])[0])
        z_hat = [ntt(poly) for poly in z]
        w = []
        for row in range(4):
            products = [(sum(matrix[row * 4 + col][j] * z_hat[col][j] for col in range(4)) - c_hat[j] * t1[row][j]) % Q for j in range(256)]
            w.extend(use_hint(hints[row][j], value)[0] for j, value in enumerate(intt(products)))
        encoded_w = sum(value << (6 * j) for j, value in enumerate(w)).to_bytes(768, "little")
        mu = hashlib.shake_256(tr + (b"" if internal else b"\0\0") + message).digest(64)
        return hashlib.shake_256(mu + encoded_w).digest(32) == sig[:32]
    except (ValueError, IndexError):
        return False


@functools.lru_cache(maxsize=512)
def key_identity(pk: bytes) -> bytes:
    matrix, t1, tr = expand_public_key(pk)
    return kh(raw([ec(value) for poly in matrix + t1 for value in poly] + cells(tr)))


def public_claim(record: dict) -> dict:
    pk = bytes.fromhex(record.get("compact_public_key_hex", record.get("public_key_hex", "")))
    message = bytes.fromhex(record["message_hex"])
    if len(message) != 32:
        raise ValueError("ML-DSA-44 public message must contain 32 bytes")
    return {"compact_public_key_hex": pk.hex(), "message_hex": message.hex(), "expanded_key_hash_hex": key_identity(pk).hex()}


def expected_public_input(public_records: list[dict]):
    if not public_records:
        raise ValueError("at least one public claim is required")
    batch = kh(TAG)
    for record in public_records:
        claim = public_claim(record)
        batch = kh(batch + bytes.fromhex(claim["expanded_key_hash_hex"]) + bytes.fromhex(claim["message_hex"]))
    return cells(batch)


_WORD_HELPERS = """
def unpack_words(inp, count: Const):
    result = HeapBuf(GEN ** (count * 16))
    for i in mul_range(1, GEN ** count):
        shake_unpack_word(inp[i], result, i ** 16)
    return result


def pack_words(inp, count: Const):
    result = HeapBuf(GEN ** count)
    for i in mul_range(1, GEN ** count):
        packed = 0
        for j in unroll(0, 16):
            byte = inp[i ** 16 * GEN ** j]
            packed = packed + const(2 ** (8 * j)) * byte
        result[i] = packed
    return result
"""


def source(count: int) -> str:
    if count < 1:
        raise ValueError("count must be positive")
    template = (ROOT / "guests/mldsa.py").read_text()
    helpers = shake.dsl_helpers() + _WORD_HELPERS
    helpers += shake.dsl_function("mldsa_mu", 98, 64)
    helpers += shake.dsl_function("mldsa_challenge_stream", 32, SAMPLE_BYTES)
    helpers += shake.dsl_function("mldsa_hash_challenge", 832, 32)
    template = template.replace("SHAKE_FUNCTIONS_PLACEHOLDER", helpers)
    template = template.replace("BATCH_0_PLACEHOLDER", str(int.from_bytes(kh(TAG)[:16], "little"))).replace("BATCH_1_PLACEHOLDER", str(int.from_bytes(kh(TAG)[16:], "little")))
    return template.replace("COUNT_PLACEHOLDER", str(count)).replace("NTT_FUNCTIONS_PLACEHOLDER", d._ntt_source() + "\n\n" + d._ntt_source(True)).replace("PACK_FUNCTION_PLACEHOLDER", d._packing_source())


def _build(count: int, records: list[dict]) -> dict:
    if count < 1:
        raise ValueError("count must be positive")
    if records is not None and len(records) != count:
        raise ValueError("replay record count must match the requested batch count")
    rec = Recorder()
    batch = kh(TAG)
    output_records = []
    total_verify_ns = 0
    for index in range(count):
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
        mu = hashlib.shake_256(tr + b"\0\0" + message).digest(64)
        assert hashlib.shake_256(mu + wp).digest(32) == sig[:32], "independent Python verification disagrees with upstream C"
        keycells = [ec(v) for p in A + t1 for v in p] + cells(tr)
        keyhash = kh(raw(keycells))
        if records is not None and "expanded_key_hash_hex" in records[index]:
            if records[index]["expanded_key_hash_hex"].lower() != keyhash.hex():
                raise ValueError("saved expanded key hash disagrees with replayed compact key")
        batch = kh(batch + keyhash + message)
        output_records.append({"message_hex": message.hex(), "compact_public_key_hex": pk.hex(), "compact_signature_hex": sig.hex(), "expanded_key_hash_hex": keyhash.hex(), "signature_bytes": len(sig), "compact_key_bytes": len(pk), "expanded_key_encoding_bytes": len(keycells) * 16, "native_verify_ns": verify_ns, **{k: records[index][k] for k in ("index", "native_keygen_ns", "native_sign_ns") if k in records[index]}})
    return {"scheme": SCHEME, "source": source(count), "witness": dict(rec.witness), "public_input": cells(batch), "metadata": {"count": count, "raw_signature_bytes": count * 2420, "raw_key_bytes": count * 1312, "raw_expanded_key_bytes": count * 81984, "signature_bytes": count * 2420, "public_key_bytes": count * 1312, "expanded_public_key_bytes": count * 81984, "signature_bytes_per_signature": 2420, "public_key_bytes_per_signature": 1312, "expanded_public_key_bytes_per_signature": 81984, "native_verify_ns_per_signature": total_verify_ns / count, "native_build": dict(NATIVE_BUILD_INFO), "claim_encoding": "Keccak-256 ordered fold of expanded exponent-key hash and 32-byte message", "standard": "FIPS 204 ML-DSA-44 (pure, empty context)", "key_model": "registered expanded verification key; compact expansion checked only by host", "sample_in_ball_output_bytes": SAMPLE_BYTES, "sample_in_ball_candidate_cap": SAMPLE_BYTES - 8, "records": output_records}}



def build_records(records: list[dict]) -> dict:
    """Build exactly the supplied records, without padding or duplication."""
    return _build(len(records), records)


def build(count: int, records: list[dict] | None = None) -> dict:
    if count < 1:
        raise ValueError("count must be positive")
    if records is not None and len(records) != count:
        raise ValueError("replay record count must match requested batch count")
    return build_records([generate_record(i) for i in range(count)] if records is None else records)


def replay(report: dict) -> dict:
    if report.get("scheme", SCHEME) != SCHEME:
        raise ValueError("report does not contain the FIPS 204 ML-DSA-44 relation")
    metadata = report.get("metadata", report)
    return build(int(metadata["count"]), metadata["records"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    fixture = build(args.count)
    pathlib.Path(args.out).write_text(json.dumps(fixture))
    print(json.dumps({"out": args.out, "count": args.count, "scheme": SCHEME}))
