#!/usr/bin/env python3
"""Native differential controls for the selected parser and aligned helpers.

No STARK is produced. The oracle is the reviewed original bounded bit decoder,
not the old vendor decoder with its known EOF/padding bugs.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE / "native-controls"
BUILD.mkdir(exist_ok=True)
REF = ROOT / "vendor/raccoon/ref-c"
SIG = 11524
OUT = 32 + 8 * (5 * 512 + 4 * 512)


def library(name, source):
    path = BUILD / (name + ".c")
    path.write_text(source)
    output = BUILD / (name + ".dylib")
    subprocess.run(["clang", "-O3", "-fwrapv", "-fno-strict-aliasing", "-dynamiclib",
                    "-I", str(REF), "-I", str(REF / "inc"), str(path), "-o", str(output)], check=True)
    return ctypes.CDLL(str(output))


def parser(name, path):
    source = path.read_text().split("int pqbench_raccoon_verify(", 1)[0]
    source += "\nint parse_export(const uint8_t *bytes, uint8_t *out) { racc_sig_t s; if (!decode_signature(&s, bytes)) return 0; memcpy(out, &s, sizeof(s)); return 1; }\n"
    loaded = library(name, source)
    function = loaded.parse_export
    function.argtypes = [ctypes.POINTER(ctypes.c_ubyte)] * 2
    function.restype = ctypes.c_int
    return function


old = parser("bitwise", HERE / "c/adapter-bitwise.c")
new = parser("bulk", HERE / "c/adapter.c")
rng = random.Random(0x524143434F4F4E)
checked = accepted = rejected = 0
corpus_hash = hashlib.sha256()


def compare(data):
    global checked, accepted, rejected
    assert len(data) == SIG
    arg = (ctypes.c_ubyte * SIG).from_buffer_copy(data)
    a, b = (ctypes.c_ubyte * OUT)(), (ctypes.c_ubyte * OUT)()
    first, second = old(arg, a), new(arg, b)
    assert first == second, f"acceptance difference at case {checked}"
    if first:
        assert bytes(a) == bytes(b), f"decoded-value difference at case {checked}"
        accepted += 1
    else:
        rejected += 1
    checked += 1
    corpus_hash.update(data)


def encode(hints, responses):
    bits = []
    for value in hints:
        bits.extend([1] * abs(value))
        bits.append(0)
        if value:
            bits.append(int(value < 0))
    for value in responses:
        magnitude = abs(value)
        bits.extend((magnitude >> i) & 1 for i in range(40))
        bits.extend([1] * (magnitude >> 40))
        bits.append(0)
        if value:
            bits.append(int(value < 0))
    assert len(bits) <= (SIG - 32) * 8
    output = bytearray(SIG)
    output[:32] = rng.randbytes(32)
    for i, bit in enumerate(bits):
        output[32 + i // 8] |= bit << (i % 8)
    return bytes(output)


saved = []
for path in (ROOT / "risc-v/raccoon/host/testdata").glob("*.bin"):
    data = path.read_bytes()[2256 + 32:]
    assert len(data) == SIG
    saved.append(data)
    compare(data)
for _ in range(300):
    hints = [rng.choice([0, 0, 0, -1, 1]) for _ in range(5 * 512)]
    responses = [rng.randrange(-(1 << 40), 1 << 40) for _ in range(4 * 512)]
    encoded = encode(hints, responses)
    compare(encoded)
    if len(saved) < 20:
        saved.append(encoded)
for _ in range(2000):
    data = bytearray(rng.choice(saved))
    for _ in range(rng.randrange(1, 5)):
        data[rng.randrange(SIG)] ^= 1 << rng.randrange(8)
    compare(bytes(data))
for _ in range(1000):
    compare(rng.randbytes(SIG))

aligned = library("alignment", f'''#include "{HERE / 'c/include/plat_local.h'}"
uint64_t read_export(const uint8_t *p) {{ return get64u_le(p); }}
void write_export(uint8_t *p, uint64_t x) {{ put64u_le(p,x); }}
''')
aligned.read_export.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
aligned.read_export.restype = ctypes.c_uint64
aligned.write_export.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint64]
alignment_cases = 0
for offset in range(8):
    for _ in range(128):
        value = rng.getrandbits(64)
        data = (ctypes.c_ubyte * 32)(*[0xa5] * 32)
        pointer = ctypes.cast(ctypes.byref(data, 8 + offset), ctypes.POINTER(ctypes.c_ubyte))
        aligned.write_export(pointer, value)
        raw = bytes(data)
        assert raw[:8 + offset] == b"\xa5" * (8 + offset)
        assert raw[8 + offset:16 + offset] == value.to_bytes(8, "little")
        assert raw[16 + offset:] == b"\xa5" * (16 - offset)
        assert aligned.read_export(pointer) == value
        alignment_cases += 1

result = {"schema": 1, "parser_cases": checked, "parser_accepts": accepted,
          "parser_rejects": rejected, "decoded_values_match": True,
          "parser_corpus_sha256": corpus_hash.hexdigest(),
          "alignment_read_write_cases": alignment_cases, "guard_bytes_unchanged": True,
          "scope": "Native correctness differentials only; no STARK or proof benchmark"}
(HERE / "decoder-alignment-controls.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
