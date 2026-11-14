#!/usr/bin/env python3
"""Independent native parser/memory checks for the fitting standard variant."""
from __future__ import annotations
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
VARIANT = ROOT / "risc-v/experiments/raccoon-crt32"
REFERENCE = ROOT / "vendor/raccoon/ref-c"
SIG = 11524


def main():
    build = HERE / "native-parser-controls"
    build.mkdir(exist_ok=True)
    sources = []
    for name, source in (("old", ROOT / "risc-v/raccoon/c/adapter.c"), ("new", VARIANT / "c/adapter.c")):
        prefix = source.read_text().split("\nint pqbench_raccoon_verify", 1)[0]
        wrapper = f"""
size_t review_decode_{name}(const uint8_t *bytes, uint8_t *output) {{
    racc_sig_t value = {{0}};
    if (!decode_signature(&value, bytes)) return 0;
    memcpy(output, &value, sizeof(value));
    return sizeof(value);
}}
"""
        if name == "new":
            wrapper += """
int review_low40(const uint8_t *bytes, size_t position, uint64_t *value, size_t *after) {
    sig_bits reader = {bytes, position};
    int result = get_low_response(&reader, value);
    *after = reader.position;
    return result;
}
uint64_t review_get64(const uint8_t *bytes) { return get64u_le(bytes); }
void review_put64(uint8_t *bytes, uint64_t value) { put64u_le(bytes,value); }
"""
        path = build / f"{name}.c"
        path.write_text(prefix + wrapper)
        sources.append(path)
    library = build / "controls.dylib"
    command = ["clang", "-O3", "-fno-strict-aliasing", "-fwrapv", "-shared",
               "-include", str(VARIANT / "c/include/plat_local.h"),
               "-I", str(REFERENCE), "-I", str(REFERENCE / "inc"),
               *map(str, sources), "-o", str(library)]
    subprocess.run(command, check=True)
    lib = C.CDLL(str(library))
    for name in ("old", "new"):
        function = getattr(lib, "review_decode_" + name)
        function.argtypes = [C.c_void_p, C.c_void_p]
        function.restype = C.c_size_t
    lib.review_low40.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
    lib.review_get64.argtypes = [C.c_void_p]
    lib.review_get64.restype = C.c_uint64
    lib.review_put64.argtypes = [C.c_void_p, C.c_uint64]
    random_source = random.Random(0x524143434F4F4E)
    inputs = []
    raw = json.loads((ROOT / "risc-v/raccoon/review/fixture-0.json").read_text())
    inputs.append(bytes.fromhex(raw["compact_signature_hex"]))
    for p in sorted((ROOT / "risc-v/raccoon/host/testdata").glob("*.bin")):
        inputs.append(p.read_bytes()[-SIG:])
    baseline = inputs[0]
    # Distributed and boundary bit changes, multi-bit changes and arbitrary
    # malformed inputs. Both successful and failed decoder cases are compared.
    for i in range(1000):
        data = bytearray(baseline)
        for _ in range(1 + i % 5):
            at = random_source.randrange(8 * SIG)
            data[at // 8] ^= 1 << (at % 8)
        inputs.append(bytes(data))
    for index in range(SIG - 8, SIG):
        for bit in range(8):
            data = bytearray(baseline)
            data[index] ^= 1 << bit
            inputs.append(bytes(data))
    inputs += [b"\0" * SIG, b"\xff" * SIG]
    accepted = rejected = 0
    for data in inputs:
        b = C.create_string_buffer(data)
        old, new = C.create_string_buffer(40000), C.create_string_buffer(40000)
        a = lib.review_decode_old(b, old)
        c = lib.review_decode_new(b, new)
        assert a == c and old.raw[:a] == new.raw[:c]
        accepted += bool(a)
        rejected += not bool(a)
    fields = 0
    data = bytes(random_source.getrandbits(8) for _ in range(SIG))
    buffer = C.create_string_buffer(data)
    for position in list(range(8 * 32, 8 * 32 + 128)) + list(range(8 * SIG - 80, 8 * SIG + 1)):
        actual, after = C.c_uint64(), C.c_size_t()
        result = lib.review_low40(buffer, position, C.byref(actual), C.byref(after))
        if position <= 8 * SIG - 40:
            first, shift = divmod(position, 8)
            expected = (int.from_bytes(data[first:first + 6], "little") >> shift) & ((1 << 40) - 1)
            assert result == 1 and actual.value == expected and after.value == position + 40
        else:
            assert result == 0 and after.value == position
        fields += 1
    aligned = 0
    for offset in range(16):
        for _ in range(100):
            original = bytes(random_source.getrandbits(8) for _ in range(64))
            storage = (C.c_uint8 * 64).from_buffer_copy(original)
            address = C.addressof(storage) + offset
            assert lib.review_get64(address) == int.from_bytes(original[offset:offset + 8], "little")
            value = random_source.getrandbits(64)
            lib.review_put64(address, value)
            expected = original[:offset] + value.to_bytes(8, "little") + original[offset + 8:]
            assert bytes(storage) == expected
            aligned += 1
    output = {"schema": 1, "scope": "Independent native old/new decoder and byte-oracle checks, not proof production",
              "decoder_cases": len(inputs), "accepted_decoder_cases": accepted,
              "rejected_decoder_cases": rejected, "bulk40_alignment_boundary_cases": fields,
              "aligned_and_unaligned_load_store_cases": aligned,
              "passed": True, "command": command,
              "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in (ROOT / "risc-v/raccoon/c/adapter.c", VARIANT / "c/adapter.c", VARIANT / "c/include/plat_local.h")}}
    (HERE / "standard-optimized-native-controls.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({k: output[k] for k in ("passed", "decoder_cases", "bulk40_alignment_boundary_cases", "aligned_and_unaligned_load_store_cases")}))


if __name__ == "__main__":
    main()
