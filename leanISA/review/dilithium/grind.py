"""Independent native differentials and recomputed adversarial guest inputs.

Run with PYTHONPATH=python .venv/bin/python review/dilithium/grind.py.
Writes only below review/dilithium; never produces proofs.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import math
import os
import pathlib
import random
import subprocess
import tempfile

from pqbench import dilithium as d

HERE = pathlib.Path(__file__).resolve().parent
RUNNER = d.ROOT / "target/release/pq-leanbench"
Poly = ctypes.c_int32 * 256
REPORT = {}


def provenance():
    paths = ["guests/ethdilithium.py", "python/pqbench/dilithium.py", "build/dilithium/one.json"]
    return {"sha256": {p: hashlib.sha256((d.ROOT/p).read_bytes()).hexdigest() for p in paths},
            "leanvm_revision": subprocess.run(["git", "-C", str(d.ROOT/"vendor/leanVM"),
                                                "rev-parse", "HEAD"], text=True, capture_output=True,
                                               check=True).stdout.strip(),
            "reproduce": "PYTHONPATH=python .venv/bin/python review/dilithium/grind.py",
            "execution_only": True}


def execute(fixture, expected, name):
    with tempfile.TemporaryDirectory(dir=HERE) as tmp:
        path = pathlib.Path(tmp) / "input.json"
        path.write_text(json.dumps(fixture))
        env = {**os.environ, "LEANVM_NUM_THREADS": "1"}
        result = subprocess.run([str(RUNNER), "execute", "--input", str(path)],
                                text=True, capture_output=True, env=env)
    actual = result.returncode == 0
    REPORT[name] = {"accepted": actual, "expected": expected}
    if not actual:
        REPORT[name]["diagnostic"] = (result.stdout + result.stderr)[-1600:]
    assert actual == expected, (name, result.stdout, result.stderr)


def native_differentials(lib):
    rng = random.Random(8288)
    c_ntt = lib.pqcrystals_dilithium2_ref_ntt
    c_intt = lib.pqcrystals_dilithium2_ref_invntt_tomont
    c_challenge = lib.pqcrystals_dilithium2_ref_poly_challenge_eth
    c_uniform = lib.pqcrystals_dilithium2_ref_poly_uniform
    c_prng_init = lib.inner_keccak256_init
    c_prng_inject = lib.inner_keccak256_inject
    c_prng_flip = lib.inner_keccak256_flip
    c_prng_extract = lib.inner_keccak256_extract
    mont = pow(2, 32, d.Q)
    wrong_mont_differences = 0
    for n in range(100):
        values = [rng.randrange(d.Q) for _ in range(256)]
        a = Poly(*values)
        c_ntt(a)
        assert [v % d.Q for v in a] == d.ntt(values)
        a = Poly(*values)
        c_intt(a)
        expected = [v * mont % d.Q for v in d.intt(values)]
        assert [v % d.Q for v in a] == expected
        wrong_mont_differences += [v % d.Q for v in a] != d.intt(values)
        # Full multiplication cancels the inverse transform's Montgomery factor.
        products = [rng.randrange(d.Q) for _ in range(256)]
        c_products = Poly(*[v * pow(mont, -1, d.Q) % d.Q for v in products])
        c_intt(c_products)
        assert [v % d.Q for v in c_products] == d.intt(products)
    assert wrong_mont_differences == 100
    REPORT["ntt"] = {"vectors": 100, "c_forward_matches": True,
                     "c_inverse_matches_with_R": True,
                     "montgomery_cancellation_matches": True,
                     "control_missing_R_differences": wrong_mont_differences}
    seeds = [bytes(32), bytes(range(32)), bytes([255]) * 32]
    seeds += [rng.randbytes(32) for _ in range(509)]
    biggest_used, control_endian_differences = 0, 0
    challenge_polys = []
    for seed in seeds:
        a = Poly()
        c_challenge(a, seed)
        poly, used, _, _ = d.challenge(seed)
        assert list(a) == poly
        assert sum(v != 0 for v in a) == 39
        biggest_used = max(biggest_used, used)
        challenge_polys.append(poly)
        # Predetermined negative control: decoding signs in big endian differs.
        data = d.prng(seed, 128)
        sign_wrong = int.from_bytes(data[:8], "big")
        wrong, pos = [0] * 256, 8
        for i in range(217, 256):
            while data[pos] > i:
                pos += 1
            j, pos = data[pos], pos + 1
            wrong[i], wrong[j] = wrong[j], 1 - 2 * (sign_wrong & 1)
            sign_wrong >>= 1
        control_endian_differences += wrong != poly
    assert control_endian_differences > 500
    REPORT["challenge"] = {"seeds": len(seeds), "max_consumed_candidates": biggest_used,
                           "all_c_polynomials_match": True,
                           "control_big_endian_sign_differences": control_endian_differences}
    # Compare multi-call native PRNG extraction against bytes, independently of
    # poly_challenge's sign/shuffle logic. Oversized aligned buffer avoids any
    # dependency on the private C context's layout.
    for seed in seeds[:20]:
        ctx = (ctypes.c_uint64 * 4096)()
        assert c_prng_init(ctx) == 0
        assert c_prng_inject(ctx, seed, len(seed)) == 0
        assert c_prng_flip(ctx) == 0
        chunks = []
        for n in [8, 64, 1, 91]:
            output = ctypes.create_string_buffer(n)
            assert c_prng_extract(ctx, output, n) == 0
            chunks.append(output.raw)
        assert b"".join(chunks) == d.prng(seed, 164)
    REPORT["prng"] = {"seeds": 20, "chunk_lengths": [8, 64, 1, 91], "all_match": True}
    for seed in seeds[:20]:
        for row, col in [(0, 0), (0, 3), (3, 0), (3, 3)]:
            a = Poly()
            c_uniform(a, seed, row * 256 + col)
            data = d.prng(seed + bytes([col, row]), 1200)
            values = [int.from_bytes(data[i:i+3], "little") & 0x7fffff
                      for i in range(0, 1200, 3)]
            values = [v for v in values if v < d.Q][:256]
            assert list(a) == values
    REPORT["matrix_expand"] = {"vectors": 80, "all_match": True}
    return seeds, challenge_polys


def challenge_guest(seeds, polynomials):
    # Execute the actual derive_challenge function with native-C expected output.
    template = (d.ROOT / "guests/ethdilithium.py").read_text()
    helper = template[template.index("def derive_challenge("):template.index("def corrected_high(")]
    main = ["from snark_lib import *", "Q = 8380417", "GQ = GEN ** 8380417", "def main():",
            "    batch = StackBuf(2)", "    batch[0] = 0", "    batch[1] = 0"]
    witness = {"ctilde": [], "used": [], "accept": []}
    batch = bytes(32)
    for seed, poly in zip(seeds[:10], polynomials[:10]):
        main += ["    seed = StackBuf(2)", '    hint_witness(seed, "ctilde")',
                 "    c = derive_challenge(seed)", "    digest = StackBuf(2)",
                 "    keccak_cells(c[0:256], digest)", "    nxt = StackBuf(2)",
                 "    keccak(batch, digest, nxt)", "    batch = nxt"]
        witness["ctilde"].append(d.cells(seed))
        _, used, _, accepted = d.challenge(seed)
        witness["used"].append([d.ec(used)])
        witness["accept"].extend([[d.cell(v)] for v in accepted])
        digest = d.kh(d.raw([d.ec(v % d.Q) for v in poly]))
        batch = d.kh(batch + digest)
    main += ["    p = GEN ** 0", "    p[1] = batch[0]", "    p[GEN] = batch[1]", "    return"]
    f = {"scheme": "dilithium-review-challenge", "source": "\n".join(main) + "\n\n" + helper,
         "public_input": d.cells(batch), "witness": witness}
    execute(f, True, "challenge_guest_native_outputs_10")
    bad = copy.deepcopy(f)
    bad["witness"]["accept"][0][0][0] ^= 1
    execute(bad, False, "challenge_guest_wrong_accept")
    return f


def primitive_guests():
    template = (d.ROOT / "guests/ethdilithium.py").read_text()
    helper = template[template.index("def read_q("):template.index("NTT_FUNCTIONS_PLACEHOLDER")]

    def fixture(call, value, recorder):
        main = ["from snark_lib import *", "Q = 8380417", "GQ = GEN ** 8380417",
                "def main():", f"    result = {call}", "    p = GEN ** 0",
                "    p[1] = result", "    p[GEN] = 1", "    return"]
        return {"scheme": "dilithium-review-primitives", "source": "\n".join(main)+"\n\n"+helper,
                "public_input": [d.ec(value), d.ec(0)], "witness": dict(recorder.witness)}

    for value in [0, d.Q-1]:
        rec = d.Recorder()
        rec.rq(value)
        execute(fixture("read_q()", value, rec), True, f"read_q_boundary_{value}")
    rec = d.Recorder()
    rec.put("q", [d.ec(d.Q & 4095), d.ec(d.Q >> 12), d.ec(0), d.ec(0)])
    execute(fixture("read_q()", d.Q, rec), False, "read_q_reject_q")
    rec = d.Recorder()
    result = rec.mc(d.Q-1, d.Q-1)
    f = fixture(f"mod_const(GEN ** {d.Q-1}, {d.Q-1})", result, rec)
    execute(f, True, "mod_const_max_product")
    bad_rec = d.Recorder()
    bad_rec.rq(1)
    bad_rec.rq(d.Q-3)  # Valid quotient encoding, wrong integer quotient.
    f["witness"] = dict(bad_rec.witness)
    execute(f, False, "mod_const_wrong_canonical_quotient")
    rec = d.Recorder()
    result = rec.mm(d.Q-1, d.Q-1)
    f = fixture(f"mod_mul(GEN ** {d.Q-1}, GEN ** {d.Q-1})", result, rec)
    execute(f, True, "mod_mul_max_product")
    f["witness"]["mul_bits"][0][22] = [1, 1, 0]
    execute(f, False, "mod_mul_nonbase_boolean_candidate")
    REPORT["integer_lift_bounds"] = {
        "generator_order": 2**64-1,
        "read_q_limb_sum_maximum": 2*(4095+4096*2047),
        "bounded17_limb_sum_maximum": 2*(255+256*511),
        "canonical_product_maximum": (d.Q-1)**2,
        "modular_relation_rhs_maximum": d.Q**2-1,
        "raw_23bit_product_maximum": (d.Q-1)*(2**23-1),
        "highest_repeated_squared_power_exponent": (d.Q-1)*2**23,
        "all_strictly_below_generator_order": True,
    }
    # Exact count of candidate-byte strings still lacking 39 acceptances after
    # 120 draws under independent uniform PRNG bytes. The actual fixed sampler
    # cap is documented, and this is a random-oracle-model estimate only.
    counts = [0]*39
    counts[0] = 1
    for _ in range(120):
        nxt = [0]*39
        for successes, ways in enumerate(counts):
            nxt[successes] += ways*(38-successes)
            if successes < 38:
                nxt[successes+1] += ways*(218+successes)
        counts = nxt
    numerator = sum(counts)
    REPORT["challenge_cap"] = {"candidate_limit": 120,
        "incompleteness_probability_model": "independent uniform candidate bytes",
        "tail_numerator": str(numerator), "tail_denominator_power_2": 960,
        "tail_log2": math.log2(numerator)-960}


def representation_guests(lib):
    template = (d.ROOT / "guests/ethdilithium.py").read_text()
    prefix = "from snark_lib import *\nQ = 8380417\nGQ = GEN ** 8380417\n"
    bounds = template[template.index("def bounded17("):template.index("def mod_const(")]
    rounding = template[template.index("def corrected_high("):template.index("PACK_FUNCTION_PLACEHOLDER")]
    c_decompose = lib.pqcrystals_dilithium2_ref_decompose
    c_hint = lib.pqcrystals_dilithium2_ref_use_hint
    inputs = []
    for high in range(44):
        for low in [-95232, -95231, -1, 0, 1, 95231, 95232]:
            residue = (high*190464+low) % d.Q
            for h in [0, 1]:
                inputs.append((residue, h))
    rec = d.Recorder()
    outputs = []
    for residue, h in inputs:
        native_low = ctypes.c_int32()
        high = c_decompose(ctypes.byref(native_low), residue)
        low = native_low.value
        rec.put("input", [d.ec(residue), d.cell(h)])
        rec.put("r1", [d.ec(high)])
        rec.put("r0sign", [d.cell(int(low < 0))])
        rec.put("wrap", [d.cell(int(high == 0 and low < 0))])
        rec.bound(abs(low), 95232 if high == 0 else 95231 if low < 0 else 95232)
        outputs.append(d.ec(c_hint(residue, h)))
    main = f'''def main():
    outputs = HeapBuf({len(inputs)})
    for k in mul_range(1, GEN ** {len(inputs)}):
        inp = StackBuf(2)
        hint_witness(inp, "input")
        assert inp[1] * inp[1] == inp[1]
        outputs[k] = corrected_high(inp[0], inp[1])
    digest = StackBuf(2)
    keccak_cells(outputs[0:{len(inputs)}], digest)
    p = GEN ** 0
    p[1] = digest[0]
    p[GEN] = digest[1]
    return
'''
    f = {"scheme": "dilithium-review-rounding", "source": prefix+main+bounds+rounding,
         "public_input": d.cells(d.kh(d.raw(outputs))), "witness": dict(rec.witness)}
    execute(f, True, f"rounding_actual_guest_native_boundaries_{len(inputs)}")
    # First residue is Q-GAMMA2, so its valid representation is high=0,
    # low=-GAMMA2, wrap=1. Flipping only wrap tests the independent equation.
    bad = copy.deepcopy(f)
    bad["witness"]["wrap"][0] = [d.cell(0)]
    execute(bad, False, "rounding_actual_guest_wrong_wrap")
    # An exact halfway tie admits high=0,+GAMMA2; the neighboring alternative
    # high=1,-GAMMA2 must fail the strict negative bound.
    tie_rec = AdversarialRecorder()
    tie_rec.put("input", [d.ec(95232), d.cell(0)])
    tie_rec.put("r1", [d.ec(1)])
    tie_rec.put("r0sign", [d.cell(1)])
    tie_rec.put("wrap", [d.cell(0)])
    tie_rec.bound(95232, 95231)
    # Reuse the first iteration, then force the output to native high zero.
    tie_source = main.replace(str(len(inputs)), "1")
    tie = {"scheme": "dilithium-review-rounding-tie", "source": prefix+tie_source+bounds+rounding,
           "public_input": d.cells(d.kh(d.raw([d.ec(0)]))), "witness": dict(tie_rec.witness)}
    execute(tie, False, "rounding_actual_guest_forbidden_negative_tie")
    zero_rec = d.Recorder()
    zero_rec.put("input", [d.ec(0), d.cell(0)])
    zero_rec.put("r1", [d.ec(0)])
    zero_rec.put("r0sign", [d.cell(1)])
    zero_rec.put("wrap", [d.cell(0)])
    zero_rec.bound(0, 95232)
    tie["witness"] = dict(zero_rec.witness)
    execute(tie, False, "rounding_actual_guest_negative_zero")
    # Verify all 256 single-bit message positions plus all-zero/all-one cases.
    # Expected bytes are independent of the DSL's 128-bit cell shuffling.
    messages = [bytes(32), bytes([255])*32]
    messages += [(1 << bit).to_bytes(32, "little") for bit in range(256)]
    formatted_helper = template[template.index("def format_message("):template.index("def derive_challenge(")]
    main = f'''def main():
    outputs = HeapBuf({len(messages)*2})
    for k in mul_range(1, GEN ** {len(messages)}):
        message = StackBuf(2)
        hint_witness(message, "message")
        formatted = format_message(message)
        digest = StackBuf(2)
        keccak_cells(formatted[0:3], digest, len=34)
        outputs[k] = digest[0]
        outputs[k * GEN ** {len(messages)}] = digest[1]
    digest = StackBuf(2)
    keccak_cells(outputs[0:{len(messages)*2}], digest)
    p = GEN ** 0
    p[1] = digest[0]
    p[GEN] = digest[1]
    return
'''
    digests = [d.kh(b"\0\0"+message) for message in messages]
    expected = d.kh(b"".join(v[:16] for v in digests)+b"".join(v[16:] for v in digests))
    f = {"scheme": "dilithium-review-message-format", "source": prefix+main+formatted_helper,
         "public_input": d.cells(expected), "witness": {"message": [d.cells(m) for m in messages]}}
    execute(f, True, "format_message_all_256_single_bits_and_endpoints")
    # Actual generated pack_w against the upstream C byte packer, using all 44
    # high values in every repeating bit/cell alignment over 1024 coefficients.
    rec = d.Recorder()
    inputs = []
    native_packed = bytearray()
    for row in range(4):
        values = [(row*256+j) % 44 for j in range(256)]
        native = ctypes.create_string_buffer(192)
        lib.pqcrystals_dilithium2_ref_polyw1_pack(native, Poly(*values))
        native_packed += native.raw
        for high in values:
            rec.put("pack_input", [d.ec(high*190464)])
            rec.put("r1", [d.ec(high)])
            rec.put("r0sign", [d.cell(0)])
            rec.put("wrap", [d.cell(0)])
            rec.bound(0, 95232)
    main = '''def main():
    r = HeapBuf(1024)
    h = HeapBuf(1024)
    for k in mul_range(1, GEN ** 1024):
        value = hint_witness("pack_input")
        r[k] = value
        h[k] = 0
    packed = pack_w(r, h)
    digest = StackBuf(2)
    keccak_cells(packed[0:48], digest)
    p = GEN ** 0
    p[1] = digest[0]
    p[GEN] = digest[1]
    return
'''
    f = {"scheme": "dilithium-review-packing", "source": prefix+main+bounds+rounding+d._packing_source(),
         "public_input": d.cells(d.kh(bytes(native_packed))), "witness": dict(rec.witness)}
    execute(f, True, "pack_w_actual_guest_all_high_values_native_bytes")


class AdversarialRecorder(d.Recorder):
    def bound(self, value, maximum):
        # An out-of-bound actual value is represented faithfully; a nonnegative
        # complement is supplied so the guest must reject its false bound.
        c = max(0, maximum - value)
        self.put("bounded17", [d.ec(value & 255), d.ec(value >> 8),
                               d.ec(c & 255), d.ec(c >> 8)])
        return value


def decoded_fixture(A, t1, tr, z, h, challenge, message):
    """Recompute every arithmetic/decomposition witness from decoded inputs.

    Native validation and Python's final challenge assertion are intentionally
    bypassed: testing them here would filter out the inputs under examination.
    """
    rec = AdversarialRecorder()
    for poly in A + t1:
        for value in poly:
            rec.rq(value)
    rec.put("tr", d.cells(tr))
    rec.put("message", d.cells(message))
    rec.put("ctilde", d.cells(challenge))
    c, used, _, accepted = d.challenge(challenge)
    rec.put("used", [d.ec(used)])
    for bit in accepted:
        rec.put("accept", [d.cell(bit)])
    c_hat = rec.ntt([v % d.Q for v in c])
    zs = []
    for poly in z:
        for value in poly:
            rec.bound(abs(value), 130993)
            rec.put("zsign", [d.cell(int(value < 0))])
        zs.append(rec.ntt([v % d.Q for v in poly]))
    for poly in h:
        for value in poly:
            rec.put("hint", [d.cell(value)])
    result = []
    for row in range(4):
        values = []
        for j in range(256):
            total = 0
            for col in range(4):
                total = rec.add(total, rec.mm(A[row*4+col][j], zs[col][j]))
            values.append(rec.sub(total, rec.mm(c_hat[j], t1[row][j])))
        result.append(rec.intt(values))
    w = []
    for row, poly in enumerate(result):
        for j, value in enumerate(poly):
            out, high, low = d.use_hint(h[row][j], value)
            rec.put("r1", [d.ec(high)])
            rec.bound(abs(low), 95232 if high == 0 else 95231 if low < 0 else 95232)
            rec.put("r0sign", [d.cell(int(low < 0))])
            rec.put("wrap", [d.cell(int(high == 0 and low < 0))])
            w.append(out)
    packed = sum(v << (6*j) for j, v in enumerate(w)).to_bytes(768, "little")
    computed = d.prng(d.prng(tr+b"\0\0"+message, 64)+packed, 32)
    keyhash = d.kh(d.raw([d.ec(v) for p in A+t1 for v in p] + d.cells(tr)))
    return {"scheme": "dilithium-review-recomputed", "source": d.source(1),
            "witness": dict(rec.witness),
            "public_input": d.cells(d.kh(d.kh(d.TAG)+keyhash+message))}, computed, keyhash


def full_adversarial_inputs(lib):
    saved = json.loads((d.ROOT / "build/dilithium/one.json").read_text())
    record = saved["metadata"]["records"][0]
    pk, sig, message = [bytes.fromhex(record[k]) for k in
                        ["compact_public_key_hex", "compact_signature_hex", "message_hex"]]
    A, t1, tr, z, h = d.unpack(pk, sig)
    c = sig[:32]
    f, expected, _ = decoded_fixture(A, t1, tr, z, h, c, message)
    assert expected == c
    execute(f, True, "full_recomputed_valid")
    altered_z = copy.deepcopy(z)
    altered_z[0][0] += 1
    f, expected, _ = decoded_fixture(A, t1, tr, altered_z, h, c, message)
    assert expected != c
    execute(f, False, "full_recomputed_changed_z")
    altered_h = copy.deepcopy(h)
    altered_h[0][0] ^= 1
    f, expected, _ = decoded_fixture(A, t1, tr, z, altered_h, c, message)
    assert expected != c
    execute(f, False, "full_recomputed_changed_h")
    changed_message = bytes([message[0] ^ 1]) + message[1:]
    f, expected, _ = decoded_fixture(A, t1, tr, z, h, c, changed_message)
    assert expected != c
    execute(f, False, "full_recomputed_changed_message")
    changed_c = bytes([c[0] ^ 1]) + c[1:]
    f, expected, _ = decoded_fixture(A, t1, tr, z, h, changed_c, message)
    assert expected != changed_c
    execute(f, False, "full_recomputed_changed_challenge")
    bad_tr = copy.deepcopy(saved)
    bad_tr["witness"]["tr"][0][0][2] = 1
    execute(bad_tr, False, "full_tr_third_limb")
    # Fixed zero expanded key: no signing secret is needed. This is expected
    # under the declared expanded-key relation, and a consumer registration test.
    zeros = [[0]*256 for _ in range(4)]
    zeroA = [[0]*256 for _ in range(16)]
    tr0 = bytes(range(64))
    for index, msg in enumerate([message, changed_message]):
        seed = d.prng(d.prng(tr0+b"\0\0"+msg, 64)+bytes(768), 32)
        forged, computed, keyhash = decoded_fixture(zeroA, zeros, tr0, zeros, zeros, seed, msg)
        assert computed == seed
        assert keyhash.hex() != record["expanded_key_hash_hex"]
        execute(forged, True, f"arbitrary_zero_expanded_key_message_{index}")
        # Canonically pack the decoded signature; the original compact key must
        # reject it. This explicitly bounds the demonstrated security bridge.
        zbytes = sum(131072 << (18*j) for j in range(1024)).to_bytes(2304, "little")
        wire = seed+zbytes+bytes(84)
        assert lib.pqcrystals_dilithium2_ref_verify(wire, len(wire), msg, len(msg), b"", 0, pk) != 0
    REPORT["expanded_key_boundary"] = {"zero_expanded_key_allows_secretless_signing": True,
        "original_compact_key_rejects_both": True,
        "requires_authorizing_different_expanded_digest": True,
        "classification": "expected relation boundary; not an honest-key forgery"}
    # With zero A,t1 all z are irrelevant to the hash, so the valid neighbor and
    # norm failures separate range constraints from challenge failures.
    seed = d.prng(d.prng(tr0+b"\0\0"+message, 64)+bytes(768), 32)
    for value, accept in [(130993, True), (-130993, True), (130994, False), (-130994, False)]:
        norm_z = copy.deepcopy(zeros)
        norm_z[0][0] = value
        f, computed, _ = decoded_fixture(zeroA, zeros, tr0, norm_z, zeros, seed, message)
        assert computed == seed
        execute(f, accept, f"recomputed_z_norm_{value}")
    for population, accept in [(80, True), (81, False)]:
        population_h = copy.deepcopy(zeros)
        population_h[0][:population] = [1]*population
        high = [43]*population + [0]*(1024-population)
        packed = sum(v << (6*j) for j, v in enumerate(high)).to_bytes(768, "little")
        seed = d.prng(d.prng(tr0+b"\0\0"+message, 64)+packed, 32)
        f, computed, _ = decoded_fixture(zeroA, zeros, tr0, zeros, population_h, seed, message)
        assert computed == seed
        execute(f, accept, f"recomputed_hint_population_{population}")


def main():
    REPORT["provenance"] = provenance()
    src = d.ROOT / "vendor/ETHDILITHIUM/c-ref"
    binary = HERE / "rounding_exhaustive"
    subprocess.run(["clang", "-O2", "-DDILITHIUM_MODE=2", "-DETHDILITHIUM=1",
                    f"-I{src}", str(HERE / "rounding_exhaustive.c"), str(src / "rounding.c"),
                    "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
    REPORT["rounding_exhaustive"] = json.loads(result.stdout)
    lib = d._native()
    REPORT["native_build"] = d.NATIVE_BUILD_INFO.copy()
    seeds, polys = native_differentials(lib)
    challenge_guest(seeds, polys)
    primitive_guests()
    representation_guests(lib)
    full_adversarial_inputs(lib)
    (HERE / "report.json").write_text(json.dumps(REPORT, indent=2)+"\n")
    print(json.dumps(REPORT, indent=2))


if __name__ == "__main__":
    main()
