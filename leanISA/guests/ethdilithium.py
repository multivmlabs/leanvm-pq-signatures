# Template: assembled by pqbench.dilithium.source; single-file leanVM zkDSL.
from snark_lib import *

COUNT = COUNT_PLACEHOLDER
Q = 8380417
GQ = GEN ** 8380417


def main():
    batch = StackBuf(2)
    # Host replaces these two constants with Keccak(TAG), independent of inputs.
    batch[0] = BATCH_0_PLACEHOLDER
    batch[1] = BATCH_1_PLACEHOLDER
    for index in unroll(0, COUNT):
        key, message = verify_one()
        nxt = StackBuf(2)
        keccak(batch, key, nxt, tail=[message[0], message[1], 0, 0], len=96)
        batch = nxt
    p = GEN ** 0
    p[1] = batch[0]
    p[GEN] = batch[1]
    return


def read_q():
    v = StackBuf(4)
    hint_witness(v, "q")
    assert log(v[0]) < 4096
    assert log(v[1]) < 2048
    assert log(v[2]) < 4096
    assert log(v[3]) < 2048
    x = v[0] * v[1] ** 4096
    y = v[2] * v[3] ** 4096
    assert x * y == GEN ** 8380416
    return x


def bounded17(maximum: Const):
    v = StackBuf(4)
    hint_witness(v, "bounded17")
    assert log(v[0]) < 256
    assert log(v[1]) < 512
    assert log(v[2]) < 256
    assert log(v[3]) < 512
    x = v[0] * v[1] ** 256
    y = v[2] * v[3] ** 256
    assert x * y == GEN ** maximum
    return x


def mod_const(x, factor: Const):
    r = read_q()
    t = read_q()
    assert x ** factor == r * t ** Q
    return r


def mod_mul(x, y):
    bits = StackBuf(23)
    hint_witness(bits, "mul_bits")
    y_exp = 1
    product = 1
    power = x
    for j in unroll(0, 23):
        b = bits[j]
        assert b * b == b
        y_exp = y_exp * (1 + (GEN ** (2 ** j) + 1) * b)
        product = product * (1 + (power + 1) * b)
        power = power * power
    assert y_exp == y
    r = read_q()
    t = read_q()
    assert product == r * t ** Q
    return r


def mod_add(x, y):
    r = read_q()
    b = hint_witness("reduce")
    assert b * b == b
    assert x * y == r * (1 + (GQ + 1) * b)
    return r


def mod_sub(x, y):
    r = read_q()
    b = hint_witness("reduce")
    assert b * b == b
    assert x * GQ == y * r * (1 + (GQ + 1) * b)
    return r


def butterfly_forward(inp, out, start, half: Const, zeta: Const):
    for j in mul_range(1, GEN ** half):
        a = inp[start * j]
        b = inp[start * j * GEN ** half]
        t = mod_const(b, zeta)
        out[start * j] = mod_add(a, t)
        out[start * j * GEN ** half] = mod_sub(a, t)
    return


def butterfly_inverse(inp, out, start, half: Const, zeta: Const):
    for j in mul_range(1, GEN ** half):
        a = inp[start * j]
        b = inp[start * j * GEN ** half]
        out[start * j] = mod_add(a, b)
        difference = mod_sub(a, b)
        out[start * j * GEN ** half] = mod_const(difference, zeta)
    return


NTT_FUNCTIONS_PLACEHOLDER


def format_message(message: StackBuf(2)):
    lo = StackBuf(128)
    hi = StackBuf(128)
    hint_decompose_bits(lo, message[0], 128)
    hint_decompose_bits(hi, message[1], 128)
    raw_lo = 0
    raw_hi = 0
    first = 0
    second = 0
    third = 0
    for j in unroll(0, 128):
        assert lo[j] * lo[j] == lo[j]
        assert hi[j] * hi[j] == hi[j]
        raw_lo = raw_lo + const(2 ** j) * lo[j]
        raw_hi = raw_hi + const(2 ** j) * hi[j]
        if const(j // 112 == 0):
            first = first + const(2 ** (j + 16)) * lo[j]
            second = second + const(2 ** (j + 16)) * hi[j]
        else:
            second = second + const(2 ** (j - 112)) * lo[j]
            third = third + const(2 ** (j - 112)) * hi[j]
    assert raw_lo == message[0]
    assert raw_hi == message[1]
    formatted = StackBuf(3)
    formatted[0] = first
    formatted[1] = second
    formatted[2] = third
    return formatted


def derive_challenge(ctilde: StackBuf(2)):
    state = StackBuf(2)
    keccak(ctilde, [0, 0], state, len=32)
    candidates = HeapBuf(120)
    signs = HeapBuf(39)
    for block in unroll(0, 4):
        output = StackBuf(2)
        keccak(state, [const(block * 72057594037927936), 0], output, len=40)
        for word in unroll(0, 2):
            bits = StackBuf(128)
            hint_decompose_bits(bits, output[word], 128)
            packed = 0
            for j in unroll(0, 128):
                assert bits[j] * bits[j] == bits[j]
                packed = packed + const(2 ** j) * bits[j]
                if const((block * 256 + word * 128 + j) // 39 == 0):
                    signs[GEN ** (block * 256 + word * 128 + j)] = bits[j]
            assert packed == output[word]
            for byte in unroll(0, 16):
                if const((block * 32 + word * 16 + byte) // 8 != 0):
                    exponent = 1
                    for bit in unroll(0, 8):
                        exponent = exponent * (1 + (GEN ** (2 ** bit) + 1) * bits[8 * byte + bit])
                    candidates[GEN ** (block * 32 + word * 16 + byte - 8)] = exponent
    selected = HeapBuf(39)
    counts = HeapBuf(121)
    counts[1] = 1
    used = hint_witness("used")
    assert log(used) < 121
    for p in mul_range(1, used):
        count = counts[p]
        assert log(count) < 39
        boundary = count * GEN ** 217
        candidate = candidates[p]
        take = hint_witness("accept")
        assert take * take == take
        if take == 1:
            assert log(boundary / candidate) < 256
            selected[count] = candidate
            counts[p * GEN] = count * GEN
        else:
            assert log(candidate / (boundary * GEN)) < 256
            counts[p * GEN] = count
    assert counts[used] == GEN ** 39
    current = HeapBuf(256)
    for k in mul_range(1, GEN ** 256):
        current[k] = 1
    for turn in unroll(0, 39):
        nxt = HeapBuf(256)
        chosen = selected[GEN ** turn]
        sign = signs[GEN ** turn]
        signed = GEN + (GEN + GEN ** 8380416) * sign
        for k in mul_range(1, GEN ** 256):
            if k == chosen:
                nxt[k] = signed
            elif k == GEN ** (217 + turn):
                nxt[k] = current[chosen]
            else:
                nxt[k] = current[k]
        current = nxt
    return current


def corrected_high(r, hint):
    r1 = hint_witness("r1")
    assert log(r1) < 44
    sign = hint_witness("r0sign")
    assert sign * sign == sign
    values = StackBuf(3)
    if r1 == 1:
        values[0] = bounded17(95232)
    else:
        if sign == 1:
            values[0] = bounded17(95231)
        else:
            values[0] = bounded17(95232)
    magnitude = values[0]
    if sign == 1:
        assert magnitude != 1
        values[1] = 1 / magnitude
    else:
        values[1] = magnitude
    wrap = hint_witness("wrap")
    assert wrap * wrap == wrap
    assert r1 ** 190464 * values[1] * (1 + (GQ + 1) * wrap) == r
    if hint == 1:
        if sign == 0:
            if magnitude != 1:
                if r1 == GEN ** 43:
                    values[2] = 1
                else:
                    values[2] = r1 * GEN
            else:
                if r1 == 1:
                    values[2] = GEN ** 43
                else:
                    values[2] = r1 / GEN
        else:
            if r1 == 1:
                values[2] = GEN ** 43
            else:
                values[2] = r1 / GEN
    else:
        values[2] = r1
    return values[2]


PACK_FUNCTION_PLACEHOLDER


def verify_one():
    keydata = HeapBuf(5124)
    for i in mul_range(1, GEN ** 5120):
        keydata[i] = read_q()
    tr = StackBuf(4)
    hint_witness(tr, "tr")
    for j in unroll(0, 4):
        keydata[GEN ** (5120 + j)] = tr[j]
    keyhash = StackBuf(2)
    keccak_cells(keydata[0:5124], keyhash)
    message = StackBuf(2)
    hint_witness(message, "message")
    formatted = format_message(message)
    mustate = StackBuf(2)
    keccak_cells([tr[0], tr[1], tr[2], tr[3], formatted[0], formatted[1], formatted[2]], mustate, len=98)
    mu = StackBuf(4)
    keccak(mustate, [0, 0], mu[0:2], len=40)
    keccak(mustate, [72057594037927936, 0], mu[2:4], len=40)
    ctilde = StackBuf(2)
    hint_witness(ctilde, "ctilde")
    c = derive_challenge(ctilde)
    c_hat = ntt(c)
    zhat = HeapBuf(1024)
    for col in unroll(0, 4):
        z = HeapBuf(256)
        for i in mul_range(1, GEN ** 256):
            magnitude = bounded17(130993)
            sign = hint_witness("zsign")
            assert sign * sign == sign
            if sign == 1:
                assert magnitude != 1
                z[i] = GQ / magnitude
            else:
                z[i] = magnitude
        transformed = ntt(z)
        for i in mul_range(1, GEN ** 256):
            zhat[i * GEN ** (col * 256)] = transformed[i]
    hints = HeapBuf(1024)
    sum_hint = 1
    # A runtime loop carries the population count in write-once memory.
    populations = HeapBuf(1025)
    populations[1] = 1
    for i in mul_range(1, GEN ** 1024):
        bit = hint_witness("hint")
        assert bit * bit == bit
        hints[i] = bit
        populations[i * GEN] = populations[i] * (1 + (GEN + 1) * bit)
    assert log(populations[GEN ** 1024]) < 81
    result = HeapBuf(1024)
    for row in unroll(0, 4):
        pointwise = HeapBuf(256)
        for i in mul_range(1, GEN ** 256):
            total = 1
            for col in unroll(0, 4):
                product = mod_mul(keydata[i * GEN ** ((row * 4 + col) * 256)], zhat[i * GEN ** (col * 256)])
                total = mod_add(total, product)
            challenge_product = mod_mul(c_hat[i], keydata[i * GEN ** (4096 + row * 256)])
            pointwise[i] = mod_sub(total, challenge_product)
        coefficients = intt(pointwise)
        for i in mul_range(1, GEN ** 256):
            result[i * GEN ** (row * 256)] = coefficients[i]
    packed_w = pack_w(result, hints)
    challenge_state = StackBuf(2)
    challenge_input = StackBuf(52)
    for j in unroll(0, 4):
        challenge_input[j] = mu[j]
    for j in unroll(0, 48):
        challenge_input[4 + j] = packed_w[j]
    keccak_cells(challenge_input, challenge_state)
    keccak(challenge_state, [0, 0], ctilde, len=40)
    return keyhash, message
