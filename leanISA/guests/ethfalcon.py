from snark_lib import *

Q = 12289
N = 512
BLOCKS = 40
TWIST = TWIST_VALUES
UNTWIST = UNTWIST_VALUES
FW = FW_VALUES
BW = BW_VALUES
REV = REV_VALUES
DOMAIN = DOMAIN_VALUE


def main():
    MAIN_BODY
    return


def load_bytes(n: Const):
    data = HeapBuf(n)
    for i in mul_range(1, GEN ** n):
        value = hint_witness("salt_msg")
        bits = StackBuf(8)
        hint_decompose_bits(bits, value, 8)
        check = 0
        for j in unroll(0, 8):
            b = bits[j]
            bits[j] = b * b
            check = check + b * const(2 ** j)
        assert check == value
        data[i] = value
    return data


def hash_bytes(data, start: Const, length: Const):
    words = StackBuf((length + 15) // 16)
    for w in unroll(0, (length + 15) // 16):
        packed = 0
        for j in unroll(0, 16):
            if const((w * 16 + j) // length) == 0:
                packed = packed + data[GEN ** (start + w * 16 + j)] * const(2 ** (8 * j))
        words[w] = packed
    out = StackBuf(2)
    if length == 0:
        keccak_cells([0], out, len=0)
    else:
        keccak_cells(words, out, len=length)
    return out


def raw_exponent(value):
    bits = StackBuf(14)
    hint_decompose_bits_exponent(bits, value, 14)
    exponent = 1
    raw = 0
    for j in unroll(0, 14):
        b = bits[j]
        bits[j] = b * b
        exponent = exponent * (1 + b * (GEN ** (2 ** j) + 1))
        raw = raw + b * const(2 ** j)
    assert value == exponent
    return raw


def read_key():
    h = HeapBuf(N)
    raw = HeapBuf(N)
    for i in mul_range(1, GEN ** N):
        value = hint_witness("h")
        assert log(value) < Q
        h[i] = value
        raw[i] = raw_exponent(value)
    words = StackBuf(64)
    for w in unroll(0, 64):
        packed = 0
        for j in unroll(0, 8):
            packed = packed + raw[GEN ** (8 * w + j)] * const(2 ** (16 * j))
        words[w] = packed
    digest = StackBuf(2)
    keccak_cells(words, digest)
    return h, digest


def read_signature():
    sig = HeapBuf(N)
    for i in mul_range(1, GEN ** N):
        value = hint_witness("s2")
        assert log(value) < Q
        sig[i] = value
    return sig


def reduce(value, bound: Const):
    rem = hint_witness("remainder")
    quo = hint_witness("quotient")
    assert log(rem) < Q
    assert log(quo) < log(GEN ** bound)
    assert value == rem * quo ** Q
    return rem


def mul_const(value, scalar: Const):
    return reduce(value ** scalar, Q)


def mul_mod(a, b):
    bits = StackBuf(14)
    hint_decompose_bits_exponent(bits, b, 14)
    exp = 1
    product = 1
    power = a
    for j in unroll(0, 14):
        bit = bits[j]
        bits[j] = bit * bit
        exp = exp * (1 + bit * (GEN ** (2 ** j) + 1))
        product = product * (1 + bit * (power + 1))
        power = power * power
    assert exp == b
    return reduce(product, Q)


def transform(data, inverse: Const):
    twisted = HeapBuf(N)
    for j in unroll(0, N):
        if inverse == 0:
            twisted[GEN ** j] = mul_const(data[GEN ** j], TWIST[j])
        else:
            twisted[GEN ** j] = data[GEN ** j]
    stage = HeapBuf(N)
    for j in unroll(0, N):
        stage[GEN ** j] = twisted[GEN ** REV[j]]
    for level in unroll(0, 9):
        nxt = HeapBuf(N)
        for group in unroll(0, N // (2 ** (level + 1))):
            for j in unroll(0, 2 ** level):
                lo = const(group * (2 ** (level + 1)) + j)
                hi = const(group * (2 ** (level + 1)) + j + 2 ** level)
                u = stage[GEN ** lo]
                if inverse == 0:
                    v = mul_const(stage[GEN ** hi], FW[(2 ** level) - 1 + j])
                else:
                    v = mul_const(stage[GEN ** hi], BW[(2 ** level) - 1 + j])
                nxt[GEN ** lo] = reduce(u * v, 2)
                nxt[GEN ** hi] = reduce(u / v * GEN ** Q, 2)
        stage = nxt
    if inverse == 1:
        out = HeapBuf(N)
        for j in unroll(0, N):
            out[GEN ** j] = mul_const(stage[GEN ** j], UNTWIST[j])
        return out
    return stage


def digest_bits(word):
    bits = StackBuf(128)
    hint_decompose_bits(bits, word, 128)
    raw = 0
    for j in unroll(0, 128):
        b = bits[j]
        bits[j] = b * b
        raw = raw + b * const(2 ** j)
    assert raw == word
    return bits


def take_candidate(candidate, index, point):
    next_index = StackBuf(1)
    if index == GEN ** N:
        next_index[0] = index
    else:
        accepted = hint_witness("accepted")
        if accepted == 1:
            assert log(candidate) < 61445
            value = reduce(candidate, 5)
            point[index] = value
            next_index[0] = index * GEN
        else:
            assert accepted == 0
            assert log(candidate / GEN ** 61445) < 4091
            next_index[0] = index
    return next_index[0]


def sample_block(initial0, initial1, block, index, point):
    counter_bits = StackBuf(6)
    hint_decompose_bits_exponent(counter_bits, block, 6)
    exponent = 1
    counter = 0
    for j in unroll(0, 6):
        b = counter_bits[j]
        counter_bits[j] = b * b
        exponent = exponent * (1 + b * (GEN ** (2 ** j) + 1))
        counter = counter + b * const(2 ** (j + 56))
    assert exponent == block
    digest = StackBuf(2)
    keccak_cells([initial0, initial1, counter], digest, len=40)
    first = digest_bits(digest[0])
    second = digest_bits(digest[1])
    for pair in unroll(0, 8):
        candidate = candidate_word(first, pair)
        index = take_candidate(candidate, index, point)
    for pair in unroll(0, 8):
        candidate = candidate_word(second, pair)
        index = take_candidate(candidate, index, point)
    return index


def candidate_word(bits: StackBuf(128), pair: Const):
    candidate = 1
    for j in unroll(0, 8):
        low = bits[pair * 16 + 8 + j]
        high = bits[pair * 16 + j]
        candidate = candidate * (1 + low * (GEN ** (2 ** j) + 1))
        candidate = candidate * (1 + high * (GEN ** (2 ** (j + 8)) + 1))
    return candidate


def hash_to_point(initial: StackBuf(2)):
    point = HeapBuf(N)
    indices = HeapBuf(BLOCKS + 1)
    indices[1] = 1
    first = initial[0]
    second = initial[1]
    for b in mul_range(1, GEN ** BLOCKS):
        indices[b * GEN] = sample_block(first, second, b, indices[b], point)
    assert indices[GEN ** BLOCKS] == GEN ** N
    return point


def centered_square(value, signature: Const):
    magnitude = hint_witness("magnitude")
    negative = hint_witness("negative")
    if signature == 1:
        assert log(magnitude) < 2048
    else:
        assert log(magnitude) < 6145
    assert negative * negative == negative
    assert value == magnitude + negative * (magnitude + GEN ** Q / magnitude)
    bits = StackBuf(13)
    hint_decompose_bits_exponent(bits, magnitude, 13)
    exp = 1
    square = 1
    power = magnitude
    for j in unroll(0, 13):
        b = bits[j]
        bits[j] = b * b
        exp = exp * (1 + b * (GEN ** (2 ** j) + 1))
        square = square * (1 + b * (power + 1))
        power = power * power
    assert exp == magnitude
    return square


def verify_signature(initial: StackBuf(2), key, sig):
    point = hash_to_point(initial)
    fh = transform(key, 0)
    fs = transform(sig, 0)
    product = HeapBuf(N)
    for i in mul_range(1, GEN ** N):
        product[i] = mul_mod(fh[i], fs[i])
    convolution = transform(product, 1)
    sums = HeapBuf(N + 1)
    sums[1] = 1
    for i in mul_range(1, GEN ** N):
        s0 = reduce(point[i] / convolution[i] * GEN ** Q, 2)
        square0 = centered_square(s0, 0)
        square1 = centered_square(sig[i], 1)
        sums[i * GEN] = sums[i] * square0 * square1
    low = hint_witness("norm_complement_low")
    high = hint_witness("norm_complement_high")
    assert log(low) < 65536
    assert log(high) < 520
    assert sums[GEN ** N] * low * high ** 65536 == GEN ** 34034726
    return
