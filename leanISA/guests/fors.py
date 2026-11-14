# Research Keccak FORS verifier, not SLH-DSA or leanSPHINCS.
# COUNT, K and A are set by the fixture builder; no signature data is compiled in.
from snark_lib import *

COUNT = COUNT_PLACEHOLDER
K = K_PLACEHOLDER
A = A_PLACEHOLDER
DS_LEAF = DS_LEAF_PLACEHOLDER
DS_NODE = DS_NODE_PLACEHOLDER
DS_ROOT = DS_ROOT_PLACEHOLDER
DS_MSG = DS_MSG_PLACEHOLDER
DS_BATCH = DS_BATCH_PLACEHOLDER


def canonical(word):
    low = StackBuf(1)
    hint_f192_limbs(low, word)
    high = (word + low[0]) / f192(0, 1, 0)
    assert_in_k(low[0], high)
    return


def bits128(word):
    bits = StackBuf(128)
    hint_decompose_bits(bits, word, 128)
    value = 0
    for j in unroll(0, 64):
        assert bits[j] * (bits[j] + 1) == 0
        value = value + bits[j] * const(2 ** j)
    for j in unroll(64, 128):
        assert bits[j] * (bits[j] + 1) == 0
        value = value + bits[j] * const(2 ** (j - 64)) * f192(0, 1, 0)
    assert value == word
    return bits


def verify_one(claims, base):
    header = StackBuf(6)
    hint_witness(header, "fors_header")
    for j in unroll(0, 6):
        canonical(header[j])
        claims[base * GEN ** j] = header[j]

    # Header = public seed || forest public root || 32-byte message.
    md = StackBuf(2)
    keccak_cells([DS_MSG, header[0], header[1], header[2], header[3], header[4], header[5]], md)
    digest_bits = bits128(md[0])
    roots = StackBuf(3 + 2 * K)
    roots[0] = DS_ROOT
    roots[1] = header[0]
    roots[2] = header[1]

    for tree in unroll(0, K):
        secret = StackBuf(2)
        hint_witness(secret, "fors_secret")
        canonical(secret[0])
        canonical(secret[1])
        index = 0
        for bit in unroll(0, A):
            index = index + digest_bits[tree * A + bit] * const(2 ** bit)
        node = StackBuf(2)
        # Address = LE32(tree) || LE32(height) || LE64(index).
        address = const(tree) + f192(0, 1, 0) * index
        keccak_cells([DS_LEAF, header[0], header[1], address, secret[0], secret[1]], node)

        for height in unroll(0, A):
            sibling = StackBuf(2)
            hint_witness(sibling, "fors_auth")
            canonical(sibling[0])
            canonical(sibling[1])
            side = digest_bits[tree * A + height]
            delta0 = side * (node[0] + sibling[0])
            delta1 = side * (node[1] + sibling[1])
            left0 = node[0] + delta0
            left1 = node[1] + delta1
            right0 = sibling[0] + delta0
            right1 = sibling[1] + delta1
            parent_index = 0
            for bit in unroll(height + 1, A):
                parent_index = parent_index + digest_bits[tree * A + bit] * const(2 ** (bit - height - 1))
            parent_address = const(tree + (height + 1) * 2 ** 32) + f192(0, 1, 0) * parent_index
            parent = StackBuf(2)
            keccak_cells([DS_NODE, header[0], header[1], parent_address, left0, left1, right0, right1], parent)
            node = parent
        roots[3 + 2 * tree] = node[0]
        roots[4 + 2 * tree] = node[1]

    # Equality against the claimed public root authenticates the forest.
    keccak_cells(roots, header[2:4])
    return


def main():
    claims = HeapBuf(1 + 6 * COUNT)
    claims[1] = DS_BATCH
    for i in mul_range(1, GEN ** COUNT):
        verify_one(claims, GEN * i ** 6)
    digest = StackBuf(2)
    keccak_cells(claims[0:1 + 6 * COUNT], digest)
    public = GEN ** 0
    public[1] = digest[0]
    public[GEN] = digest[1]
    return
