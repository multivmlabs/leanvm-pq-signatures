# Native claim reduction expressed entirely in the Python-shaped leanISA DSL.
# This file is appended to a single-file wrapper before compilation. It uses
# the specialised KECCAK instruction through keccak_cells, and never calls a
# host verifier. All inputs and messages are full GF(2^192) elements.
from snark_lib import *

RED_Y_TOWER = f192(0, 1, 0)
RED_Y_INV = f192(1, 0, 1)
RED_INSTANCE_DOMAIN = 1003201680331580587326919884501360
RED_MAX_DIM = 32
RED_MAX_CLAIMS = 8
RED_INSTANCE_CELLS = 7 + 3 * ((RED_MAX_CLAIMS * (RED_MAX_DIM + 1) + 1) // 2)
RED_ROUND_DOMAIN = 256819625207113016318433485441036656


@inline
def red_pack64x2(a, b):
    assert_in_k(a, b)
    return a + RED_Y_TOWER * b


@inline
def red_assert_canonical(word):
    low = StackBuf(1)
    hint_f192_limbs(low, word)
    high = (word + low[0]) * RED_Y_INV
    assert_in_k(low[0], high)
    return


@inline
def red_pack_pair(out, at: Const, s, t):
    # Two E elements occupy three canonical 128-bit Keccak cells. Membership
    # checks bind every exposed limb, including both elements' third limbs.
    slo = StackBuf(2)
    tlo = StackBuf(2)
    hint_f192_limbs(slo, s)
    hint_f192_limbs(tlo, t)
    out[at] = red_pack64x2(slo[0], slo[1])
    out[at + 1] = red_pack64x2(((s + slo[0]) * RED_Y_INV + slo[1]) * RED_Y_INV, tlo[0])
    out[at + 2] = red_pack64x2(tlo[1], ((t + tlo[0]) * RED_Y_INV + tlo[1]) * RED_Y_INV)
    return


@inline
def red_challenge(state):
    # The first 192 bits of the 256-bit Keccak digest, in little-endian limbs.
    # state[0] contains limbs 0,1; the low limb of state[1] supplies limb 2.
    low = StackBuf(1)
    hint_f192_limbs(low, state[1])
    high = (state[1] + low[0]) * RED_Y_INV
    assert_in_k(low[0], high)
    return state[0] + RED_Y_TOWER * RED_Y_TOWER * low[0]


@inline
def red_claim_word(points, values, index: Const, n: Const):
    if const(index % (n + 1) == n):
        word = values[GEN ** (index // (n + 1))]
    else:
        word = points[GEN ** ((index // (n + 1)) * n + index % (n + 1))]
    return word


def red_instance(poly0, poly1, context0, context1, points, values, n: Const, m: Const):
    red_assert_canonical(poly0)
    red_assert_canonical(poly1)
    red_assert_canonical(context0)
    red_assert_canonical(context1)
    cells = StackBuf(RED_INSTANCE_CELLS)
    cells[0] = RED_INSTANCE_DOMAIN
    cells[1] = n
    cells[2] = m
    cells[3] = poly0
    cells[4] = poly1
    cells[5] = context0
    cells[6] = context1
    for pair in unroll(0, (m * (n + 1) + 1) // 2):
        left = red_claim_word(points, values, 2 * pair, n)
        if const(2 * pair + 1 == m * (n + 1)):
            right = 0
        else:
            right = red_claim_word(points, values, 2 * pair + 1, n)
        red_pack_pair(cells, 7 + 3 * pair, left, right)
    state = StackBuf(2)
    keccak_cells(cells[0:7 + 3 * ((m * (n + 1) + 1) // 2)], state)
    return state


def red_round(state: StackBuf(2), c0, c2, index: Const):
    # domain16 || index_LE128 || previous_digest32 || c0_LE192 || c2_LE192.
    # The messages enter Keccak BEFORE deriving the challenge.
    cells = StackBuf(7)
    cells[0] = RED_ROUND_DOMAIN
    cells[1] = index
    cells[2] = state[0]
    cells[3] = state[1]
    red_pack_pair(cells, 4, c0, c2)
    following = StackBuf(2)
    keccak_cells(cells, following)
    return following


def red_reduce_claims(poly0, poly1, context0, context1, points, values, point_out, n: Const, m: Const):
    # points is a row-major m*n HeapBuf; values is an m-element HeapBuf.
    # point_out is fresh write-once HeapBuf(n), filled from derived challenges.
    # The caller must expose the returned value and point_out in the parent PI.
    assert n != 0
    assert m != 0
    if const(n // (RED_MAX_DIM + 1) != 0):
        assert 0 != 0
    if const(m // (RED_MAX_CLAIMS + 1) != 0):
        assert 0 != 0
    state = red_instance(poly0, poly1, context0, context1, points, values, n, m)
    theta = red_challenge(state)
    target = 0
    coefficient = 1
    for claim in unroll(0, m):
        target = target + coefficient * values[GEN ** claim]
        coefficient = coefficient * theta
    messages = HeapBuf(2 * RED_MAX_DIM)
    hint_witness(messages[0:2 * n], "reduce_rounds")
    for round_index in unroll(0, n):
        c0 = messages[GEN ** (2 * round_index)]
        c2 = messages[GEN ** (2 * round_index + 1)]
        # Characteristic two: g(0)+g(1) = c1+c2 = target.
        c1 = target + c2
        state = red_round(state, c0, c2, round_index)
        challenge = red_challenge(state)
        point_out[GEN ** round_index] = challenge
        target = (c2 * challenge + c1) * challenge + c0
    terminal = StackBuf(1)
    hint_witness(terminal, "reduce_value")
    weight = 0
    coefficient = 1
    for claim in unroll(0, m):
        equality = 1
        for coordinate in unroll(0, n):
            equality = equality * (1 + points[GEN ** (claim * n + coordinate)] + point_out[GEN ** coordinate])
        weight = weight + coefficient * equality
        coefficient = coefficient * theta
    assert target == terminal[0] * weight
    return terminal[0]
