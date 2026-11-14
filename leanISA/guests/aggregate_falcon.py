# A fixed-arity proof of custom ETHFALCON leaf proofs. The generic proof verifier
# and field packing helpers are extracted from pinned leanEthereum/leanVM.
# Every deferred bytecode evaluation is hashed into the public statement and
# MUST be recomputed against the expected leaf bytecode by the outer verifier.

AGG_CHILDREN = AGG_CHILDREN_PLACEHOLDER
AGG_LEAF_SEED_0 = AGG_LEAF_SEED_0_PLACEHOLDER
AGG_LEAF_SEED_1 = AGG_LEAF_SEED_1_PLACEHOLDER
AGG_DOMAIN = AGG_DOMAIN_PLACEHOLDER
AGG_DEFER_PAIRS = (DEFER_STMT_CELLS + 1) // 2
AGG_CHILD_CELLS = 2 + 3 * AGG_DEFER_PAIRS
AGG_STATEMENT_CELLS = 4 + AGG_CHILDREN * AGG_CHILD_CELLS


def main():
    logs_pow2, squares = exponent_tables()
    statement = StackBuf(AGG_STATEMENT_CELLS)
    statement[0] = AGG_DOMAIN
    statement[1] = AGG_CHILDREN
    statement[2] = AGG_LEAF_SEED_0
    statement[3] = AGG_LEAF_SEED_1
    for child in unroll(0, AGG_CHILDREN):
        pi = StackBuf(2)
        hint_witness(pi, "aggregate_child_pi")
        deferred = HeapBuf(DEFER_SIZE)
        verify_sub(pi[0], pi[1], AGG_LEAF_SEED_0, AGG_LEAF_SEED_1, logs_pow2, squares, deferred)
        statement[4 + child * AGG_CHILD_CELLS] = pi[0]
        statement[5 + child * AGG_CHILD_CELLS] = pi[1]
        for pair in unroll(0, AGG_DEFER_PAIRS):
            s = deferred[GEN ** (2 * pair)]
            if const(2 * pair + 1 == DEFER_STMT_CELLS):
                t = 0
            else:
                t = deferred[GEN ** (2 * pair + 1)]
            pack_pair(statement, 6 + child * AGG_CHILD_CELLS + 3 * pair, s, t)
    digest = StackBuf(2)
    keccak_cells(statement, digest)
    public = GEN ** 0
    public[1] = digest[0]
    public[GEN] = digest[1]
    return
