# Constrained leanISA reduction guest

`sumcheck.py` is appended to the wrapper's single-file Python DSL before
compilation. It uses the existing specialised Keccak instruction and full
GF(2^192) arithmetic. No signature or proof-verifier check is delegated to a
trusted host result.

## Interface

```
red_reduce_claims(poly0, poly1, context0, context1,
                  points, values, point_out, n: Const, m: Const) -> value
```

`poly0/poly1` and `context0/context1` are canonical two-cell 256-bit digests.
`points` is a row-major heap of `m*n` full field elements, `values` is an `m`
element heap, and `point_out` is a fresh write-once heap of `n` elements.
The primitive fills the new point from transcript-derived challenges and
returns its claimed polynomial value. It supports dimensions 1..32 and 1..8
claims, matching the native helper. Fixed maximum buffer allocation is needed
because this pinned compiler resolves allocation sizes before specialising
`Const` parameters; only the exact actual-length slice is read and hashed.

The witness streams are:

- `reduce_rounds`: one entry of `2*n` fields ordered `c0,c2` per round.
- `reduce_value`: one entry containing the final claimed value.

These streams are hints constrained by the guest. The returned value must be
checked against the trusted polynomial by the final receiver, or authenticated
as part of a child statement and included in a later constrained reduction.
The primitive alone is deliberately not a verifier of the polynomial table.

## Exact transcript

All integer headers use 16-byte little-endian encodings. Canonical digest cells
use two little-endian 64-bit limbs. Every field coordinate/value uses all three
little-endian 64-bit limbs. Keccak is Ethereum Keccak-256, not SHA3-256.

Initial preimage:

```
"pq-red-inst/v1\0\0" || n_LE128 || m_LE128 || polynomial_id32 || context32
|| claim0_point_LE192[] || claim0_value_LE192 || ...
```

The flattened list of fields is padded with one zero field only if its total
field count is odd. Packing two fields into three canonical 128-bit Keccak
cells is checked in the guest, including both third limbs.

Each round's preimage is exactly 112 bytes:

```
"pq-red-round/v1\0" || round_LE128 || previous_digest32 || c0_LE192 || c2_LE192
```

The first 192 bits of the initial digest supply the batching challenge. The
first 192 bits of each round digest supply that round's evaluation coordinate.
Round messages are absorbed before the challenge is derived. In characteristic
two, `c1 = target + c2`; the next target is `(c2*r + c1)*r + c0`.
The terminal equality weights all original input claims. There is no division
by the terminal weight, and zero challenges or weights are not specially
rejected; they belong to the normal probabilistic soundness analysis.

The wrapper must supply its context from authenticated child semantic
statements, program/family identifiers and policy, and it must publish the new
point/value in its own public statement. Omitting that integration would leave
the reduction unattached to the intended proofs.

## Evidence

`validate_guest.py` executes independent Python oracle vectors in the actual
leanISA compiler/interpreter, with a small trusted table's terminal evaluation
explicitly constrained in the test guest. It produced 24 accepting controls and
69 rejecting witness controls, including full-width top-limb changes. Separate
codec controls assert the exact independent initial digest, every derived point
coordinate and final value. Negative controls do not rely on those expected
output assertions: they check the reduction plus actual trusted-table equality.
These are constraint-execution tests, not STARK production or a backend audit.

```
python3 leanISA/reduction/guest/validate_guest.py
```

`tests.rs` adds native-versus-independent-vector comparisons and repeats all 93
actual guest outcomes in the new Rust crate's test suite.
