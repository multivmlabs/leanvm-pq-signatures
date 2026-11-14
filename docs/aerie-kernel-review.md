# Aerie base-field multiplication feasibility kernel

This is a constrained arithmetic probe for the field `p = 2^64 - 59` used by
Aerie's pinned Akita profile. It is not an Aerie verifier. Its source is
[aerie_kernels.py](../python/pqbench/aerie_kernels.py), with controls in
[test_aerie_kernels.py](../tests/test_aerie_kernels.py).

The pinned custom leanISA multiplies characteristic-two field elements. Its
ordinary `GEN` lies in GF(2^64), with multiplicative order `2^64 - 1`. Directly
encoding the product of two 64-bit integers as `GEN^(a*b)` would lose integer
information modulo that order. This kernel instead checks small integer
columns, each strictly below the generator order. The existing independent
generator-order certificate is in
[field-encoding-check.json](../results/article/field-encoding-check.json).

## Relation and carry normalization

For canonical `0 <= a,b,r,q < p`, the checked relation is

```
a*b = r + p*q
a*b + 59*q = r + 2^64*q
```

Use radix `B = 2^22` and three limbs of widths 22, 22 and 20. Thus
`a = a0 + B*a1 + B^2*a2`, with analogous representations of `b,q,r`.
Nine limb products are computed by boolean bit selection of successive
squarings of `GEN^ai`. The 64 multiplier bits are shared across three rows.

Both sides are nonnegative. They are normalized separately to the same digits,
avoiding signed carry advice. Write `pij = ai*bj` in the following **integer**
equalities. The guest checks their exponent encodings:

```
p00 + 59*q0                  = r0 + B*c0
p01 + p10 + 59*q1 + c0       = r1 + B*c1
p02 + p11 + p20 + 59*q2 + c1 = t2 + B*c2
p12 + p21 + c2               = t3 + B*c3
p22 + c3                     = t4 + B*t5

r2 + 2^20*q0                 = t2 + B*d2
2^20*q1 + d2                 = t3 + B*d3
2^20*q2 + d3                 = t4 + B*t5
```

The shared first digits are `t0=r0` and `t1=r1`. Carries `c0..c3` have 24 bits;
`d2,d3` have 20 bits; `t2..t4` have 22 bits and `t5` has 18. Both sides have no
source coefficient at column five, so their shared final carry is exactly
`t5`. There is no further unchecked carry. Multiplying the column equalities
by their radix weights and cancelling carries recovers the full integer
relation, even though its product can require 128 bits.

Every bit hint is explicitly boolean. A conservative bound for any left
column is `3*(B-1)^2 + 59*(B-1) + 2^24-1 < 2^47`; a right equality side is
bounded by `(B-1) + B*(2^24-1) < 2^47`. The limb powers and products obey the
same bound. Hence none of these exponent equalities can wrap modulo
`2^64-1`. These bounds apply to all admitted advice, not just sampled inputs.

## Canonical residues and public binding

Each of `a,b,q,r` has exactly 64 checked bits. Since `p = 2^64-64+5`, a value
is canonical unless all bits 6 through 63 are one. In that exceptional case,
its low six bits must be below five. The guest enforces bits 5,4,3 to be zero
and disallows bit 2 together with either bit 1 or bit 0. This accepts precisely
low values 0 through 4.

The public statement is an ordered Keccak-256 fold of the actual `(a,b,r)`
records. Each fold hashes the previous 32-byte digest followed by
`LE64(a) || LE64(b) || LE64(r) || zero[8]`. A versioned domain initializes the
fold, and count is fixed by the guest specialization. Quotient and carry hints
are private advice; changing them cannot change the claimed operands or result.

Each operation supplies 476 checked bits and includes **one Keccak binding
step**. That binding cost is part of the probe's VM execution and proving cost.
The host computes advice with Python integer arithmetic; native advice generation
does not replace any guest arithmetic constraint.

## Executed controls

The dedicated suite passed all **10 tests** using the existing release runner.
It performs execution only and generates no STARK proofs:

```sh
PYTHONPATH=python .venv/bin/python -m unittest discover \
  -s tests -p test_aerie_kernels.py -v
```

The [execution log](../results/aerie/kernel-tests.log) records these checks:

- Exact column identities for 169 boundary pairs and 1,000 deterministic random
  pairs, including `a=b=p-1`; conservative bounds exclude exponent aliasing.
- A positive guest with 16 distinct boundary/random operations.
- Changed quotient, five separate carry/terminal mutations, a nonboolean bit,
  and a false result with its public commitment recomputed.
- Noncanonical `a` or `b`, equal to `p` or `2^64-1`, with the other operand
  zero. The product equation still holds and the public commitment is recomputed.
- A noncanonical result isolated from arithmetic failure: `a=2`,
  `b=(p+1)/2`, `q=0`, `r=p+1`, with hand-derived consistent carries and digits.
  Only canonical-result enforcement should reject that otherwise exact relation.
- Public commitment sensitivity to result, count and ordering.

Fixtures for profiling can be generated without proof generation:

```sh
PYTHONPATH=python .venv/bin/python -m pqbench.aerie_kernels \
  --count 64 --out artifacts/aerie/kernels/64.json
```

The resumable [benchmark driver](../scripts/aerie_kernel_bench.py) defaults to
counts 1, 8, 64 and 256, one warmup, three measured proofs and inverse-rate
logarithm one. `--prepare-only` writes fixtures without VM execution or proving.
When the driver is run without that option, the core CLI self-verifies every
generated proof and saves the final measured proof. A fresh process verifies
that saved proof against independently regenerated source and public commitment,
using a statement file with an empty witness. Source, input, public-statement,
runner-binary and proof hashes must match before a completed point is resumed.

```sh
.venv/bin/python scripts/aerie_kernel_bench.py --prepare-only
.venv/bin/python scripts/aerie_kernel_bench.py
```

Results go to `results/aerie/kernels`; fixtures and proofs go to
`artifacts/aerie/kernels`. Reports preserve VM cycles, memory and committed cells,
proof sizes, proving samples and process peak RSS. Python fixture construction
and compilation are outside `prove_s`. The complete CLI process wall time is
recorded separately. These timings include each kernel's Keccak binding step.

## Measured proof probes

All four default counts completed on the same M4 Pro host, one warmup followed
by three measured proofs at inverse-rate log one. Every saved final proof passed
fresh verification under the independently derived program hash and public
commitment. No signature witnesses or arithmetic hints were supplied to that
fresh verifier. There were no capacity failures in this probe range.

| Base multiplications | VM cycles | Median proving, s | Saved proof, KiB | Process peak, GiB | Commitment ceiling, log2 |
|---:|---:|---:|---:|---:|---:|
| 1 | 6,802 | 0.026932 | 229.66 | 0.051 | 19 |
| 8 | 54,311 | 0.039026 | 243.05 | 0.129 | 21 |
| 64 | 434,383 | 0.128060 | 287.74 | 0.715 | 24 |
| 256 | 1,737,487 | 0.499761 | 314.27 | 2.511 | 26 |

The asymptotic execution count is approximately **6,787 custom-ISA cycles per
independently ranged base multiplication**, including its binding hash. These
are VM cycles, not native CPU cycles. Peak RSS is for the complete proving
process including warmup. The commitment ceiling is derived as
`ceil(log2(committed_cells))`; it is not a measured capacity limit.

The [measurement log](../results/aerie/kernel-bench.log) and
[raw proof and fresh-verification reports](../results/aerie/kernels/) retain
the three samples, source/input/proof hashes and exact statement pins.

## Interpretation limits

This measures independent full-width base-field multiplications. A real
verifier could reuse range checks, exploit small coefficients or use a different
constraint representation. It also needs modular additions, Fp2 operations,
PIOP and Akita verification, proof decoding, BLAKE2b Fiat-Shamir transcripts,
and correct public-key/message/salt binding. None is implemented by this kernel.

The probe therefore supplies measured evidence about one cost component. It
does not establish complete-verifier capacity, prove an Aerie aggregate, or
justify multiplying a native Aerie verification time by a guessed slowdown.
The proof-producing measurements retain this limited scope; none is a full
Aerie-to-leanSTARK measurement. These proofs also use the existing non-ZK backend.
