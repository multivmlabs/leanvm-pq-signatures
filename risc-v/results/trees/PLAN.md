# RISC-V recursive signature benchmark

Use the unchanged Falcon and ML-DSA-44 baseline guests and leanVM RISC-V commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. Do not alter the `2^28` commitment
cap, cryptographic checks, signature hashes, or proof verifier.

Requested distinct signature counts: 10, 30, 70, 100. Prepare the ordinary first
100 deterministic signer records per scheme. Every real leaf verifies ten
Falcon signatures or two ML-DSA signatures. Measure every leaf before proving and require identical
`LeafShape` within a scheme. A shape failure must be reported, not hidden by
discarding records or weakening checks.

Use the upstream positional output tree with first-level arity two and higher
arity two. Its balanced shape needs a power-of-two number of leaf slots.
Use at least two slots; repeat the final real proof/output only for the disclosed padding slots. These
are reused proofs, not additional signatures or freshly proved leaves. Charge
all first-level and higher merge proofs, including those covering padding.

| Scheme | Distinct signatures | Fresh real leaves | Total leaf slots | Padding slots | Merge proofs |
|---|---:|---:|---:|---:|---:|
| Falcon | 10 | 1 | 2 | 1 | 1 |
| Falcon | 30 | 3 | 4 | 1 | 3 |
| Falcon | 70 | 7 | 8 | 1 | 7 |
| Falcon | 100 | 10 | 16 | 6 | 15 |
| ML-DSA | 10 | 5 | 8 | 3 | 7 |
| ML-DSA | 30 | 15 | 16 | 1 | 15 |
| ML-DSA | 70 | 35 | 64 | 29 | 63 |
| ML-DSA | 100 | 50 | 64 | 14 | 63 |

Preflight initially tested five signatures per leaf for both schemes. Two
Falcon groups (records 35..39 and 60..64) have different padded table heights.
All ten-signature Falcon groups match; all five-signature ML-DSA groups match.
The Falcon grouping was changed before proving. No records were discarded or
replaced. Two- and one-signature Falcon groups also match, but require more
merge proofs; these are diagnostic alternatives, not additional timing curves.

Before the timing matrix, actual ten-signature ML-DSA pilots compared five-
and two-signature leaves. Five-signature leaves took 56.999 s including one
merge, whereas two-signature leaves took 8.053 s including seven merges. Both
produced and fully verified real roots; the original guests were unchanged.
All 50 two-signature groups also have the same leaf shape. The matrix therefore
uses two-signature ML-DSA leaves to avoid the expensive larger-leaf operating
point. These single-pipeline controls are not substituted into the three-sample
curves. Their reports remain under `pilot/`.

Run one configuration at a time. Record three complete fresh pipelines, each
in its own process. Keep fixture preparation, program loading, tree setup,
leaf proving, merge proving, serialization and verification as separate
timers. A separate preliminary pipeline may exercise the configuration, but
must not be described as an in-process warmup for the measured samples. Do not
reuse real leaf or merge proofs between measured pipelines.

The receiver pins the approved ELF and independently intended public statement,
reconstructs leaf commitments and canonical padding, decodes the saved root and
calls full `Tree::verify`. It must not read signature advice or child proof
files. Record public-claim derivation separately from prepared verification;
also record program loading and `Tree::new` so verification including setup can
be compared. All reduced bytecode, image, fixed-polynomial and matrix claims
must be settled. This RISC-V protocol does not use the older FORS wrapper's
per-edge external obligation list.

Retain source/compiler/backend identities, commands, raw reports, all saved
proofs, receiver reports and negative controls. Figures must use actual
verified samples, include all padding overhead, disclose the sampling and
backend differences, and preserve logarithmic direct-proving axes.
