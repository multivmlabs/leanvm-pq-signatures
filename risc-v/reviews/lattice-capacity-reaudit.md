# Falcon and ML-DSA capacity re-audit

## Findings

The original prefix-corpus boundaries were real, but **32 is not a universal
maximum for Falcon**. An unchanged production prover successfully proved **33
valid Falcon signatures** from another deterministic signer window, and the
unchanged full verifier accepted the proof. The original 33-signature prefix
still fails. The earlier claim must therefore be expressed as a measured corpus
boundary, not the maximum number that this guest can ever verify in one proof.

For ML-DSA, the original six-signature proof and seven-signature rejection agree
with a complete independent execution and exact size calculation. Seven also
fails for all nine tested record windows. This does not prove a universal
maximum for every valid public-key/message/signature collection or every
implementation.

No capacity cap, verifier check, cryptographic relation or guest was changed for
the successful 33-signature proof. No transient early-size-check false rejection
was found in the tested traces.

## Pin, methods and independence

Backend: official `leanEthereum/leanVM`, experimental `riscv-exploration`,
`06e5c9cd6981103786f9d0a17324241b559a50d3`; vendor patch state remains clean.

The owned diagnostic is in [lattice-capacity-reaudit](lattice-capacity-reaudit/).
It runs the unchanged ELF through raw `Machine` until a successful exit and
checks the output against independently prepared public claims. This bypasses
only `Program::run`'s allocation guard for **counting**, not for proving. It
does not retain a trace, build a witness or generate a proof from a rejected
execution.

The diagnostic reproduces three public rules from the pinned source:

1. `cpu/filler.rs::Plan::solve`, including padding-block closing jumps into ALU;
2. `cpu/layout.rs::Sizes::column_sources`, counting shared columns, circuit and
   clock packed witnesses, remaining direct columns and packed register words;
3. `stacking.rs`, whose committed length is the sum of the committed columns.

It accounts for LD/SD and hash-word aliases rather than counting their virtual
ports twice. The exact calculation matches **all 25 original successful
production reports**. For sampled successes, it also asserts equality with
production `Program::measure` row counts, filled heights and committed size.
For rejected cases, production measurement is recorded separately from the
diagnostic size. This is a capacity investigation, not a cryptographic audit of
the full backend.

The original saved Falcon-32 and ML-DSA-6 receipts were also reverified through
the separate project receiver after independently reconstructing their public
digests with Python BLAKE2s. The new Falcon-33 proof passed that same separate
receiver, and its public statement contains 33 distinct keys. See
[the receiver check](lattice-capacity-reaudit/independent-33-receiver-check.json).

## Exact original-prefix boundaries

The cap is `268,435,456 = 2^28` words.

| Guest/count | Complete execution | Exact committed words | Production measure |
|---|---|---:|---|
| Falcon 32 | Valid output | 243,229,192 | Accepts |
| Falcon 33, original prefix | Valid output | 273,637,896 | `TooLong` |
| ML-DSA 6 | Valid output | 261,277,800 | Accepts |
| ML-DSA 7, original prefix | Valid output | 276,520,040 | `TooLong` |

The original Falcon transition is in the **SHIFT** table. It has 1,020,071
executed rows for 32 signatures, fitting a table of `2^20` rows. At 33 it has
1,052,575 rows, just beyond `2^20 = 1,048,576`, so it needs `2^21` rows. Its
circuit/clock/direct/register columns then add 30,408,704 words to the witness,
crossing the total cap. Both the naturally rounded final heights and the filled
heights produce the same rejected final size.

The ML-DSA transition is mainly the **narrow LOAD** table. Six signatures make
457,815 LOAD rows, fitting `2^19`; seven make 534,127, exceeding
`2^19 = 524,288`, and need `2^20`. The small BLAKE2s HASH table also grows from
128 to 256 rows. Together these increase committed size from 261,277,800 to
276,520,040. Seven is only 9,839 narrow loads beyond the lower table height, so
further legitimate decoding or byte-I/O optimization could change this boundary.
It is not an inherent ML-DSA restriction.

The input/advice and instruction-count limits are not responsible. Falcon 33
uses 6,634 advice words out of 16,384 available; ML-DSA 7 uses 3,298 out of
131,072. Their roughly 4.8 and 7.5 million instructions are far below the clock
limit. Complete raw execution confirms their signature checks and public output.

## Actual counterexample: a verified 33-signature proof

The fixed upstream host corpus was tested at offsets
`0,1,2,3,4,8,16,24,32,48,64,96,128`, taking 33 consecutive distinct signers each
time. Offset 96 fits. The other tested windows fail. The successful window is
not silently substituted into the original timing curves.

| 33-signature input | Keccak permutations | SHIFT rows | Rounded SHIFT height | Total words |
|---|---:|---:|---:|---:|
| Original indices 0..32 | 283 | 1,052,575 | `2^21` | 273,637,896 |
| Indices 96..128 | 279 | 1,047,136 | `2^20` | 243,229,192 |

Falcon's hash-to-point uses SHAKE rejection sampling. The nonce and message
determine how many output samples are discarded and whether another Keccak
permutation is needed. Entry counts were measured at the pinned ELF's actual
`f1600` symbol and checked independently with Python's `hashlib.shake_256` on
the exact nonces/messages. The original prefix contains 14 signatures using
eight permutations and 19 using nine; the successful window contains 18 using
eight and 15 using nine.

Four fewer permutations save `4 * 1392 = 5568` SHIFT instructions. The
successful window actually has 114 **more** unary-zero bits in its compressed
coefficients and five more decoder-window reloads, costing `114 + 3*5 = 129`
additional SHIFTs. The net saving is exactly 5,439. That is enough to cross this
table's power-of-two boundary. This is legitimate input-dependent execution
cost, not omitted signature verification or a cheaper synthetic key/signature
relation. The [independent shape oracle](lattice-capacity-reaudit/falcon-shape-oracle.json)
also verifies that the proved advice is a byte-exact slice of the unchanged
upstream corpus.

The [validation record](lattice-capacity-reaudit/results/falcon-33-start96-proved.json)
records one actual `Prover::prove`, serialization, decoding, full
`Program::verify`, and rejection of a changed public output. The proof is
402,606 bytes. Proving took 14.222 seconds in that one cold run; this is **not**
comparable to the previous warmup-plus-three-sample timing medians and should
not replace them.

Artifacts:

- [Proof](lattice-capacity-reaudit/results/falcon-33-start96-proved.proof)
- [Public statement](lattice-capacity-reaudit/results/falcon-33-start96-proved.statement.json)
- [Actual advice](lattice-capacity-reaudit/results/falcon-33-start96-proved.advice.bin)
- [Compiled validation producer](lattice-capacity-reaudit/proof-producer.bin),
  SHA-256 `0dbe723295d1c2dfc4751e489de4d72e1c707175c6ccbebe798840a8820e3271`
- ELF SHA-256: `421470c0aef38d3b2c2ca392edd7786c7425085f6a430b0286a679c69f0f9a4c`
- Proof SHA-256: `b023f97b7a0fe1edfd13136c81e8bcbe21453b6a1cf8783c36ce2ff77284ad8e`

We additionally tested each of 34, 35 and 36 signatures at the predeclared
offsets `0,32,64,96,128,160,192,224,256`. All 27 cases failed production
measurement. ML-DSA seven was tested at offsets `0,1,2,3,4,8,16,32,64`; all nine
failed with 276,520,040 words. These are finite experiments, not global
impossibility proofs. All cases, including failures, are indexed in
[SUMMARY.json](lattice-capacity-reaudit/SUMMARY.json).

## The early guard and register packing

The diagnostic records every production-periodic size-check point and the full
final shape, including cases that production stops early. For the rejected
original Falcon 33, every periodic shape still fits; the final size check after
completion rejects. ML-DSA seven crosses the cap during execution and finishes
with an even larger rejected shape. There is no tested case where an early
oversized shape later becomes small enough.

Register packing is height-dependent, so monotonicity should not be asserted
without checking it. At this pin, however, it can be bounded. The 11 tables have
147 register bits in total, each table requiring at most 16. In first-fit packing
of 64-bit words, opening a fourth word at one height would require at least 147
bits already in three words, plus another positive-width item, exceeding the
total. Thus each height group uses at most three words. When one table doubles
from height `h` to `2h`, register regrouping can save at most `3h + 4h = 7h`
words, while that table's packed circuit, clock and direct columns add at least
`16h`. The total therefore grows. Repeating this argument handles larger height
jumps. The fixed public columns are unchanged. This addresses the possible
transient-shape objection for this pinned layout.

## Why PR #490 reported 28

There are documented backend changes after that PR, even though the signature
guest's instruction count stays essentially unchanged:

- [Register packing, PR #491](https://github.com/leanEthereum/leanVM/commit/9ae69db5b35526f4b56736900918a931c937d4f7)
  reduces the Falcon-28 witness from 163,009,336 to 153,571,464 words.
- [Linear control flow, PR #492](https://github.com/leanEthereum/leanVM/commit/bf115c30d7cf9f7afc0a6894a327da81177db7b2)
  reduces it again to 145,182,856, exactly matching our pinned measurement.

This explains why an earlier published maximum cannot simply be transferred to
the later pin. Both the backend revision and the concrete inputs must be named
when reporting capacity.
