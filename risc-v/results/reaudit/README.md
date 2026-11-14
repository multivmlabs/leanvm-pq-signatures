# Capacity recheck

The earlier successful proofs were real, but a signature-count boundary for one
fixture prefix is not a universal maximum. This recheck keeps the original data
and separates unchanged-program reproductions from implementation optimizations.

Backend: `leanEthereum/leanVM`, experimental `riscv-exploration`, commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. Its vendor checkout is unchanged.
All production attempts retain the `2^28 = 268,435,456`-word cap, rate one and
complete verification. The FORS hash remains Keccak-256. Inputs contain distinct
public-key/message claims, rather than repeated copies counted as new signers.

## What was reproduced

Fresh calls to the production prover produced and fully verified the original
prefix batches: Falcon 32, ML-DSA 6 and FORS 7. Their serialized proof bytes are
identical to the original saved proofs. Their next prefixes again return
`TooLong`. Reports, commands, proof files and public statements are in
[`baseline-fresh/`](baseline-fresh/).

Independent full interpreter runs also complete those rejected next batches
with the correct cryptographic outputs. Exact public layout accounting matches
all 25 original successful reports and explains the rejections:

| Original prefix | Table crossing | Executed rows | Rounded table rows | Full witness words |
|---|---|---:|---:|---:|
| Falcon 33 | SHIFT | 1,052,575 | 2,097,152 | 273,637,896 |
| ML-DSA 7 | narrow LOAD | 534,127 | 1,048,576 | 276,520,040 |
| FORS 8 | ALU | 4,321,584 | 8,388,608 | 329,588,824 |

The raw interpreter and owned layout calculator are diagnostics only. No
rejected execution was turned into a proof by bypassing the production guard.

## FORS: the old 100-signature proof still works

A fresh proof of the archived 100-signature workload was produced, serialized
and verified, including a separate public-only receiver. It needs 19,439,616
witness words, only 7.24% of the same numerical cap. Thus 100 was a successful
tested count, not the old implementation's maximum.

Each FORS signature performs exactly 150 Keccak-f permutations. The archived
backend has a dedicated Keccak instruction and proves those permutations through
a specialized argument. The RISC-V pin has a BLAKE2s instruction, while Keccak is
software. Its FORS guest spends 94.1% of its instructions in Keccak-f.

One RISC-V signature needs 42,128,704 witness words, versus 470,016 in the archived
guest. At eight RISC-V signatures the ALU table doubles. Its packed circuit
witnesses alone already exceed the cap. The regression is caused by the chosen
execution/proving architecture, not a new restriction in FORS or a missing
signature check. See [the independent FORS report](../../reviews/fors-capacity-reaudit.md).

## Falcon: an actual 33-signature counterexample

Thirty-three ordinary signatures from upstream signer indices 96..128 produced
a real proof with the unchanged Falcon ELF and backend. Its 33 distinct public
claims were independently reconstructed and the proof passed the separate
project receiver. The proof is 402,606 bytes and needs 243,229,192 witness words.

The original prefix needs 283 Keccak permutations; this window needs 279.
Four fewer permutations save enough SHIFT instructions to remain below the
`2^20` table-height boundary. Decompression differences are included in the exact
accounting. Thus **32 is not a universal Falcon limit**.

Twenty-seven declared windows for counts 34, 35 and 36 failed measurement.
That finite search does not establish a universal maximum of 33. All windows,
inputs, an independent SHAKE/codec oracle and the actual proof are retained in
[the lattice report](../../reviews/lattice-capacity-reaudit.md).

## ML-DSA: seven with a reviewed representation optimization

The baseline seven-signature prefix crosses a narrow-load table boundary by
9,839 instructions. A separate guest stores the fixed NTT twiddle constants and
their local temporaries as 64-bit values. The constants have identical numeric
values; the original products already cast them to 64 bits. Coefficient arrays,
Montgomery truncations, compact parsing, matrix expansion, hints, norms and
challenge checks remain unchanged.

This removes enough narrow loads to prove seven ordinary ML-DSA-44 signatures:
261,315,688 witness words, 411,502 proof bytes. The produced proof passed
serialization/decoding, full verification, a separate public-only consumer,
wrong-output rejection and baseline-program substitution rejection. Its ELF is
distinct and is not silently substituted into the baseline timing curves.

The [independent arithmetic review](../../experiments/keccak-registers/twiddle64-independent-review.md)
and [actual proof record](../../experiments/mldsa-poly64/capacity-proof.json)
document this optimization. Native differential, ACVP, sanitizer and actual-VM
adversarial controls accompany it. It uses the original SDK kernel, not the
separate unmerged PR #605 assembly experiment.

## Timing interpretation and admission policy

The fresh rechecks use one proof per process with no preceding proof warmup.
They are capacity and validity controls, not new three-sample latency benchmarks.
Their times are substantially shorter than the old repeated-process medians,
despite producing identical proof bytes. The original allocator retains freed
pages, and host memory state is relevant; this recheck does not isolate every
cause of the timing difference. Neither timing series should be mixed with the
other or described as an intrinsic cost of the signature algorithm.

An aggregator should evaluate the actual batch against the witness budget and
split it when necessary. A fixed per-scheme signature count does not capture
input-dependent rejection sampling, table padding or legitimate implementation
optimizations. Improving FORS substantially on this backend likely requires
real Keccak acceleration with constraints, or a separately identified hash
variant. Changing the hash and presenting it as the same benchmark would be an
invalid comparison.
