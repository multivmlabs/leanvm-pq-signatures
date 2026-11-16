# Reduced recursive FORS proofs in Python leanISA

This implements a degree-two sumcheck reduction inside the Python-shaped DSL,
using the pinned leanISA backend and its specialised Keccak circuit. It does
not move FORS to software Keccak or change its signature relation. The leaf
program is byte-for-byte the approved five-signature guest from the earlier
study: `9f26663ec851871efc147c210850edbf0f2b4b49a43bc22684a2e53df878a14b`.

The backend remains `575df819d9c857f38068cecf7b1640e0ce4bfb29`, at rate one with
the existing `2^28` commitment cap. No vendored source was changed. The independent
[review](review/REVIEW.md) covers the new protocol integration and its controls.

## How the reduction works

A child proof leaves a bytecode claim `P(q)=v`. A parent receives fresh claims
from its child-proof verifiers and the accumulators authenticated by its child
statements. For each required program family it batches the two claims with a
transcript-derived challenge `theta`, then proves a sumcheck for
`sum_x P(x) * sum_i theta^i eq(q_i,x) = sum_i theta^i v_i`.

The DSL verifier checks every round and its final weighted-value identity. It
derives the new point itself from Keccak after absorbing the round message.
It does not trust a host Boolean or simply average the old values. The resulting
point and value enter the parent's public commitment. The final receiver
verifies the root STARK and evaluates every remaining claim against the exact
trusted bytecode table. Omitting those terminal evaluations is incomplete.

Full 192-bit field values are packed into canonical hash cells without dropping
limbs. Initial transcripts bind protocol domain, dimensions, claim count,
program identity, context and every input point/value; round messages bind
before their challenges. [Guest source and transcript specification](guest/README.md),
[native prover](src/reduction.rs), [wrapper construction](src/wrapper.rs), and
[complete consumer](src/receipt.rs) are provided separately.

The public semantic digest and accumulator record are distinct. A parent
reconstructs each child's complete public commitment before verifying its proof,
but computes its own semantic digest from the child semantic digests alone.
Consequently, the final receiver derives the expected semantic root from all
intended public key/message pairs and needs only the root accumulator record,
not all intermediate records or child proof files.

## Depth and remaining work

This is bounded recursion with one program family per level. Programs are
compiled bottom-up: each wrapper embeds only already-known descendant program
identities, avoiding a circular dependency on its own bytecode hash. The root's
own bytecode is checked by its ordinary full STARK verifier. Its accumulator
contains only descendant families.

At 100 signatures, twenty real five-signature leaves occupy 32 binary slots.
Padding repeats the last existing proof and never counts as additional
signatures; all 31 merges are freshly produced and charged. There are 62 edges,
but only five final reduced family evaluations. The older fan-in-four wrapper
had 26 edges. These are different topologies, so the check counts are not a
controlled same-tree comparison.

The remaining evaluations grow with the number of distinct level programs,
usually tree depth. This does not implement RISC-V's fixed two-kind recursion
machine or claim constant verification cost at arbitrary depth. Compiled
programs do not depend on the key/message values. Prepared timings below reuse
a verifier bound to one statement; a separate cache API across changing
statements has not been benchmarked.

## Measured results

Apple M4 Pro, 24 GiB RAM, automatic upstream worker selection. Every point uses
three complete fresh producer processes followed by separate public-only
receivers. Signature witnesses and child proof files are absent from the
isolated receiver's working directory. Proof controls are separate.

| Distinct signatures | Proving work, s | Complete receipt, KiB | Full verify prepared, ms | Full verify including setup, ms | Final family evaluations |
|---:|---:|---:|---:|---:|---:|
| 10 | 0.367 | 331.91 | 5.865 | 234.23 | 1 |
| 30 | 2.457 | 331.82 | 8.744 | 678.84 | 3 |
| 70 | 5.527 | 334.65 | 10.263 | 940.89 | 4 |
| 100 | 11.261 | 335.98 | 11.913 | 1204.02 | 5 |

Proving work includes every fresh leaf STARK, native child verification and
advice preparation, native sumcheck generation, and every wrapper STARK. At
100 signatures, native sumcheck generation accounts for 1.319 s of the total
11.261 s; all native preparation totals 4.160 s, and wrapper STARK generation
6.077 s. Leaf STARKs account for the remainder. Compilation, fixtures, files and
self-verification are separate; full process elapsed time is also recorded.

Prepared full verification checks the decoded root and all final family claims.
At 100, the root-core component is about 6.14 ms and the five trusted-table
evaluations about 5.75 ms. Public key/message commitment derivation is additional,
0.087 ms. The setup-inclusive measurement includes rebuilding programs and
verification tables; it is not just the prepared verifier call. Receipt decoding
and file reads precede these timers, matching the older FORS accounting.

The complete 100-signature receipt is 344,040 bytes: 341,128 root-core bytes and
2,912 accumulator/header bytes. Peak resident process memory is about 1.406 GiB.
Direct FORS batching still wins at this count: 0.283 s
and 298.02 KiB. No optimum or larger-count capacity is claimed.

## Correctness evidence

- Twelve independent Python field/Keccak vectors match the native prover exactly.
- 93 actual DSL executions give 24 expected acceptances and 69 rejections.
- A six-STARK control carries a false bytecode claim through two valid approved
  wrapper proofs. The complete unchanged consumer rejects it at the final
  trusted-table evaluation; the honest two-level control accepts.
- Eighteen isolated production-CLI controls reject changed/recommitted public
  claims, wrong pins and damaged receipts while accepting the honest root.
- All twelve measured roots independently match every intended leaf commitment,
  the full padded semantic digest, proof hashes and complete consumer receipts.

See [review evidence](review/REVIEW.md) and
[figure-input validation](../../articles/figures/validation.json). This is a scoped research
implementation, not a formal proof-system audit. The unchanged FORS construction
is a few-time component with the limitations documented in
[the original FORS relation](../docs/fors.md); it is not full SLH-DSA. Proofs are
not zero knowledge, and benchmark keys are publicly reproducible.

## Reproduce

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/target" RUSTFLAGS="-C target-cpu=native" \
 cargo +stable build --release --locked --offline --manifest-path leanISA/reduction/Cargo.toml
.venv/bin/python leanISA/reduction/run_benchmarks.py --output leanISA/reduction/results/trees-rerun
python3 articles/scripts/raccoon_figures.py --output build/figures --render
```

For a single actual two-level twenty-signature tree:

```sh
.venv/bin/python leanISA/reduction/prepare_fors.py --count 20 --out /tmp/reduced-fors20
 target/release/leanisa-reduced-tree plan --public /tmp/reduced-fors20/public.json --out /tmp/reduced-fors20/plan.json
 target/release/leanisa-reduced-tree prove --public /tmp/reduced-fors20/public.json --out /tmp/reduced-fors20/run
```

The public-only `verify` command requires `--public`, `--proof`,
`--expect-public-sha256`, `--expect-leaf-guest-hash` and `--out`. The expected
public digest must come from the receiver's own intended records; the approved
leaf identity must come from its own trusted policy. Values attached by an
untrusted sender do not authenticate either one.

Raw per-node work, native reduction cost, exact commands, binary/source hashes
and complete receipts are in [results/trees](results/trees/).
The frozen benchmark binary SHA-256 is
`1d683e440929570d459dca6747f18b74760fa94ee385d7adb0261129fbba38b5`.
