# Figures for mine.md

Regenerate the CSV, source hashes, LaTeX, PDF and PNG artifacts with:

```sh
python3 articles/scripts/mine_figures.py --render
```

The script reads saved reports without editing them, runs no prover and fetches
no external resources. It uses cached Tectonic resources and `pdftoppm`.

| Figure | Measurement |
|---|---|
| 1 | Direct-batch proof bytes and proving time |
| 2 | Direct-batch verification and peak prover process RSS |
| 3 | Commitment-budget occupancy and proving work per signature |
| 4 (`figure-4-recursive-trees`) | Fresh tree proving work and complete aggregate size for the three selected implementations |
| 5 (`figure-5-tree-verification`) | Complete tree verification, including setup or with setup prepared |

Falcon and ML-DSA use the pinned RISC-V baseline guests. FORS keeps its unchanged
Python leanISA guest and specialised Keccak circuit. Its active recursive curve
now uses a constrained sumcheck reduction of deferred bytecode claims. The
reviewed seven-signature ML-DSA variant and alternative 33-signature Falcon
corpus remain separate capacity controls.

## Unchanged direct measurements

Figures 1, 2 and 3 still use the original 50 direct-batch points: twelve Falcon,
six ML-DSA and 32 FORS. Each uses three proofs after one warmup. No new reduced
wrapper data enter a direct-batch curve. Figure 1 proving and Figure 3 proving
per signature use log10 y axes; proof size and capacity stay linear. Direct
counts use log2 x axes.

The RISC-V direct verifier timer includes decoding and full `Program::verify`.
The FORS direct timer uses the independent pinned receiver's prepared-bytecode
samples. Public-record derivation, setup and file reads are outside these
verification curves; exact timer boundaries differ. RISC-V requests eight
workers and the backend can add efficiency-core workers. FORS uses automatic
worker selection. Budget percentages refer to each backend's own witness
representation.

## Active recursive measurements

Every tree count uses three complete fresh pipelines and a separate public-only
receiver for each saved root. Falcon uses ten signatures per leaf, ML-DSA two
and FORS five; all active trees use binary merges. Their balanced shapes repeat
the last real proof in padding slots without counting extra signatures. Every
real leaf and every merge is freshly proved and charged. Error bars span the
full sample range; lines connect measurements only.

RISC-V work sums actual leaf and native merge API calls. Reduced FORS work
includes all leaf STARKs, every merge's native child verification/advice and
sumcheck generation (`prepare_s`), and its wrapper STARK. The
`native_reduction_prove_s`, `merge_prepare_s` and `wrapper_stark_prove_s` CSV
columns retain these components. Native reduction generation is never omitted
from the plotted proving work. Setup, fixtures, serialization and files are
separate; broader pipeline elapsed times remain in raw reports.

Every verification point retains all remaining obligations. RISC-V
`Tree::verify` checks the root and settles its folded dense-polynomial and
matrix claims. Reduced FORS verifies the root STARK and evaluates one reduced
claim for each required descendant program against trusted bytecode. That
count grows with program families/depth, not every edge. At 100 signatures,
the new binary FORS tree has 62 edges and five final family evaluations. It
makes no fixed-cost unlimited-recursion claim.

The setup-inclusive panel adds RISC-V program loading and tree construction,
or FORS program compilation and bytecode-table preparation. Prepared RISC-V
verification includes decoding; FORS starts from a decoded receipt. Both exclude
public-claim derivation and file reads. Derivation is retained separately as
`claim_ms`. Neither receiver reads signature witnesses or child proof files.
The size panel includes the whole serialized RISC-V tree proof or the FORS root
STARK plus its final reduced record and metadata. Public records and shared
programs are additional transport. Recursive timing axes use log10 y; sizes and
signature counts remain linear.

The active data are `recursive-trees.csv`, `recursive-tree-samples.csv` and
`tree-{falcon,mldsa,fors}.csv`. The reduced FORS reader requires all twelve
accepted producer/receiver pairs, the unchanged approved leaf identity, exact
root hashes, fixed binary padding, complete family settlement and full work
accounting. `provenance.json` records current source and input hashes.

## Legacy edge-obligation curves

`legacy-edge-obligations/` is an exact snapshot of the earlier figures, data,
generator and provenance, with `archive-manifest.json` hashing that snapshot.
The source reports under `leanISA/results/article/` remain unchanged.

`legacy-recursive-trees.csv`, `legacy-recursive-tree-samples.csv` and
`tree-fors-legacy.csv` preserve the previous selected numeric curves. Explicit
legacy Figures 4/5 regenerate them; the older FORS-only Figure 4/5 files and
`tree.csv` also remain available. Legacy FORS uses fan-in four and an external
check per edge: 26 at 100 signatures. The active reduced FORS binary tree has a
different topology and includes more complete native proving preparation, so
its old/new proving times do not isolate the effect of reduction alone.

Backend, acceleration, worker policy, leaf size, padding, timer boundaries and
aggregation protocol differ. These charts describe measured implementations,
not signature-only speedup ratios.
