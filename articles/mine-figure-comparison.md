# Figure coverage

`mine.md` selects RISC-V Falcon-512 and ML-DSA-44, plus Python leanISA FORS with its specialised Keccak circuit. The active FORS tree now also proves sumcheck reductions of its deferred bytecode claims. Its signature guest and backend pin are unchanged. `leanvm-signature-aggregation.md` and the earlier FORS tree curves retain the older per-edge protocol.

| Measurement | Earlier article | Updated `mine.md` |
|---|---|---|
| Direct-batch proof size and proving time | Figure 1 | Figure 1, unchanged measurements, backend labelled for each scheme |
| Direct-batch STARK verification | Direct reports | Figure 2; one batch proof, without recursion |
| Peak prover memory and witness budget | Reports and efficiency study | Figures 2 and 3 |
| Complete recursive-tree proving work | Figure 2A | Figure 4, all three selected implementations |
| Complete serialized aggregate proof | Figure 2B | Figure 4; RISC-V folded root, or FORS root plus reduced program-family claims |
| Complete recursive-tree verification | Figure 2C | Figure 5, including every remaining obligation |
| Public-claim derivation | Figure 2D | Separately measured for every case as `claim_ms`; excluded from Figure 5 |
| Fan-in and signatures-per-leaf sensitivity | Figure 3 | No complete sensitivity matrix; the selected operating points and padding are disclosed below |

The active tree experiments cover 10, 30, 70 and 100 distinct signatures, with three complete fresh pipelines per case and a separate public-only receiver for every root. Old leanISA Falcon and ML-DSA curves are not relabelled. The old FORS tree measurements remain available in [the exact figure snapshot](../results/mine/figures/legacy-edge-obligations/) and [the legacy tree CSV](../results/mine/figures/legacy-recursive-trees.csv). A root combining the different signature programs or proof backends is not measured.

## Tree shape and padding

All active trees use binary merges. Falcon uses ten signatures per real leaf, ML-DSA two, and FORS five. All intended records appear in their original order. The RISC-V leaf sizes keep the padded execution-table shapes uniform over the benchmark corpus. The reduced FORS wrapper is built bottom-up at each depth from the unchanged leaf verifier and already compiled descendant wrappers.

Canonical padding repeats the final real leaf proof into a balanced power-of-two slot count. Padding never counts as additional signatures. Every real leaf and every merge is freshly proved and charged; the receiver independently reconstructs the same padding.

| Distinct signatures | Falcon real leaves + padding slots | ML-DSA real leaves + padding slots | Reduced FORS real leaves + padding slots | FORS final program-family evaluations |
|---:|---:|---:|---:|---:|
| 10 | 1 + 1 | 5 + 3 | 2 + 0 | 1 |
| 30 | 3 + 1 | 15 + 1 | 6 + 2 | 3 |
| 70 | 7 + 1 | 35 + 29 | 14 + 2 | 4 |
| 100 | 10 + 6 | 50 + 14 | 20 + 12 | 5 |

The separate ML-DSA leaf-size pilots and the reduced FORS 20-signature pilot are validity or configuration controls, not extra median-curve points. The [RISC-V runner](../risc-v/tree-bench/README.md) and [leanISA reduction implementation](../leanISA/reduction/) retain their exact configurations and component work.

## What complete-tree verification checks

Every receiver starts with intended public key/message records and approved programs, derives all leaf commitments and checks one root. Neither child proof files nor signature witnesses are needed.

RISC-V calls upstream **`Tree::verify`**. It checks the recursion proof and ordered output digest, then settles all reduced bytecode, memory-image, fixed-polynomial and Flock-matrix claims. The same fixed set of table types serves the tree; a per-edge obligation list is unnecessary. Setup depends on the approved program and proof shape and can serve different compatible public claim lists.

The new [leanISA FORS consumer](../leanISA/reduction/src/receipt.rs) checks the complete root STARK and evaluates the final reduced claim for **every required descendant program family** against trusted bytecode. The [DSL reduction](../leanISA/reduction/guest/sumcheck.py) verifies a degree-two sumcheck linking all input claims to those final claims. Each parent authenticates its children's semantic digest and inherited accumulators before reducing them. The parent semantic digest depends on the intended leaf claims, not on intermediate accumulator records. Thus only the root record is needed by the receiver.

The bounded leanISA wrappers have different bytecode at successive depths. Their final evaluation count grows with the number of program families, normally the depth, unlike RISC-V's fixed family set. At 100 signatures, the new binary FORS tree has 62 edges but only five reduced family claims to settle, in addition to the full root STARK. This does not claim constant-cost unlimited recursion.

The old FORS wrapper retains a separate evaluation at every edge. Its 100-signature fan-in-four tree has 26 edges, so it is not the same topology as the new binary tree. The old and new curves therefore do not isolate the speedup of reduction alone.

Figure 5 uses these timing boundaries:

- **Including setup:** RISC-V program loading, tree construction, root decoding and full `Tree::verify`; or reduced FORS program compilation, trusted bytecode-table preparation and first complete root-plus-family verification.
- **Setup prepared:** RISC-V decoding and full `Tree::verify`; or reduced FORS full root STARK and every final program-family evaluation with tables prepared. FORS starts from a decoded receipt.

Public-claim derivation and file reads are excluded and recorded separately. Each fresh receiver records a setup-inclusive time plus three prepared verification samples after one warmup. The plot uses the median and full range across three pipeline receivers. The prepared curves retain all required checks.

## Proving work and comparison boundaries

RISC-V proving work sums actual leaf and native merge API calls. Reduced FORS additionally includes **all native child verification/advice and sumcheck generation** in every merge's `prepare_s`, plus its constrained wrapper STARK. The `native_reduction_prove_s`, `merge_prepare_s` and `wrapper_stark_prove_s` columns preserve those costs separately. No reduction transcript is precomputed for free.

Compilation, fixtures, serialization and files are outside the plotted proving-work sums; broader pipeline times remain in the raw reports. The old FORS curve measured its leaf and wrapper STARK calls without the same complete native-preparation accounting. That boundary difference, changed fan-in and padding preclude a controlled old/new prover speedup claim.

The implementations share the host and logarithmic inverse rate but differ in backend, acceleration, leaf size and protocol. RISC-V requests eight workers; leanISA uses automatic worker selection. Public records and shared programs are extra transport beyond proof bytes. These are measurements of selected implementations, not signature-only speedup ratios. The distinct 33-signature Falcon corpus and seven-signature ML-DSA storage variant remain separate capacity controls.

The [figure script](scripts/mine_figures.py) exports [CSV, source hashes and LaTeX](../results/mine/figures/). Rebuild with:

```sh
python3 articles/scripts/mine_figures.py --render
```
