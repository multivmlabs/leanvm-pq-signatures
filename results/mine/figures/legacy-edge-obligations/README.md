# Figures for mine.md

Regenerate the CSV, source hashes, LaTeX, PDF and PNG artifacts with:

```sh
python3 articles/scripts/mine_figures.py --render
```

The script reads original reports without editing them. It uses cached Tectonic
resources and `pdftoppm`; it runs no prover and fetches no external resources.

| Figure | Measurement |
|---|---|
| 1 | Direct-batch proof bytes and proving time |
| 2 | Direct-batch verification and peak prover process RSS |
| 3 | Backend commitment-budget occupancy and proving work per signature |
| 4 (`figure-4-recursive-trees`) | Fresh tree proving work and complete aggregate size for all three selected implementations |
| 5 (`figure-5-tree-verification`) | Complete tree verification, including setup or with setup prepared, for all three implementations |

Falcon and ML-DSA use the pinned RISC-V baseline. FORS uses the Python leanISA
guest with constrained Keccak. Backend names are printed in the direct-figure
legends. The separately reviewed seven-signature ML-DSA guest and alternative
33-signature Falcon corpus are capacity controls, not baseline timing points.

Direct points use three proofs after one warmup. Tree points use three fresh
leaf-plus-merge pipelines at 10, 30, 70 and 100 distinct signatures. RISC-V Falcon
uses ten signatures per real leaf, ML-DSA two, and binary merges. Their canonical
balanced trees repeat the last real leaf proof in padding slots; those slots are
not counted as additional signatures. Every merge is freshly proved and charged.
The archived FORS trees use five signatures per leaf and fan-in four. Error bars span the full recorded sample range.
Connections between measured counts do not supply intermediate measurements.
Figure 1's proving time, Figure 3's time per signature and the recursive timing
panels use logarithmic y axes so all measurements remain visible. Proof size and
capacity stay linear.

The RISC-V verifier timer includes proof decoding and full `Program::verify`.
The FORS direct timer uses the independent public-only receiver's prepared
bytecode and `verify_cached_s` samples. These timer boundaries and the explicit
eight requested workers versus automatic worker-selection policies differ. The
backend can add efficiency-core workers, so eight is not a total thread count. The charts
compare measured implementations; they do not establish signature-only speedup
ratios. Budget percentages refer to each backend's own witness representation.

Both tree verifier panels include all obligations required by their backend. The
RISC-V `Tree::verify` checks the root and settles the reduced bytecode, image,
fixed-polynomial and matrix claims at the root. The leanISA FORS receiver checks
each edge's deferred obligation and the root STARK. The setup-inclusive panel
also includes RISC-V ELF loading and tree construction, or FORS trusted-plan
compilation and verification-table preparation. The prepared panel excludes
those setup costs. Neither includes public-claim derivation or file reads; claim
derivation is recorded separately as `claim_ms` in the CSVs. Neither receiver uses
child proof files or signature witnesses. The size panel includes the complete
serialized RISC-V tree proof, or the FORS root plus auxiliary edge data and
metadata. Public claims and shared programs are additional transport.

`recursive-trees.csv` and `recursive-tree-samples.csv` contain the selected
three-scheme tree measurements. `tree-falcon.csv`, `tree-mldsa.csv` and
`tree-fors.csv` drive the new plots. The earlier FORS-only Figures 4/5 and
`tree.csv`/`tree-samples.csv` remain available with their original definitions.
Old leanISA Falcon/ML-DSA tree results are not relabeled or included. Backend,
hash acceleration, tree shape, padding and timer boundaries differ, so the
figures do not isolate signature-only speedups. See `provenance.json` for exact
pins, source SHA256 hashes, timing definitions and sampling policies.
