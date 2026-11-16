# Article figures

PNG files are ready for ethresearch. PDF and TeX sources are retained alongside
them; the conceptual diagrams also have SVG where originally available.

| Post figure | Asset |
|---|---|
| 1 — RISC-V and leanISA flows | [Architecture](figure-architecture.png) |
| 2 — Raccoon-G row split | [Matrix split](matrix-split.png) |
| 3 — Recursive aggregation | [Proof aggregation](proof-aggregation.png) |
| 4 — Direct proving | [Prover overview](figure-prover-overview.png) |
| 5 — Capacity and amortized cost | [Capacity](figure-3-capacity-efficiency.png) |
| 6 — Direct verification | [Verification](figure-direct-batch-verification.png) |
| 7 — Tree proving and size | [Recursive trees](figure-4-recursive-trees.png) |
| 8 — Tree verification | [Tree verification](figure-5-tree-verification.png) |
| 9 — Wallet flow | [Wallet flow](figure-wallet-flow.png) |

[Direct data](measurements.csv), [tree summaries](recursive-trees.csv),
[individual tree samples](recursive-tree-samples.csv) and
[verification components](verification-raw-timers.csv) support the five
experimental plots. [Provenance](provenance.json) identifies their input files.

From the repository root:

```sh
python3 articles/scripts/raccoon_figures.py --output build/figures
```

The generator writes to a new directory and checks complete receiver records
and final receipts. It does not rerun cryptographic verification. See the
[reproduction guide](../../docs/reproduce.md) for rendering and benchmark commands.
