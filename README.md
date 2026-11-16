# Post-quantum signature proofs under leanVM

Supporting code, measurements and figures for the [ethresearch post](articles/ethresearch.md).
The study covers Falcon-512, ML-DSA-44, FORS, Raccoon-128 and Raccoon-G.
This is an experimental benchmark implementation, not an EIP-8288 client integration.

## Experimental status

This work has **not been audited**. It is experimental research intended to
support discussion around EIP-8288, and is not suitable for production use.
The tests and scoped reviews in this repository do not constitute a security audit.

## Repository guide

- [Read the post](articles/ethresearch.md)
- [Build, reproduce and verify](docs/reproduce.md)
- [Build and test validation](docs/validation.md)
- [Figures and source data](articles/figures/README.md)
- [Capacity qualification](risc-v/results/reaudit/README.md)

| Workload | Implementation | Measurements |
|---|---|---|
| Falcon and ML-DSA, direct | [RISC-V runner](risc-v/bench) and [ML-DSA guest](risc-v/mldsa) | [Direct reports](risc-v/results/direct) |
| Falcon and ML-DSA, recursive | [Native tree runner](risc-v/tree-bench) | [Trees](risc-v/results/trees) |
| FORS, direct | [Python leanISA guest](leanISA/guests/fors.py) and [runner](leanISA/src/main.rs) | [Direct reports](leanISA/results/article/direct) |
| FORS, recursive | [Sumcheck reduction](leanISA/reduction) | [Trees](leanISA/reduction/results/trees) |
| Raccoon-128 | [Measured optimized guest](risc-v/experiments/raccoon-crt32) and [runners](risc-v/raccoon-optimized-study) | [Direct and tree reports](risc-v/results/raccoon-runtime-study) |
| Raccoon-G | [Five-part verifier and tree runner](risc-v/experiments/raccoong-segmented) | [Trees](risc-v/results/raccoong-segmented-uniform-trees) |

RISC-V uses leanVM `06e5c9cd6981103786f9d0a17324241b559a50d3`; FORS uses
leanISA `575df819d9c857f38068cecf7b1640e0ce4bfb29`. External source pins are in
[upstream.lock.json](upstream.lock.json). Guest ELFs and build manifests identify
the exact measured programs.

Measurements were made on an Apple M4 Pro with 24 GiB RAM. Direct proofs use
one warmup and three measured proofs. Recursive points use three fresh complete
pipelines in separate processes, without an in-process proving warmup; Raccoon-G
at 100 signatures has one completed pipeline. Error bars show the full range.
RSS includes setup and warmup. Raccoon runs use an explicit Jemalloc page-purging
policy; other schemes retain their recorded allocator settings.

Final receipts, intended public statements, per-node timings, source identities
and verification records are retained. Intermediate leaf/merge proofs, build
products, abandoned experiments and older drafts were removed. Figure generation
checks the retained evidence without rerunning a prover or claiming to reverify
discarded intermediate files.

The monolithic Raccoon sources support the witness-capacity diagnosis; the
RISC-V FORS adapter remains a shared runner dependency. The small ML-DSA capacity
variant and its review qualify the original 32-Falcon/6-ML-DSA prefix boundaries:
these are measured operating points, not universal maxima. Those controls do
not replace the original timing curves. Shared leanISA fixture helpers remain
dependencies of the FORS preparation code.

Proofs are not zero knowledge and fixture keys are publicly reproducible. FORS
is a few-time component, not full SLH-DSA. Retained specifications and scoped
reviews describe the exact relations and assumptions.
