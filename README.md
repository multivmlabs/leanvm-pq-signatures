# Signature batching and recursive proofs under leanVM

The article uses the official experimental RISC-V backend for **Falcon-512 and
ML-DSA-44**, and Python leanISA with specialised Keccak for **FORS**. The RISC-V
FORS implementation remains available as a separate comparison.

- [Article](articles/mine.md)
- [Implementation, build and benchmark instructions](risc-v/README.md)
- [Exact upstream pins](risc-v/UPSTREAM.json)
- [Measurements](risc-v/results/direct)
- [Recursive RISC-V tree runner](risc-v/tree-bench/README.md)
- [Recursive tree measurements](risc-v/results/trees/)
- [Article LaTeX figures and source data](results/mine/figures/)
- [ML-DSA review](risc-v/reviews/mldsa-security.md)
- [FORS review](risc-v/reviews/fors-security.md)
- [Recursive tree integration review](risc-v/reviews/riscv-tree-security.md)
- [Python leanISA reduction with specialised Keccak](leanISA/reduction/README.md)
- [leanISA reduction review](leanISA/reduction/review/REVIEW.md)
- [Standard Raccoon-128-1 RISC-V port](risc-v/raccoon/README.md)
- [Raccoon-G source and verification specification](risc-v/raccoon-g/SPEC.md)
- [Raccoon experiment plan and approved study](risc-v/raccoon-study/PLAN.md)

The backend is `leanEthereum/leanVM`, branch `riscv-exploration`, commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. Vendor checkouts are unchanged.

The previous implementation and measurements are preserved in [leanISA/](leanISA/).
Root links to its original source and Cargo files remain for compatibility;
build the new implementation explicitly with `risc-v/bench/Cargo.toml`.

The [capacity recheck](risc-v/results/reaudit/README.md) corrects the interpretation
of the original counts: an unchanged Falcon guest also proves 33 distinct
signatures from another input corpus, and a separately reviewed ML-DSA storage
optimization proves seven. The original fixed-prefix data remain available.
