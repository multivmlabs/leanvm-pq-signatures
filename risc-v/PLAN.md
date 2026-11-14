# RISC-V signature study

Backend: official `leanEthereum/leanVM` branch `riscv-exploration`, commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. Keep the vendor checkout unchanged.

1. Archive the existing implementation and measurements under `leanISA/`.
2. Build compact-input ML-DSA-44 and FORS guests; reuse upstream Falcon.
3. Cross-check honest inputs and adversarial changes inside the actual VM.
4. Measure direct batches. Search the capacity boundary with `Program::measure`,
   then actually prove and fully verify the largest fitting batch and attempt the
   next count. A memory or framing failure is not a commitment-capacity result.
5. Record three measured fresh proofs after one warmup, exact serialized sizes,
   full verification time, process RSS, table counts, executable/source hashes,
   compiler versions, hardware and commands. Run memory-heavy provers serially.
6. Independent security agents review ML-DSA and FORS, including host/guest
   agreement, canonical encodings, statement binding and public-only consumers.
   Fix valid findings and rerun affected measurements.
7. Rewrite `articles/mine.md` around these three RISC-V implementations. Generate
   the figures from the measured results using LaTeX/PGFPlots. Retain the TeX,
   PDF, rendered images and the raw measurements. Do not run Aerie.

Plain proofs are used. Maximum batch means the measured boundary for this guest,
input schedule and backend, not a universal signature-scheme limit. FORS is the
specified few-time component, not a complete SLH-DSA signature.

## Completed

- Direct proofs produced, serialized and fully verified at 25 measured points.
- Largest verified batches: Falcon 32, ML-DSA-44 6, FORS 7.
- Actual next-count prover rejections: 33, 7 and 8 respectively.
- ML-DSA and FORS independently reviewed, including saved-proof consumers.
- 87 common public-only receipt controls passed; independent reviewer probes
  add 37 ML-DSA and 46 FORS receipt controls.
- `articles/mine.md` rewritten and three LaTeX/PGFPlots figures generated.
- Raw reports, proofs, public statements, build/source hashes and reproduction
  scripts retained under this directory. No Aerie experiment was run.

## Capacity re-audit correction

The completed counts above refer to the original fixture prefixes. They are not
universal limits. The 6 November re-audit proves a different valid 33-signature
Falcon batch with the unchanged guest/backend, and a seven-signature ML-DSA batch
under a separately reviewed constant-storage optimization. FORS's apparent
regression is explained by software Keccak versus the archived backend's proven
Keccak instruction; the archived 100-signature proof was reproduced. All raw
reports are retained, with new recheck evidence in `results/reaudit` and `reviews`.
