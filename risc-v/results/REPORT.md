# RISC-V signature batch results

Apple M4 Pro, 24 GiB RAM, eight total prover threads. One warmup and three measured fresh proofs per count.

**These are original-corpus measurements, not universal capacity limits.** The [capacity recheck](reaudit/README.md) proves 33 Falcon signatures from a different valid corpus with the unchanged program, and seven ML-DSA signatures under a separately reviewed storage optimization. Original raw measurements remain unchanged.

The proving and verification columns are medians. RSS is the whole-process resident high-water mark, including setup/warmup. Large-batch timing variability is retained in raw samples and figure range bars.

| Scheme | Batch | Proving, s | Proof, KiB | Verification, ms | Peak RSS, GiB | Witness words |
|---|---:|---:|---:|---:|---:|---:|
| Falcon-512 | 1 | 0.102 | 314.21 | 1.84 | 1.06 | 7,916,072 |
| Falcon-512 | 2 | 0.203 | 334.90 | 1.90 | 2.05 | 15,506,616 |
| Falcon-512 | 4 | 0.377 | 345.24 | 1.99 | 3.94 | 30,687,672 |
| Falcon-512 | 7 | 0.532 | 315.25 | 1.98 | 4.71 | 36,539,320 |
| Falcon-512 | 8 | 0.764 | 359.46 | 2.08 | 7.62 | 61,049,784 |
| Falcon-512 | 16 | 4.197 | 372.33 | 2.67 | 13.15 | 121,776,264 |
| Falcon-512 | 24 | 6.843 | 350.30 | 2.66 | 13.47 | 141,250,696 |
| Falcon-512 | 28 | 7.470 | 351.37 | 2.76 | 14.22 | 145,182,856 |
| Falcon-512 | 29 | 37.772 | 394.26 | 5.95 | 15.55 | 243,224,712 |
| Falcon-512 | 30 | 37.656 | 392.64 | 4.65 | 15.33 | 243,224,712 |
| Falcon-512 | 31 | 43.305 | 393.79 | 3.67 | 15.93 | 243,229,192 |
| Falcon-512 | 32 | 56.922 | 394.29 | 5.34 | 15.35 | 243,229,192 |
| ML-DSA-44 | 1 | 0.689 | 343.18 | 2.04 | 6.53 | 51,534,184 |
| ML-DSA-44 | 2 | 1.362 | 354.72 | 2.05 | 12.66 | 102,399,592 |
| ML-DSA-44 | 3 | 2.078 | 379.42 | 2.29 | 15.98 | 130,973,288 |
| ML-DSA-44 | 4 | 20.266 | 378.01 | 5.26 | 16.16 | 204,130,408 |
| ML-DSA-44 | 5 | 58.055 | 400.13 | 6.65 | 16.67 | 257,345,640 |
| ML-DSA-44 | 6 | 79.425 | 402.04 | 6.28 | 16.08 | 261,277,800 |
| FORS | 1 | 0.598 | 326.15 | 1.97 | 5.18 | 42,128,704 |
| FORS | 2 | 1.166 | 338.31 | 2.10 | 10.07 | 83,194,112 |
| FORS | 3 | 1.391 | 351.30 | 2.19 | 11.78 | 97,875,040 |
| FORS | 4 | 8.069 | 361.15 | 2.86 | 15.32 | 165,324,896 |
| FORS | 5 | 21.461 | 374.27 | 4.18 | 15.56 | 194,689,112 |
| FORS | 6 | 38.259 | 374.02 | 3.57 | 14.91 | 194,689,112 |
| FORS | 7 | 54.965 | 381.08 | 4.44 | 16.05 | 212,148,312 |

## Capacity and verification evidence

Each next-count failure was attempted through both Program::measure and Prover::prove. These are commitment-cap rejections, below the guests' advice bounds. No failed proof size or time is extrapolated.

All accepted files were serialized, decoded and checked through full Program::verify. Public-only mutation controls are in [consumer-controls.json](consumer-controls.json). Independently reviewed guest boundaries are in [ML-DSA](../reviews/mldsa-security.md) and [FORS](../reviews/fors-security.md).

The points use one fixed deterministic corpus per scheme. Falcon uses the official same-message distinct-key corpus; the other two use distinct messages and keys. Fixture generation and signing are outside proving time. These workloads do not establish matched security levels, deployed wallet authorization, browser performance or EIP gas costs.

The official branch and dependency pins are in [UPSTREAM.json](../UPSTREAM.json). Guest build manifests record compiler/source hashes. Initial and final native runner identities are in the environment JSON files. The backend vendor checkout is unmodified.
