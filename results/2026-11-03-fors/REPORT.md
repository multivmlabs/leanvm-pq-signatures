# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| fors-keccak-research | 1 | 7,534 | 0.026 | 7.766/4.195 | 234.4 | 0.05 | 38.6 |
| fors-keccak-research | 16 | 120,201 | 0.067 | 8.444/4.720 | 288.8 | 0.28 | 237.9 |
| fors-keccak-research | 64 | 480,729 | 0.177 | 9.016/4.992 | 326.7 | 0.99 | 360.7 |
| fors-keccak-research | 256 | 1,922,851 | 0.639 | 11.961/5.169 | 352.3 | 3.86 | 400.8 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.
