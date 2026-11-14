# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ethfalcon-512-keccak | 1 | 1,630,904 | 0.484 | 83.120/6.171 | 310.7 | 2.51 | 2.1 |
| ethfalcon-512-keccak | 4 | 6,534,038 | 3.608 | 99.928/6.343 | 347.4 | 8.82 | 1.1 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.

Unsupported or failed workloads:

- ethfalcon, N=8: error: prove: WitnessOutOfRange { log_committed: 29 }
