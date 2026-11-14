# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ethfalcon-512-keccak | 1 | 1,608,881 | 0.820 | 97.172/unmeasured | 308.2 | 2.32 | 1.2 |
| ethfalcon-512-keccak | 2 | 3,219,597 | 2.193 | 83.157/unmeasured | 321.1 | 3.69 | 0.9 |
| ethfalcon-512-keccak | 3 | 4,831,916 | 4.565 | 96.346/unmeasured | 341.8 | 5.11 | 0.7 |
| ethfalcon-512-keccak | 4 | 6,445,946 | 4.650 | 105.508/unmeasured | 345.4 | 7.68 | 0.9 |
| ethfalcon-512-keccak | 5 | 8,061,643 | 5.368 | 99.085/unmeasured | 349.6 | 8.00 | 0.9 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.

Unsupported or failed workloads:

- ethfalcon, N=6: error: prove: WitnessOutOfRange { log_committed: 29 }
