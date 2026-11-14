# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ethdilithium2-expanded-keccak-prng-v1 | 1 | 6,854,815 | 1.722 | 90.843/6.400 | 341.0 | 8.84 | 0.6 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.

Unsupported or failed workloads:

- ethdilithium, N=2: error: prove: WitnessOutOfRange { log_committed: 29 }
