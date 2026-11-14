# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| ethdilithium2-expanded-keccak-prng-v1 | 1 | 6,854,815 | 5.318 | 100.130/6.200 | 341.0 | 5.85 | 0.2 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.
