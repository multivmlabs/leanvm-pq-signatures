# Measured signature verification in leanVM

Median times; prover time includes VM execution and excludes compilation, fixture generation and serialization. Memory is the process high-water mark. These proofs are not zero knowledge. All sizes are bincode proof payloads, excluding statements and keys.

| Scheme | N | VM steps | Prove s | Verify cold/cached ms | Proof KiB | Peak GiB | Sig/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| fors-keccak-research | 1 | 7,534 | 0.030 | 7.924/unmeasured | 234.4 | 0.05 | 33.3 |
| fors-keccak-research | 2 | 15,045 | 0.035 | 7.804/unmeasured | 225.4 | 0.06 | 56.7 |
| fors-keccak-research | 3 | 22,554 | 0.040 | 7.756/unmeasured | 237.1 | 0.06 | 75.7 |
| fors-keccak-research | 4 | 30,063 | 0.043 | 7.654/unmeasured | 264.2 | 0.08 | 94.0 |
| fors-keccak-research | 5 | 37,577 | 0.048 | 7.654/unmeasured | 232.3 | 0.11 | 104.9 |
| fors-keccak-research | 6 | 45,087 | 0.096 | 9.103/unmeasured | 236.1 | 0.11 | 62.6 |
| fors-keccak-research | 7 | 52,599 | 0.060 | 7.949/unmeasured | 242.2 | 0.12 | 116.1 |
| fors-keccak-research | 8 | 60,109 | 0.058 | 7.760/unmeasured | 276.6 | 0.16 | 138.6 |
| fors-keccak-research | 9 | 67,623 | 0.062 | 8.059/unmeasured | 241.0 | 0.18 | 145.2 |
| fors-keccak-research | 10 | 75,132 | 0.071 | 8.001/unmeasured | 244.6 | 0.18 | 140.0 |
| fors-keccak-research | 11 | 82,641 | 0.064 | 8.026/unmeasured | 245.9 | 0.18 | 170.8 |
| fors-keccak-research | 12 | 90,155 | 0.069 | 7.975/unmeasured | 248.5 | 0.19 | 173.3 |
| fors-keccak-research | 13 | 97,665 | 0.067 | 8.120/unmeasured | 249.2 | 0.19 | 192.8 |
| fors-keccak-research | 14 | 105,176 | 0.071 | 8.012/unmeasured | 252.8 | 0.20 | 196.6 |
| fors-keccak-research | 15 | 112,687 | 0.079 | 8.173/unmeasured | 267.9 | 0.23 | 189.7 |
| fors-keccak-research | 16 | 120,201 | 0.085 | 8.179/unmeasured | 288.8 | 0.27 | 187.6 |
| fors-keccak-research | 17 | 127,709 | 0.095 | 8.144/unmeasured | 255.2 | 0.31 | 178.5 |
| fors-keccak-research | 18 | 135,219 | 0.096 | 8.306/unmeasured | 254.8 | 0.31 | 188.3 |
| fors-keccak-research | 19 | 142,733 | 0.102 | 8.078/unmeasured | 258.0 | 0.33 | 185.9 |
| fors-keccak-research | 20 | 150,242 | 0.100 | 8.249/unmeasured | 257.4 | 0.33 | 199.7 |
| fors-keccak-research | 21 | 157,751 | 0.102 | 8.301/unmeasured | 258.0 | 0.33 | 205.7 |
| fors-keccak-research | 22 | 165,265 | 0.105 | 8.400/unmeasured | 258.6 | 0.33 | 210.2 |
| fors-keccak-research | 23 | 172,775 | 0.104 | 8.249/unmeasured | 261.6 | 0.34 | 220.8 |
| fors-keccak-research | 24 | 180,287 | 0.108 | 8.175/unmeasured | 261.0 | 0.34 | 222.6 |
| fors-keccak-research | 25 | 187,797 | 0.103 | 8.379/unmeasured | 262.2 | 0.34 | 242.5 |
| fors-keccak-research | 26 | 195,311 | 0.102 | 8.269/unmeasured | 261.9 | 0.34 | 254.5 |
| fors-keccak-research | 27 | 202,820 | 0.112 | 9.146/unmeasured | 261.3 | 0.34 | 241.8 |
| fors-keccak-research | 28 | 210,329 | 0.145 | 9.349/unmeasured | 266.6 | 0.36 | 193.7 |
| fors-keccak-research | 29 | 217,843 | 0.189 | 8.603/unmeasured | 280.1 | 0.40 | 153.6 |
| fors-keccak-research | 30 | 225,353 | 0.199 | 8.564/unmeasured | 279.6 | 0.40 | 151.0 |

Raw samples, exact guest hash, public input, rate and parameters are in adjacent JSON files. Counts are direct batches, not recursive merges.
