# Measured costs, 3 November 2026

**Completed follow-up benchmarks:** [the article](../articles/leanvm-signature-aggregation.md) adds SHAKE Falcon, ML-DSA-44 and bounded recursive trees, with [methodology](../articles/leanvm-signature-aggregation-methodology.md), [raw records](article/) and a separate [tree verification format](../docs/tree-format.md). All primary, fan-in and leaf-size configurations completed successfully on 3 November 2026 at 20:59 UTC. The final suite and strengthened two-wrapper control passed at 21:02 UTC. The [interleaved mixed-scheme case](article/mixed/evidence.json) also passed as a single correctness demonstration, separate from the performance curves. This page retains the historical measurements, definitions and projections below.

**Later recursive result:** a [real 30-signature ETHFALCON aggregate](recursive-30/REPORT.md) now combines six five-signature leaf proofs into one 369,348-byte envelope. The comparison below retains the earlier direct-batch measurements and projections.

**Historical Falcon results:** the later encoding review found and removed an extra 625-byte compression policy that was stricter than the pinned C verifier. The Falcon measurements below retain that earlier guest's program hashes and three-sample timings. Current Falcon proof sizes and the compatibility correction are in the size-growth and encoding-review reports. The older proofs establish the documented restricted relation and should not be relabeled as proofs of the updated guest.

The project generates and verifies real leanVM proofs for all three experimental signature relations. Prime-field lattice verification is expensive in this binary-field VM. The pinned backend also limits direct batch size: Falcon batches of four succeed, eight fail; Dilithium one succeeds, two fail. These measurements preceded custom recursive merging, so large-count figures below describe projected leaf work. The later recursive experiment above is measured separately.

## Hardware and method

Apple M4 Pro, 24 GiB RAM, 12 logical CPUs, macOS 26.3 (25D125), Rust 1.99.0. Release builds use `target-cpu=native` and upstream's jemalloc allocator. `LEANVM_NUM_THREADS` is unset, using the pinned upstream pool's default. All proofs use inverse-rate logarithm 1. Each custom workload runs in its own process, with one warmup and three measured proofs, followed by verification. Only one prover job runs at a time. Background OS activity, thermal state and frequency are not controlled; these are preliminary single-machine measurements, not confidence intervals or cross-platform performance claims.

Custom proof time includes execution, witness construction and proving. It excludes guest compilation, input/key generation, serialization and native proof verification. Peak RSS includes the whole process and warmups. Cached verification prepares bytecode once and includes proof conversion; the one-time bytecode preparation is separately recorded. This distinction matters: rebuilding a lattice guest's bytecode adds roughly 75-80 ms, whereas checking its proof with cached bytecode takes roughly 6 ms.

The native backend is pinned to `575df819d9c857f38068cecf7b1640e0ce4bfb29`. Every JSON contains exact parameters, program hash, public input and raw timing samples. See [Falcon results](2026-11-03-falcon/REPORT.md), [Dilithium results](2026-11-03-dilithium/REPORT.md), [FORS results](2026-11-03-fors/REPORT.md) and [validation log](validation.log). Timing changes to cached verification did not change the guest or its proof relation; saved proofs were independently rechecked.

## Direct proof measurements

| Relation | Signatures | VM steps | Median proof s | Proof KiB | Cached verify ms | Process peak GiB |
|---|---:|---:|---:|---:|---:|---:|
| ethFalcon-512 | 1 | 1,630,904 | 0.484 | 310.7 | 6.17 | 2.51 |
| ethFalcon-512 | 4 | 6,534,038 | 3.608 | 347.4 | 6.34 | 8.82 |
| ethDilithium2, expanded key | 1 | 6,854,815 | 1.722 | 341.0 | 6.40 | 8.84 |
| Research FORS | 1 | 7,534 | 0.026 | 234.4 | 4.19 | 0.05 |
| Research FORS | 16 | 120,201 | 0.067 | 288.8 | 4.72 | 0.28 |
| Research FORS | 64 | 480,729 | 0.177 | 326.7 | 4.99 | 0.99 |
| Research FORS | 256 | 1,922,851 | 0.639 | 352.3 | 5.17 | 3.86 |

The three proving samples ranged from 0.437-0.498 s for Falcon one, 3.273-4.258 s for Falcon four, and 1.702-2.482 s for Dilithium one. Do not treat the median as a precise constant or assume linear scaling. In particular, the larger Falcon leaf had worse throughput in this trial. The raw samples retain this variability rather than hiding it in a single throughput claim.

The Falcon workload uses distinct upstream KATs with different message lengths; its first message is 33 bytes. Dilithium and FORS use 32-byte messages. The Falcon key commitment is its expanded canonical polynomial. Dilithium registers an expanded key identity; the guest does not prove expansion from the compact key. These formats and the unoptimized custom guests limit conclusions about what a purpose-built lattice arithmetization could achieve.

## Full leanSPHINCS and recursive reference

These are the unmodified upstream CLI results on the same host. Proving times below are the upstream reported means of three samples after warmup, not the custom harness's medians. Proof sizes are printed to 0.1 KiB by upstream. Raw commands, samples and logs are retained in [the upstream directory](2026-11-03-upstream/).

| Reference workload | VM steps | Prove s | Proof KiB | Cached verify ms | Peak GiB |
|---|---:|---:|---:|---:|---:|
| 1 leanSPHINCS | 11,544 | 0.053 | 260.2 | 6.913 | 0.493 |
| 16 leanSPHINCS | 38,621 | 0.0707 | 251.6 | 6.944 | 0.496 |
| 64 leanSPHINCS | 125,579 | 0.142 | 298.5 | 7.011 | 0.909 |
| 256 leanSPHINCS | 473,155 | 0.430 | 326.6 | 7.387 | 2.386 |
| 2-to-1 recursion, each child contains 16 leanSPHINCS | 553,114 | 0.263 | 288.9 | 9.508 | 1.392 |

The recursive row measures only the merge after child proofs exist. It is not a Falcon/Dilithium/FORS recursive measurement. Their program identities, bytecode obligations and child witness shapes differ. Full upstream leanSPHINCS also uses a substantially optimized guest and different parameters; the standalone research FORS row is not a security-equivalent replacement. Its default signature is 4,608 bytes; the pinned full leanSPHINCS signature is 4,276 bytes.

## Bandwidth and native verification

Proof sizes count only the serialized proof payload. Required claim manifests, public-key registration/distribution, shared bytecode, dependency frames, networking and transaction data are additional costs. Statements are commitments to ordered key/message claims; the receiver must know the intended claims. A digest alone is not a public list of authorized transactions.

- Falcon one: 656 bytes of compressed signature become a 318,192-byte proof. Falcon four: 2,631 signature bytes become a 355,712-byte proof. These small leaves increase bandwidth.
- Dilithium one: 2,420 signature bytes become a 349,184-byte proof. Its experimental expanded key encoding is 81,984 bytes, versus the upstream compact key's 1,312 bytes. Registration must validate and authorize that expanded identity; the cost cannot be silently omitted.
- FORS 64: 294,912 signature bytes become a 334,536-byte proof, before claim overhead. FORS 256: 1,179,648 signature bytes become a 360,800-byte proof, a 3.27x reduction in signature-only bytes. This does not supply an unlimited-use wallet scheme.

The separately timed upstream reference C verifiers took approximately 14 microseconds per Falcon signature and 98 microseconds per Dilithium signature for these inputs. These are 30-call means through Python ctypes, including compressed key/signature decoding. The independent Python verifiers validate fixture compatibility but are not optimized native baselines. Native key generation/signing and hardware-wallet/MPC signing costs are outside the proof timings.

## What 10,000 signatures would cost

The following are **leaf-only projections**, multiplying the measured median by the number of full-capacity leaves. They are not measurements of 10,000 signatures, a recursive aggregate, a distributed prover or parallel elapsed time. The last partial leaf is charged as a full leaf. No merge, networking, scheduling, claim-union or discard cost is included.

| Measured leaf used | Leaves for 10,000 signatures | Projected total leaf prover work |
|---|---:|---:|
| Falcon one | 10,000 | 4,835 s, about 81 minutes |
| Falcon four | 2,500 | 9,020 s, about 150 minutes |
| Dilithium one | 10,000 | 17,216 s, about 4.8 hours |
| FORS 256 | 40 | 25.6 s |

Use `pqbench project` with another measurement to change these assumptions. For binary merging of L leaves, L-1 merge operations are needed. At the time of these historical projections, custom recursive verification had not yet been implemented or benchmarked; the later measurements linked above count proof/envelope size, merge work and final deferred bytecode evaluations. [The recursion documentation](../docs/recursion-plan.md) describes that soundness boundary and its required tests.

## Practical implications

These experiments support measuring alternative PQ signatures behind a generic proof interface, with important engineering limits. On the current backend, an arithmetic-aware lattice guest or dedicated arithmetic support is the primary optimization opportunity. Smaller signature bytes do not imply cheaper proving. Generic STARKs can amortize verification and bandwidth at sufficient scale, but their custom recursive implementation and resulting bandwidth break-even point remain unmeasured here.

For hardware wallets and MPC wallets, signature production remains a separate design decision. An off-device prover can aggregate verification work; it does not create threshold signing or remove the need to enforce the canonical EIP-8141 transaction digest, chain, nonce, expiry and account policy. The project emits an explicitly experimental dependency-frame codec; current EIP-8288 generic leanSTARK dependencies remain reserved and these objects are not accepted by an unmodified client.
