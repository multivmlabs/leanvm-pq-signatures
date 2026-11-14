# Aerie: paper and compatibility notes

Checked 4 November 2026 against the [paper](https://eprint.iacr.org/2026/2501), its [author-hosted mirror](https://assets.layerzero.network/pdf/aerie.pdf), and the local [Aerie v0.2.0 source](../vendor/aerie/README.md), commit `49b6c212c209286c536196f53618823ffdf0e899`.

The repository's `paper/aerie.pdf` is the 15 October 2026 version, 58 pages, SHA-256 `efc7038f38102e3c854f0288d4ecfad0f1560da8d2a9e8be7a4b2e530d5c9d5b`. Page numbers below are printed page numbers, one greater than zero-based PDF indices.

## What is proved

Aerie aggregates one homogeneous Falcon parameter set, either 512 or 1024, into one proof. It uses four Akita commitment groups, three sum-check stages and one batched opening. For each key/message/salt record it proves the ring equation, the exact Falcon norm bound and encodability in the fixed padded format. It does not prove the message hashes: its verifier computes them from public records. The final proof establishes existence of valid canonical signature bytes; it does not commit to one original signature byte string. See paper Sections 3 and 4, and [the pinned specification](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/falcon.md).

For Falcon-512, the parameters are `n=512`, `q=12289`, squared norm bound `34034726`, signature length 666 bytes, coefficient bound `|s2[j]|<=2047`, and unary-bit budget `sum(floor(abs(s2[j])/128))<=392`. Falcon-1024 uses norm bound `70265242`, signature length 1280 bytes and unary budget 696. These encoding conditions are stricter than accepting every variable-length compressed signature.

The shipped framing is the proposed FN-DSA style implemented by `fn-dsa` 0.3.0, with raw messages and empty context:

```text
hpk = SHAKE256(canonical_public_key_bytes, 64)
target = HashToPoint(salt40 || hpk || 0x00 || 0x00 || message)
```

Original round-3 `salt || message` framing and ETHFalcon's Keccak counter stream are unsupported by the released API. The algebraic proof takes the target as public data, so a verifier adapter can change the framing, but it must preserve the matching native input checks, transcript binding and explicit variant identity. Such an adapter is additional implementation work. The paper's aggregate-unforgeability theorem must not silently be attributed to a changed signature variant. Neither the paper nor the repository claims final FIPS 206 compatibility.

The count is 1 to 65536. The batch pads to `max(next_power_of_two(N),8)` for Falcon-512 or a minimum of 4 for Falcon-1024. Inactive rows are zero; they have no messages or salts. Thus the requested 1/10/30/70/100 Falcon-512 cases use 8/16/32/128/128 physical rows. Akita separately extends physical commitment tables to at least 8192 cells. These floors need actual small-batch measurements.

## Published native measurements

Paper Table 2, page 22, reports the following Falcon-512 measurements. These are published upstream figures, not leanVM results and not measurements on this project's M4 Pro.

| Signatures | Prove, 16 threads, s | Verify, one thread, ms | Verify, 16 threads, ms | Aggregate with individual salts, KiB | Estimated common-salt aggregate, KiB | Peak RSS, MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 1024 | 0.13 | 5.5 | 4.6 | 101.8 | 61.8 | 198 |
| 2048 | 0.17 | 7.5 | 5.2 | 142.8 | 62.8 | 280 |
| 4096 | 0.21 | 11.1 | 6.0 | 222.9 | 63.0 | 418 |
| 8192 | 0.26 | 16.9 | 6.7 | 384.7 | 64.7 | 658 |
| 16384 | 0.39 | 29.0 | 8.2 | 704.8 | 64.9 | 1126 |
| 32768 | 0.65 | 53.6 | 11.6 | 1346.4 | 66.4 | 2113 |
| 65536 | 1.07 | 101.2 | 15.8 | 2626.6 | 66.7 | 4127 |

The machine is Apple M4 Max, 12 performance and 4 efficiency cores, 64 GiB, macOS 27.0.1, Rust 1.95.0. Aerie is release v0.2.0; Akita is revision `e023b6a4`. Times are medians of seven runs. Key generation and signing are excluded. Proving includes native input validation, public-record binding, witness generation, commitments, projections, sum-check and opening, but excludes commitment-key generation. Verification starts from encoded aggregate plus ordered public keys/messages and ends with acceptance. Sizes include headers and salts, but exclude supplied keys/messages.

At 32768 records, one-thread proving is 4.3 seconds. Native PQClean verification is 519 ms for the batch and native signing 3.2 seconds on one core. Paper Section 6.2 attributes approximately 70% of one-core Aerie verification to key hashing and hash-to-point evaluation and 14% to Akita opening verification. Per-record public-key inner products also remain. Verification therefore has linear work in the record count despite the succinct algebraic proof.

The proof itself is about 66 KiB at this batch size; the other 1280 KiB is 40-byte salts. Common-salt sizes are estimates obtained by subtracting `40*(N-1)`, not measurements establishing a production signing policy. Shared salts require signer changes and a separate fixed-target unforgeability assumption, persistent cached or deterministic responses, and the key-prefixed framing. Aerie includes no production common-salt signer. Existing signatures with independent salts cannot be converted by merely deleting their salts.

## What the leanSTARK wrapper must do

The natural composition is `Falcon signatures -> Aerie proof -> leanVM proof of Aerie verification`. The outer public statement must bind the intended ordered keys/messages, count, parameter set, framing and trusted Aerie setup/catalog/profile identity. The Aerie proof and its salts can be outer witnesses. A receiver still derives keys and messages from transactions/account policy; it need not receive the original signatures or salts if the complete verifier is proved.

This moves public-key hashing, hash-to-point, record binding, all Fiat-Shamir checks and work nonces, canonical wire decoding, projections, sum-check and the entire Akita opening verifier into the outer proved computation. Passing host-computed targets or a host `true` result without constraining their derivation would prove a weaker relation.

A deliberately split receipt can instead require receivers to derive and authenticate public values themselves, as this project's Dilithium frontend does for expanded keys. For Aerie targets that retains the public salts and native hashing work. It needs an explicit binding of those derived values to the guest statement and is a different measurement from proving the complete verifier with salts hidden inside the outer witness. A prover-supplied preprocessing result alone is insufficient.

Aerie uses the prime field `p=2^64-59` and quadratic challenge extension `Fp2`. These are foreign to leanVM's binary field. A faithful custom-ISA port needs bounded limb/carry arithmetic for modular products, inverses, comparisons and centered representatives, plus the PCS arithmetic. The existing small-modulus `g^x` encoding cannot cover full 64-bit-prime products: products reach 128 bits and exponent reduction can alias them. Native verification milliseconds cannot be converted into leanVM cycles or prover seconds without a constrained port or actual VM execution. A scalar Rust verifier build is a useful starting point for a RISC-V branch, but is not itself a custom-leanISA guest.

An outer proof may omit the inner proof bytes and salts from transport, so common-salt signing is unnecessary for that transport goal. Actual outer size, runtime, memory and capacity must be measured. A large batch may still need a tree if the constrained verifier exceeds the pinned backend's commitment limit.

## Security scope

Aerie's paper proves knowledge soundness in the classical random-oracle model under the stated Module-SIS assumptions and then derives aggregate unforgeability under its signing model. This is not a QROM theorem. Wrapping it preserves its lattice assumptions; a hash-based outer proof does not make a forged accepting Aerie proof impossible after those assumptions fail. Paper Section 7 also notes that a recursive verifier reintroduces the composition analysis avoided by standalone Aerie.

The repository is a research release and explicitly has not passed production acceptance. Neither Aerie nor this project's current leanVM proofs claim zero knowledge. Witness omission alone establishes no privacy guarantee. See the pinned [release policy](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/specs/release-policy.md) and [verifier API](https://github.com/a16z/aerie/blob/49b6c212c209286c536196f53618823ffdf0e899/crates/aerie-verifier/src/lib.rs).
