# Independent review: original Raccoon RISC-V guest

Reviewed 2026-11-09. Scope: compact input decoding, signature-verification relation, integer/NTT operations, guest public-output binding and build provenance. The review uses the `zkvm-security-review` workflow. It does not audit leanVM's core proof system or establish a production deployment.

**Result:** the reviewed guest implements the pinned official reference verification relation with a stricter, bounded byte decoder. The independent controls found no signature-check bypass or public-input omission in that relation. The review identified a **NIST PDF versus official reference conformance conflict**. On 2026-11-09 the user explicitly selected official reference interoperability with the PDF discrepancies documented. The implementation follows that approved policy; it does not claim literal PDF equivalence.

No proving, timing, proof-size, capacity or aggregation experiment was run. All executions below are correctness-only native or actual RISC-V interpreter controls. Full proof-consumer controls remain pending the user's benchmark approval.

## Reviewed identity and intended claim

| Component | Identity |
| --- | --- |
| leanVM RISC-V backend | `06e5c9cd6981103786f9d0a17324241b559a50d3` |
| Official Raccoon repository | `e789b4b72a2b7e8a2205df49c487736985fc8417` |
| NIST PDF SHA-256 | `7dae8c58264599fc65d0c31421166732d6253fe3cb5665034316c25c79998926` |
| Reviewed ELF SHA-256 | `b8b78438d96258c436a4a34f5f40505d469555bb29d289936e01c863dd1f7e6a` |
| Guest profile | Original Raccoon-128-1, fixed 32-byte messages |

Both vendor checkouts were clean. All 52 source hashes, the ELF hash and the NIST PDF hash in `build-manifest.json` independently matched their files. The manifest records the target, Rust and C compiler identities and compile flags. This confirms which artifact was reviewed; it is not an independent reproducible-build demonstration.

The intended statement is: under the approved ELF, each signature in a nonempty ordered batch verifies for its corresponding compact public key and 32-byte message. The public output commits to the domain, count and every ordered key/message pair. Signatures are witnesses. Provers control all advice, including keys, messages, signatures and count. The receiver must supply the intended pairs and pin the executable. The guest does not establish an account's authority, freshness or transaction semantics independently of those external pairs.

The one-share parameter controls the fixture signer. The verification relation and signature/public-key serialization are shared across masking share counts. This does not implement a threshold-signing protocol.

## Finding R1: NIST PDF Algorithm 9 differs from the reference and guest

Status: **reproduced conformance conflict; interoperability policy explicitly resolved by the user**. This is not a demonstrated cryptographic forgery or STARK soundness failure.

The requested NIST PDF, page 20, Algorithm 9, specifies the SHAKE input order:

```text
hdr_h || serialized_w || mu
```

The pinned official C `xof_chal_hash`, official Python `_chal_hash`, and this guest instead compute:

```text
hdr_h || mu || serialized_w
```

The PDF was visually checked, not only text-extracted. The rendered evidence is `nist-page20.png`. This is a real byte-level difference: both strings have known fixed component lengths, and swapping their order changes the challenge digest.

Two independent vectors isolate it without relying on the reference's parser or hashing helper. Set the canonical public key and response/hint vectors to zero, choose a fixed 32-byte message, and compute the two possible challenges with Python `hashlib.shake_256`. The algebraic verification commitment is zero under both variants, so no challenge polynomial assumption is needed to distinguish the hash order.

| Control | Native port | Actual approved RISC-V ELF |
| --- | --- | --- |
| Reference order `hdr || mu || w` | Accept | Accept |
| NIST PDF order `hdr || w || mu` | Reject | Reject |

The ordinary transcript from the first row is therefore not a valid signature under a literal Algorithm 9 implementation, while the second row is. These algebraic zero-key inputs are conformance controls, not key-generation fixtures or benchmark material. A trivially signable zero public key is not being presented as a security attack.

Reproduction and immutable evidence:

- `independent-vectors/vectors.json`: independent challenges, input hashes and expected outcomes.
- `independent-vectors/{reference-order,nist-pdf-order}.bin`: exact input bytes.
- `independent-vectors/execution.tsv`: native and unchanged ELF outcomes.
- `control-harness/`: interpreter-only consumer, with no prover invocation.

The same PDF's Algorithm 10 also contains discrepancies: its loop condition is printed as `||c||_1 <= omega`, despite the prose and inline comment requiring exactly `omega` nonzero coefficients, and its sign assignment is `(-1)^b0`. The reference instead stops at weight 19 and uses `2*b0-1`. The loop is internally contradictory in the PDF; the opposite sign convention is an interoperability difference. The specification should enumerate these points rather than asserting all algorithms are identical.

Resolution, 2026-11-09: the user selected **official reference interoperability and documentation of the PDF discrepancies**. `SPEC.md` and `README.md` now state this policy. The reviewed ELF is unchanged, so the interoperability and correctness evidence remains applicable. The PDF conflict itself remains a source fact; approval does not make the two byte relations identical or prove which document contains the intended correction. A future literal-PDF variant would need separate signing, vectors and a profile identity. No implementation files were modified by this review.

## Byte decoding and bounds

The adapter's fixed arrays establish 2256 public-key bytes and 11524 signature bytes. The public-key decoder consumes the entire compact key and hashes those exact bytes. The adapter rejects every packed coefficient outside `Z_125`, including the final coefficient; there are no unused public-key bits because `5*512*7` is byte-aligned.

The bounded signature reader advances only when a bit is requested. It implements the specified low-bit-first unary magnitudes and sign rule, omits sign bits for zero, enforces hint/response infinity bounds while decoding, and verifies every remaining padding bit. It handles a payload ending exactly on the final available bit without fetching an extra byte. The four additional word-transport bytes are separately checked for zero. These properties address the pinned reference decoder's byte-aligned padding and final-bit issues.

The existing independent Python boundary controls were inspected: the exact-full signature really consumes the full fixed allocation, and the byte-aligned control leaves whole trailing bytes whose nonzero alteration must reject. Neither special input is reachable from the ordinary benchmark fixture function.

The original `CheckBounds` is retained. In particular, it floors each absolute response coefficient by `2^32` before squaring. Replacing that with a differently rounded Euclidean norm would change the relation. For all values admitted by the local decoder, `|h_i| <= 2` and `|z_i| <= 41954689765971`. Even the maxima across all coefficients keep the scaled sums far below signed 64-bit overflow. Hint scaling is by `2^24`. The reference checks the specified bound `14656575897`; it does not use unchecked floating-point norms.

## Arithmetic, hashes and constrained execution

Public-key hashing, message hashing, challenge generation, SHAKE rejection sampling, matrix expansion, NTTs, multiplication, rounding and norm checks are performed in ordinary guest instructions. There is no host verification Boolean, supplied expanded matrix or trusted `mu`. The software Keccak replacement changes the permutation kernel and retains the reference absorption, padding and domain headers. The engineer's full-state differential test was inspected; it compares all 25 lanes, including zero and all-one states.

An additional independent arithmetic oracle was run against the unchanged native C NTT. `independent_ntt.py` uses arbitrary-precision Horner evaluation at the specified roots and schoolbook negacyclic multiplication, rather than another NTT. Five cases cover zero, identity, the `X^511*X = -1` boundary, maximum canonical residues and dense deterministic polynomials. All 2560 forward coordinates, 2560 round-trip coefficients and 2560 product coefficients matched. `independent-ntt.json` records the evidence. This validates native arithmetic with the production C wraparound flags, not a complete compiler proof for every RISC-V input.

The reference intentionally takes low limbs in Montgomery arithmetic. `-fwrapv` defines the signed multiplication/addition wraparound compiled here. The decoded input bounds and lazy butterfly ranges keep the remaining signed 64-bit operations and public-key shifts in range. Signed right shifts use the recorded compiler/target arithmetic shift semantics. The existing actual guest controls cover the optimized artifact, including nontrivial reference-generated signatures and norm failures with consistent challenge equations.

## Public statement checks

The guest commits the scheme domain, checked count and every public key/message pair, in order, after checking that record's signature. Host `expected_output` builds the same byte sequence from `PublicRecord`, not from a prover's claimed digest or acceptance bit. The 64-record maximum is an advice transport limit, not a measured prover maximum.

Eleven new binding/input controls plus the two hash-order controls were executed through the unchanged ELF. The new controls include two distinct reference-generated keys/messages, their reversed order, each single record, mutations in the second record's final key byte and final message byte, the final packed public-key coefficient, a matrix-seed byte, the challenge, swapped signature witnesses and nonzero final signature padding. Every expected acceptance/rejection matched both native verification and actual guest execution.

For all 13 controls, the output digest was independently computed from raw bytes using Python `hashlib.blake2s`, including the exact domain padding and little-endian count. Every successful guest output matched. The two-record, reversed and single-record outputs differ. This is independent of the host helper's use of the SDK digest implementation. Details are in `independent-vectors/{binding-vectors.json,validation.json,execution.tsv}`.

To reproduce the interpreter-only controls from the project root:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
CARGO_TARGET_DIR="$PWD/.cache/raccoon-host-target" \
cargo +stable run --release --locked --offline \
  --manifest-path risc-v/raccoon/review/control-harness/Cargo.toml \
  -- risc-v/raccoon/review/independent-vectors
```

## Limits and follow-up

The new controls supplement, rather than replace, the implementation's eight tests and 17 interpreter executions. No additional guest verifier bypass was found within this bounded review. R1's implementation policy is resolved as above. That conclusion does not remove the underlying PDF/reference discrepancy, prove the compiler correct or audit leanVM's underlying constraints.

A production STARK and recursive-tree receiver have not been exercised for this scheme because the user required approval before experiments. After approval, those controls must verify the pinned ELF and every intended key/message pair with a public-only receiver, reject changed count/order/source identity and terminal polynomial claims, and verify the entire recursive receipt. No verification timing or scalability conclusion is supported by this review alone.
