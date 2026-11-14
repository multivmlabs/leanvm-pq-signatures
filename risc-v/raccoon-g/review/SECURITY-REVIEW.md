# Independent review: Raccoon-G HD profile under RISC-V

Reviewed 2026-11-09 using the `zkvm-security-review` workflow. Scope: the new Rust verification guest, strict encoding and norm predicate, public-output binding, host fixture boundary and correspondence to the approved authors' executable source. This is a bounded implementation review, not an audit of leanVM's proof system or an independent lattice-parameter security estimate.

**Result:** no actionable verifier bypass, arithmetic discrepancy or public-input omission was found in the reviewed strict profile. The guest implements the inspected authors' executable verification equation, including rounding the unrounded public key during verification. Canonical parsing and the exact integer norm intentionally differ from the authors' permissive and floating-point boundary behavior. Those differences are explicitly identified by the profile domain and executable.

The complete paper remains unread because its download has not succeeded. This review therefore does **not** establish paper conformance, the stated parameter security level, or the maximum secure derivation depth. No STARK, witness-capacity plan, timing, proof-size or tree-aggregation experiment was run.

## Identity and intended statement

| Component | Reviewed identity |
| --- | --- |
| Authors' source | `p-11/lattice-hd-wallets`, commit `461a5ed9b6d57e3bf8c381be3bb79325ab21d906` |
| leanVM RISC-V backend | `06e5c9cd6981103786f9d0a17324241b559a50d3` |
| Final guest ELF SHA-256 | `24816e301dbcf77167e8c0d7a5090f93ba7e1ba448c6cc79ed4664ade2e8a56d` |
| Profile | `raccoong-hd-authors-poc-strict-v1` |
| Norm threshold | `25650475979193785709999263840` |

The final ELF is 27176 bytes. All 24 source hashes and all five correctness-fixture hashes in `build-manifest.json` independently matched the files, as did the ELF hash. The authors' source checkout is clean. The manifest records the compiler identity, profile and software Keccak kernel. The final Clippy-driven changes to chunk iteration were reviewed as preserving complete array coverage. The earlier `c018801c...` ELF is not the final reviewed artifact.

Provers control count, public keys, messages and signature witnesses through advice. The guest checks a nonempty batch of at most 64 compact records. For every ordered pair, it proves signature verification under this exact profile. It commits the 32-byte profile domain, count as LE64, and every full 16144-byte public key and 32-byte message. The receiver must pin this executable and recompute the public output from the intended pairs.

The guest proves neither honest key generation nor a path from a given root/xpub. The host fixture helper tests master, hardened, non-hardened and public-only derivation, but no derivation chain is part of this signature-verification statement. That distinction is necessary for wallet and account-authorization claims.

## Executable source correspondence

The reviewed source profile has `N=256`, `q=562949953438721`, `k=ell=9`, challenge weight 23, public-key rounding parameter 35 and commitment rounding parameter 38. Public keys contain the full unrounded vector `t`, as required by the authors' additive wallet key operation.

The authors' executable `_verify_with_unrounded_public_key` actually rounds that vector to modulus 16384, scales it by `2^35`, and uses this scaled vector in `A*z-c*t_scaled`. This differs from the surrounding source comments that describe direct use of unrounded `t`. The Rust guest follows the executable expression. It still hashes the **full** canonical unrounded public key into `tr`, so the dropped low bits are bound to the message.

Matrix expansion uses SHAKE128 with the exact eight-byte `A,row,column` header, seven-byte candidates masked to 50 bits and rejection at `q`. These sampled values are already the matrix's NTT-coordinate representation in the authors' implementation. The guest does not apply a second transform to them. Challenge expansion uses SHAKE256 with the exact `c,23` header and the authors' repeated two-byte sampling and sign convention. Commitment hashing uses the exact `hdr24('H',32,16128,0)` bytes and seven-byte encoding of **every** rounded commitment coefficient, even though hints use two bytes on the signature wire.

Full public-key hashing, `mu`, challenge sampling, matrix expansion, polynomial arithmetic, norm checking and final challenge comparison execute inside the guest. No host acceptance bit, supplied `mu`, transformed key or pre-expanded matrix is trusted.

## Strict decoding and integer bounds

The typed public-key and signature arrays require exactly 16144 and 20768 bytes. Both are whole numbers of 64-bit words; there are no extra transport-padding bytes. The decoder covers all 2304 public-key coefficients, all 2304 response coefficients and all 2304 hint coefficients. Seven-byte values must be below `q`; hints must be below 2048. High unused bits therefore cannot create accepted residue aliases. No separate attacker-controlled length changes these offsets.

The centered magnitude rule matches the source's canonical representatives. For even hint modulus 2048, residue 1024 has magnitude 1024; that single term already exceeds the norm bound and rejects. Canonical hints near 2048 represent negative small integers and contribute their correct squared magnitudes.

For a canonical response coefficient, its magnitude is less than `2^49`; its square fits below `2^98`. For a canonical hint, the scaled square is at most `1024^2 * 2^76 = 2^96`. The running sum is checked after each coefficient, so before another addition it is at most the approximately 95-bit threshold. Each next sum remains far below `2^128`. Neither a 64-bit intermediate multiplication nor a wrapping norm accumulation is used.

The selected squared threshold is the exact floor of the ideal real-valued expression displayed in `SPEC.md`. The rational certificate in `norm_bound_check.py` was reviewed: the positive Taylor partial sum bounds `exp(1/4)` below, its omitted tail is bounded by a geometric series, and integer-square-root intervals bound the two nonintegral square roots. Squaring the resulting positive radius interval gives the same floor at both ends. An additional independent 150-digit `decimal` calculation gave the same integer.

This validates evaluation of the chosen expression only. The authors' implementation uses binary64 comparisons and accepts the threshold-plus-one controls. The port deliberately rejects those values. The source's depth-1000 parameter and the Sage script's different derivation quantity remain unresolved at the security-analysis level. The strict profile is not described as bit-for-bit identical to the floating-point verifier or as paper certified.

## Arithmetic and hash controls

New review-only native controls compare the guest code with independent Python `hashlib` and arbitrary-precision integer oracles. These do not import the implementation's matrix or NTT helpers:

- **28 SHAKE controls** use rates 136 and 168, input lengths around lane and sponge boundaries, segmented absorption and 401-byte segmented squeezing. Every byte matches Python SHAKE128 or SHAKE256.
- **All 81 expanded matrix polynomials** match independent SHAKE128/rejection sampling, including all 20736 residues. This covers the entire 9-by-9 indexing scheme, rather than only `A[0][0]`.
- All 256 challenge coefficients match independently sampled position/sign values and exact weight 23.
- Montgomery constants match their defining integer identities. Multiplication uses canonical operands below `q`; the 128-bit product and reduction sum fit below `2^115`. A single final subtraction is sufficient for Montgomery reduction. Additions, subtractions and butterflies preserve canonical internal residues.
- Five NTT cases cover zero, identity, `X^255*X=-1`, maximum canonical residues and dense deterministic polynomials. All 1280 forward values match direct Horner evaluation at the specified bit-reversed roots. All 1280 round-trip coefficients and 1280 product coefficients match the original inputs and schoolbook negacyclic multiplication.

The harness uses the actual public arithmetic/XOF functions from the guest crate. It outputs raw values; `independent_oracle.py` derives expectations independently. Evidence is `independent-arithmetic-{dump,validation}.json` and `control-harness/`.

The implementation's separate nine-test suite and 20 interpreter executions were inspected. Its exact-bound and bound-plus-one controls have independently reconstructed correct challenge equations, so their rejection distinguishes the norm predicate from a failed hash comparison. Its honest and derived-key signatures originate in the pinned authors' Python code, with explicitly fixed public test randomness. Fixture generation records one attempt and refuses a failed deterministic sample rather than silently retrying with different coins.

## Actual final-ELF public-binding controls

Twelve new controls execute through the unchanged final ELF as well as native verification. They add independent checks of the following:

- Two distinct canonical key/message/signature records accept. Their reversed order and each individual record also accept with different outputs.
- Changing the second record's final message byte rejects.
- Changing a low bit of the second record's final public coefficient rejects **even though its rounded/scaled verification coefficient is unchanged**. This specifically tests binding of the full unrounded key through `tr` and `mu`.
- Changing the second challenge, final hint, final public residue to `q`, final response residue to `q`, or final hint residue to 2048 rejects.
- Exchanging the two signature witnesses while keeping the original public pairs rejects.

Every successful output, and the independently expected output for every rejected input, matches a raw-byte Python `hashlib.blake2s` calculation of the exact profile-domain/count/ordered-pair sequence. This does not rely on using the host helper as the sole digest oracle. Results and exact input hashes are in `independent-vectors/{vectors.json,execution.tsv,validation.json}`.

The guest's advice region has 524288 words. A record is 4618 words, so the transport policy of 64 records requires 295553 words including the count and fits. This arithmetic checks transport correctness only; it is not a witness-capacity estimate, execution plan or measured batch limit.

## Reproduction and remaining limits

From the project root, native arithmetic inspection and actual interpreter-only controls are:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
CARGO_TARGET_DIR="$PWD/.cache/raccoong-review-target" \
cargo +stable run --release --locked --offline \
  --manifest-path risc-v/raccoon-g/review/control-harness/Cargo.toml -- dump

CARGO_HOME="$PWD/.cache/riscv-cargo" \
CARGO_TARGET_DIR="$PWD/.cache/raccoong-review-target" \
cargo +stable run --release --locked --offline \
  --manifest-path risc-v/raccoon-g/review/control-harness/Cargo.toml \
  -- run risc-v/raccoon-g/review/independent-vectors

python3 risc-v/raccoon-g/review/independent_oracle.py
```

The saved dump is what the final command checks. The harness contains no prover call, witness planner, benchmark statistics or timer.

No additional actionable implementation finding remains from this scope. This conclusion applies to the pinned strict source profile and reviewed ELF. It does not establish the lattice assumptions or secret distributions, justify the depth/security parameters, audit a production wallet implementation, prove HD-path membership, or prove the compiler or leanVM correct.

After user approval, full proof generation and a public-only proof receiver still need end-to-end controls. Those must bind the approved ELF and every intended pair, reject statement/profile mutations, and settle all terminal claims during recursive-tree verification. The complete PDF is still required before claiming correspondence to the paper's algorithms or security theorems.
