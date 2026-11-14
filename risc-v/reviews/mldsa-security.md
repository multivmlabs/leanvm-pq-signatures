# ML-DSA-44 RISC-V guest: scoped independent security review

Review date: 2026-11-06. The review follows the zkVM security review skill's
guest/consumer, build provenance and composition checks. It covers the new
compact-input ML-DSA guest and its benchmark receiver. It does not audit the
entire pinned leanVM proof system or establish compiler correctness.

## Intended statement and attacker control

The intended claim is that every record in an ordered, nonempty batch has a valid
FIPS 204 ML-DSA-44 signature, in pure mode with empty context, on exactly 32 message
bytes under its exact 1,312-byte compact public key. The signature has exactly
2,420 bytes. The public output is BLAKE2s over a fixed 32-byte profile domain,
the LE64 count, then each compact key and message, in order. Signatures are
witnesses. This is an existence-of-valid-signatures claim, not proof of possession
of signing secret keys or a complete Ethereum account authorization policy.

The adversary controls all advice words, including keys, messages, signatures,
count and unused transport bytes. The receiver must choose the trusted program
and intended public claims independently. Duplicate records are permitted by
the relation; transaction uniqueness, nonce and account policy are separate
receiver duties. No privacy claim is made for the measured plain proofs.

## Source and executable identity

- leanVM/SDK: `06e5c9cd6981103786f9d0a17324241b559a50d3`.
- C reference: `vendor/ETHDILITHIUM` at
  `f9f4fe1d84e68304b425e054c273c276fe44ba11`.
- Both vendor checkouts were clean during inspection.
- Baseline ELF: 33,520 bytes, SHA-256
  `cbcc3929bae8f3e9ed1dd9035856d7bdaea87ae77a18ac87a7f5bcec53bf0fa4`.
- Final selected ELF: 33,520 bytes, SHA-256
  `73fa19d855adbd0ad6d8368260b5e1b173cc57a854e52624dd1b8e65d95f69d6`.
- Final build manifest SHA-256:
  `c88cda389a0069e0f683646a8700727ec99f18960a81f0da981429e3fcecd249`.
- Generated SHAKE C SHA-256:
  `c33021b9a3015084ac027ec9e0646948c0823e6e26885a112bc72f2f3612ccb0`.

All 44 source hashes in that manifest and the executable hash were independently
recomputed and matched. The [review snapshot](mldsa-review-snapshot.json) also
pins the common receiver source and review harness/scripts.

The build uses Rust `nightly-2026-10-03`, RV64IM/LP64, release optimization and LTO.
The C frontend is Apple clang 21.0.0. It emits RISC-V LLVM bitcode; Rust's linker
lowers that bitcode to guest machine code. The C flags explicitly select
`ETHDILITHIUM=0` and `DILITHIUM_MODE=2`. The build manifest records the source
closure, toolchain versions, flags and executable hash. No vendor source is
modified. Local adaptations suppress diagnostic signing prints and provide
freestanding byte memory functions on RISC-V. Their native test names are
prefixed, so they do not replace the native process's libc.

The final default `sdk-keccak` feature replaces only the C file's static
`KeccakF1600_StatePermute` function with an external call to
`leanvm_guest::keccak::f1600`. The C SHAKE absorb, finalize, squeeze and domain
padding logic is retained. The reviewer independently reconstructed that exact
source transformation and matched the generated-C hash above. The FFI passes
an initialized, aligned array of 25 conventional 64-bit lanes. The SDK function
restores that conventional representation after its internal lane complementing.
This is software RV64IM execution, not a Keccak precompile or a host hint.
Native fixture verification retains the original C permutation.

## Verification path checked

`guest/src/main.rs` reads a count in `1..=256`, commits the profile and count,
then reads each key/message/signature in place. `verify_words` rejects the four
unused high bytes in the last signature transport word. Its FFI call supplies
exact array lengths and a zero-length context. The null context is not
dereferenced in the zero-length SHAKE absorption path.

The C verifier parses the compact key and signature inside the VM. Every public
key bit pattern has a defined fixed-width decoding. Signature decoding checks
hint boundary monotonicity, the 80-hint limit, strictly increasing indices in
each polynomial, and zero unused index bytes. The infinity-norm check rejects
`|z| >= gamma1-beta`, including equality at 130,994.

The verifier computes the compact-key hash, pure-mode `00 00` message prefix,
SHAKE operations, challenge sampling, matrix expansion from rho, NTT products,
hint correction and reconstructed high-bit encoding. It compares all 32 bytes
of the recomputed challenge. There is no host acceptance bit, pre-expanded
matrix or caller-supplied challenge replacing those computations.

These correspond to the profile and verification procedures in
[FIPS 204, Table 2 and Algorithms 3 and 8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
The 32-byte message restriction is this guest's profile, rather than a general
restriction of ML-DSA.

The reviewed arithmetic remains within the reference's integer bounds: unpacked
z is norm-checked before NTT use; decoded t1 is nonnegative and its 13-bit shift
fits signed 32 bits; forward NTT growth and accumulated products fit the stated
Montgomery bounds; reduced inverse-NTT inputs keep additions below signed-32
overflow. The code relies on the toolchains' conventional arithmetic right
shift of signed integers and narrowing conversions, which are implementation
semantics rather than an additional proof-field assumption. This was a scoped
bound analysis and sanitizer exercise, not a formal proof covering every C path.

## Public-only receiver checked

The common runner's `verify` path authenticates the exact intended statement
bytes using a caller-supplied SHA-256 pin. It decodes the compact keys/messages
from `public_records`, checks that their number equals `count`, independently
recomputes the expected output, and requires the recorded output to match. It
also requires a caller-supplied ELF hash and checks both that pin and the
statement's ELF identity against the locally embedded executable.

It calls `Program::verify`, which runs `verify_core` **and** `check_deferred`.
It does not read signature witnesses or regenerate signing fixtures in this
path. A statement hash taken from the received prover artifact would not supply
application authorization; it must originate with the receiver's intended claims.

## Independently executed controls

The retained [interpreter harness](mldsa-harness/src/main.rs) accepts arbitrary
advice and executes the unchanged guest ELF. It bypasses fixture-generation
acceptance checks, without altering the guest or verifier. Its
[control script](mldsa_controls.py) independently computes the expected public
output with Python's standard-library BLAKE2s.

Baseline and final selected ELF: **16/16 controls passed** on each. The final
result, including its exact executable and harness hashes, is recorded in
[mldsa-controls.json](mldsa-controls.json). Three accepting controls covered one
record, two copies of a valid record, and unused advice beyond the declared
count. Thirteen rejecting controls covered changed rho, changed t1, changed
message, changed challenge, nonzero signature transport padding, excessive hint
count, duplicate indices, nonzero unused indices, decreasing boundaries, z at
the exact rejection bound, zero count, count above 256 and a missing second
record. Unused advice is explicitly outside the documented relation, so its
acceptance is not an omission of authenticated application data.

[Independent oracle controls](mldsa_oracles.py) passed **6/6** against both the
separate Python implementation and native C. They include pure-mode acceptance,
changed message/key/challenge rejection, acceptance under the internal API only
after adding the `00 00` pure prefix, and rejection under the unprefixed internal
API. The same script checked all **15/15 ML-DSA-44 ACVP internal-interface
vectors** against native C and Python. Results and vector hashes are in
[mldsa-oracles.json](mldsa-oracles.json).

Those official vectors use 128-byte internal-interface messages. They were not
directly executed under this unchanged fixed-32-byte pure-mode guest, and are
not described as guest KATs. The pure-prefix bridge and actual-ELF controls
provide separate evidence for that integration boundary.

[Native ASan/UBSan controls](mldsa_native_sanitizers.py) passed one honest
verification and 2,422 rejecting mutations: each signature byte flipped once,
plus all-ones and all-zero public keys. There were no reported sanitizer errors.
This covers native reference-code execution, not RISC-V machine instructions
or the STARK verifier. The recorded result is
[mldsa-native-sanitizers.json](mldsa-native-sanitizers.json).

The reviewer additionally reran the final host release suite: **6/6 tests
passed**. It includes C-permutation versus SDK-permutation comparison on 130
arbitrary full states, memory primitive comparisons across 18,785 combinations
of alignment/tail length/overlap, actual-ELF positive and negative controls, and
public output count/order binding. The differential permutation test executes
natively; the final-ELF controls independently exercise its compiled RISC-V
integration.

Reproduce the review-only interpreter checks without producing a proof:

```sh
CARGO_HOME="$PWD/.cache/aerie-cargo" CARGO_TARGET_DIR="$PWD/risc-v/mldsa/host/target" \
  cargo +stable build --release --offline --manifest-path risc-v/reviews/mldsa-harness/Cargo.toml
.venv/bin/python risc-v/reviews/mldsa_controls.py
.venv/bin/python risc-v/reviews/mldsa_oracles.py
.venv/bin/python risc-v/reviews/mldsa_native_sanitizers.py
```

## Final STARK and public-only receipt coverage

The final executable above produced real STARKs for direct batches of one
through six signatures. Each successful result records three fresh measured
proving samples after its excluded warmup, checks the guest output against the
independently prepared claim, decodes the serialized proof and calls full
`Program::verify`. The saved final proofs are 351,418 bytes for one signature,
363,234 bytes for two, and 411,694 bytes for six. The six-signature execution
commits 261,277,800 words. The actual seven-signature prover call returns
`TooLong`; this is a capacity failure rather than a signature rejection or a
soundness counterexample. The measurements are in
[`results/direct/mldsa-1.json`](../results/direct/mldsa-1.json) through
[`mldsa-7.json`](../results/direct/mldsa-7.json).

The root runner's [public-only suite](../results/consumer-controls.json) records
87 passing controls across the three schemes, including 29 for ML-DSA at counts
one, two and six. Its independent Python encoder reproduces the public digest.
Each subprocess receives only the public statement and one proof in an isolated
temporary directory. It has no signature fixtures or signature witnesses there.

The reviewer independently reran and extended the ML-DSA subset:
**37/37 saved-receipt controls passed**, recorded in
[mldsa-receipt-controls.json](mldsa-receipt-controls.json) and reproduced with
[mldsa_receipt_controls.py](mldsa_receipt_controls.py). Three accepting controls
verify the saved one-, two- and six-signature proofs. Rejecting controls cover
changed keys/messages, record insertion/deletion, reordered records, a wrong
cached output, non-ASCII hex, corrupted/truncated/extended proofs, and wrong
program/statement pins.

Thirteen controls supply a changed, well-formed public claim with its correctly
recomputed BLAKE2s output and a fresh trusted statement hash. They therefore
reach full proof verification and fail there, rather than merely failing an
outer JSON hash or cached-output consistency check. Record insertion/deletion
also recomputes the declared count, testing its cryptographic binding.

Reviewed receiver binary SHA-256:
`afd2c1625c2e21b060a9a2005cb74bf5350a4c1262e9a27f9e12491df1018783`.
The final receiver was rebuilt after two equivalent Clippy changes to even-length
checking and fixed-size Falcon record chunking. All 37 independent ML-DSA receipt
controls passed again on this final binary; the guest executable is unchanged.
The [review snapshot](mldsa-review-snapshot.json) records final receiver source,
binary, all six saved proof/statement pairs, measured-result and control-script
hashes. Key saved proof SHA-256 values are:

| Count | Proof SHA-256 |
| --- | --- |
| 1 | `f4aa5f197bb3767388c898ad7c58e7c113d8503174660fc44adb820a8b5890cd` |
| 2 | `539cbb41585ab89164b9a81cd8bf1cca359079854f768f53a0343e417ff912e6` |
| 6 | `1c083d96d27c5d5a4125eadf0220932302e9366005b3152dc32a4ce16c6ef7d5` |

```sh
.venv/bin/python risc-v/reviews/mldsa_receipt_controls.py \
  --runner .cache/aerie-wrapper-host-target/release/riscv-pqbench
```

## Findings and remaining evidence

No signature-acceptance or public-claim-binding bypass was demonstrated in the
reviewed final implementation. A build-provenance issue was identified: the build script
read `MLDSA_CLANG` without declaring a Cargo environment dependency, while the
manifest recorded the currently configured compiler after an incremental build.
Changing compilers could therefore misattribute cached C objects. This is a
reproducibility/evidence issue, not a demonstrated invalid-signature acceptance.
**Resolved:** `build_support.rs` now declares Cargo dependencies on both
`MLDSA_CLANG` and `MLDSA_CLANG_FINGERPRINT`. The supported build script computes
the fingerprint from the resolved compiler path and version before invoking
Cargo. The final manifest records that fingerprint, the selected SDK kernel,
the SDK source hash and generated-C hash. These changes were inspected and the
final manifest/source hashes independently checked. Reproducible manifest builds
must use `build_guest.py`; invoking Cargo directly does not itself produce a new
provenance manifest.

The scoped source, integration, interpreter and final saved-proof consumer
review has no open actionable finding. Heavy STARK generation was coordinated
by the root benchmark runner; the reviewer inspected those results and
independently reran public-only saved-proof acceptance and mutation checks.
These are real receipt checks in addition to the separate interpreter evidence.
Formal analysis
of leanVM's compiler, memory argument, instruction constraints, Fiat-Shamir,
PCS soundness and complete source-to-machine semantic preservation is outside
this review.
