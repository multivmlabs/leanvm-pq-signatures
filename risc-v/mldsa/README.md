# ML-DSA-44 under RISC-V leanVM

This guest verifies **FIPS 204 ML-DSA-44, pure mode, empty context**, from a compact
1,312-byte public key, 2,420-byte signature and exactly 32 message bytes. Matrix
expansion, key hashing, signature parsing, all SHAKE operations, NTTs, norm and hint
checks execute inside the VM. This is a stronger input boundary than the earlier
custom-ISA guest, which registers a pre-expanded key.

The verifier reuses the existing C reference at
`vendor/ETHDILITHIUM`, commit `f9f4fe1d84e68304b425e054c273c276fe44ba11`, compiled
with `ETHDILITHIUM=0` and `DILITHIUM_MODE=2`. No vendor source changes. Its 64-byte
key hash, pure-mode context prefix and parameter values are those used by the
project's independent FIPS 204 Python verifier. The upstream MIT license is at
`vendor/ETHDILITHIUM/LICENSE`.

The backend/SDK is `vendor/leanVM-riscv` at
`06e5c9cd6981103786f9d0a17324241b559a50d3`. `guest` is a standalone package with
Rust `nightly-2026-10-03`; `host` is a native fixture/helper package. The C frontend
emits optimized RV64IM LLVM bitcode, which Rust's RISC-V `rust-lld` lowers when
linking the guest. This works with Apple's clang, which lacks a RISC-V machine-code
backend. Suppressed `printf` diagnostics and freestanding memory functions are
local adapters. The native memory-test symbols are prefixed and do not override
the benchmark process's libc.

The default `sdk-keccak` feature generates a local copy of `fips202.c` that replaces
only `KeccakF1600_StatePermute` with a C ABI call to the official SDK's software
`keccak::f1600`. All C SHAKE absorption, domain suffixes, squeezing, sampling and
signature checks remain. The SDK permutation uses lane complementing and compiles
to normal RV64IM instructions; no Keccak precompile or host advice is involved.
Native fixture generation retains the C permutation, providing an independent
crosscheck. Native tests compare all 25 output lanes against that reference for
130 input states, including zero and all-one states. `--no-default-features`
builds the original reference permutation for controlled comparisons.

The implementation retains the C reference's in-place integer NTT and Montgomery
reductions, compiles at `-O3`, reuses fixed stack storage and reads compact inputs
in place from advice. It has no exponent-based arithmetic advice, dynamic
allocation, precomputed public matrix, trusted host acceptance bit or trusted
host challenge. This is a reference-code port, not a claim of optimal RV64IM code.
SHAKE is ordinary software in this backend. The ELF uses the SDK's 1 MiB RAM map.

An actual one-signature interpreter/commitment-plan comparison reduced the C
reference's 1,743,198 instructions and 65,436,008 committed words to 1,071,681
instructions and 51,534,184 words with SDK Keccak. Five signatures execute in
5,356,788 instructions and plan 257,345,640 words, below `2^28`. These are execution
and witness-plan measurements, not STARK proving times. A second trial replacing
byte memory primitives with aligned word loops saved only 50 instructions per
batch and no committed words, so it was not retained. See
`optimization-trials.json` and the preserved comparison ELFs.

## Statement and advice

Advice starts with `count` (`1..=256`), then each record is 164 little-endian key
words, four message words and 303 signature words. The last signature word has
four unused bytes, which the guest requires to be zero. The 256 limit is an
explicit guest input bound, not a measured proof capacity; the advice region is
1 MiB. Unused advice past the count is outside the relation.

The public output is SDK BLAKE2s over these words, in order:

```
32-byte domain "pqbench/mldsa44/compact/v1" padded with six zero bytes
count as LE64
for each record: canonical compact public key (1312 bytes), message (32 bytes)
```

The verifier must pin the intended guest program and independently derive this
output from authorized public keys/messages. Count and order are bound; duplicate
claim policy and transaction/account semantics belong to the receiver.
Signatures are witnesses, absent from `expected_output` inputs. These proofs are
the backend's plain proofs unless the caller explicitly chooses its ZK mode.

## Build and interfaces

From the project root:

```sh
python3 risc-v/mldsa/build_guest.py
CARGO_HOME="$PWD/.cache/aerie-cargo" cargo +stable test --release --offline --manifest-path risc-v/mldsa/host/Cargo.toml
```

`build_guest.py` requires clean vendor pins and writes `mldsa.elf` plus
`build-manifest.json`, including source, compiler and ELF hashes. Cargo locks are
checked in. The compiler path/version fingerprint participates in Cargo cache
invalidation, and the manifest identifies the selected SDK kernel and generated
C source hash. The native host crate `mldsa-riscv-host` exposes:

- `ELF`, the built guest bytes;
- `batch(n)` and `batch_range(start, n)` returning `leanvm_guest::Run`;
- `record(index)` returning a compact public key, message and signature;
- `records(start, n)` returning those records once for common benchmark runners;
- `run_from_records` for custom/negative fixtures;
- `expected_output(&[PublicRecord])` for verification without signature witnesses.

Native fixture generation uses the unchanged C signer and SHAKE streams derived
from a record index. Keys, messages and signing coins differ across indices and
are reproducible. The keys are public benchmark material, never wallet keys.
Fixture generation/signing is outside the proving timer.

## Checks performed

The six-test release suite exercises the actual ELF in the RISC-V interpreter,
without producing a STARK. It checks one- and two-signature outputs; deterministic distinct records;
and rejection of changed keys, messages, challenges, out-of-range hint boundaries,
duplicate hint indices, nonzero unused hints, out-of-range z coefficients, nonzero
transport padding and zero count. Public digest checks cover count and order.
Separate kernel tests compare full Keccak states and check the actual C memory
primitives over alignment, tail-length and overlapping-copy cases.

`fixture-0.json` was independently accepted by `pqbench.mldsa.verify_python` and
the existing native C consumer, with a changed-message rejection control. This
checks the compact FIPS 204 byte relation separately from the new host builder.
These checks are not a full cryptographic audit. Proving and proof verification
measurements are deliberately left to the project's common runner.
