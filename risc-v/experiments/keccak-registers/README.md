# Controlled Keccak register-state trial

This directory tests a software optimization without changing the hash function,
signature relation, public statement or `2^28` commitment cap. The backend and
verifier remain the unchanged leanVM pin
`06e5c9cd6981103786f9d0a17324241b559a50d3`.

The two Keccak files come byte-for-byte from [PR #605](https://github.com/leanEthereum/leanVM/pull/605),
head `c67701c037c11d229c563671419ccc48827b5c2d`. **That PR is closed and was not
merged.** This is a separately pinned kernel trial, not a statement that upstream
supports a new backend. The original SDK and guest directories are untouched.

The assembly keeps the Keccak state in registers, reducing spill loads and stores.
It still executes all 24 Keccak-f rounds as ordinary RV64IM instructions. There
is no Keccak precompile, trusted hash hint, BLAKE2s substitution or cap increase.

## What changed

- `sdk/` is a copy of the pinned SDK. Only `src/keccak.rs` and `src/keccak_rv64.S`
  change executable logic; Cargo metadata is made standalone. The manifest checks
  both official Git blob hashes.
- `guest/` copies the FORS guest, with only the SDK path and crate name adjusted.
  Its `lib.rs`, Keccak-256 domain/address encodings, input bytes and public claim
  are unchanged.
- `mldsa/` copies the compact-input ML-DSA verifier, rebasing paths to the same C
  reference and replacing the SDK path. Its FIPS 204 parameters, C signature
  verifier, SHAKE padding/absorb/squeeze logic and public claim are unchanged.
- `kernel-guest/` exposes the full permutation through the actual VM so that the
  assembly is compared with the original Rust implementation, rather than testing
  a native fallback against itself.

## Results

These are **execution and witness-plan measurements, not proof-production results**.
Every listed count also completed in the raw interpreter and returned its exact
independently derived public output, even where the production size check refused
proof production.

| Workload | Original committed words | Register kernel words | Production size check |
|---|---:|---:|---|
| FORS, 1 | 42,128,704 | 38,892,864 | fits |
| FORS, 7 | 212,148,312 | 184,238,168 | fits |
| FORS, 8 | over cap | over cap | refused |
| ML-DSA, 1 | 51,534,184 | 49,985,896 | fits |
| ML-DSA, 6 | 261,277,800 | 247,851,112 | fits |
| ML-DSA, 7 | over cap | 264,076,392 | fits |
| ML-DSA, 8 | over cap | over cap | refused |

The ML-DSA seven-signature witness fits narrowly beneath 268,435,456 words. It
still needs an actual production proof and full verification before being called
a successful proof batch. The FORS limit does not increase: reducing spills does
not remove the dominant ALU/shift cost, and its eighth signature still crosses a
padded-table boundary. Thus even a real software optimization does not restore
the old dedicated-Keccak backend's large FORS batches.

The permutation differential covers **1,730 actual VM states**: all 1,600
single-bit basis states, zero, all ones and 128 pseudorandom full states. All
25 output lanes are committed and compared with the original SDK's native Rust
permutation. The FORS trial also rejects 162 malicious advice controls. The
ML-DSA trial rejects nine controls covering key/message/challenge changes, hint
bounds, duplicate/unused hints, z bounds, transport padding and zero count.
This is differential evidence, not a formal proof or complete assembly audit.

## Reproduce

From the project root, set a writable Cargo cache, then build from each guest's
directory so its target configuration and linker script are selected:

```sh
export CARGO_HOME="$PWD/.cache/riscv-cargo"
(cd risc-v/experiments/keccak-registers/guest && cargo build --release --locked --offline)
(cd risc-v/experiments/keccak-registers/kernel-guest && cargo build --release --locked --offline)
(cd risc-v/experiments/keccak-registers/mldsa/guest && cargo build --release --locked --offline)
```

Run `probe` and `mldsa-probe` with `cargo +stable run --release --locked --offline
--manifest-path <directory>/Cargo.toml`. Their JSON files retain the measured
rows and actual errors. No diagnostic disables a check in the production prover
or verifier. `build-manifest.json` records the copied sources and ELF identities.

For a separately coordinated proof confirmation, the ML-DSA probe supports
`-- --prove 7` (or `8` to attempt the next count). It invokes the unchanged
production `Prover`, serializes and decodes the result and calls full
`Program::verify`. It saves the exact advice, public records, expected output,
proof and hashes, and rejects a changed message under an independently recomputed
public output. Its single cold timing must not be compared with benchmark medians.
No such proof confirmation has been run for this assembly trial.

The ML-DSA bitcode link emits warnings about unsupported disabled experimental
target-feature names from the C frontend. The target remains RV64IM; all tested
execution paths run in the pinned VM. Those warnings are not suppressed in the
build.

The separate [twiddle-width review](twiddle64-independent-review.md) evaluates
`../mldsa-poly64`, which uses the original SDK kernel. Its arithmetic argument and
576 native differential comparisons do not depend on the unmerged assembly here.
