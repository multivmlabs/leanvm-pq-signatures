# Standard Raccoon fitting trials

This directory preserves implementation trials for the unchanged ordinary
Raccoon-128-1 signature relation. The original port and backend remain untouched.
The directory name records the first CRT32 experiment; **the selected variant
uses the original 64-bit Montgomery NTT**, because the CRT32 trials were worse.

The selected default guest and native host are in `guest/` and `host/`.
`raccoon.elf` is the checked-in selected executable, SHA-256
`e375033cde726b2e988db2c433bf8d83b8516252c5954c1e43cb6720f3b25eac`.
`build_guest.py` checks the unchanged reference/backend pins and records compiler,
flags, selected features and 56 source hashes in `build-manifest.json`.

## Changes in the selected variant

The public domain, count, ordered key/message commitment, compact inputs,
signature equation, NTT, challenge sampling, matrix expansion and all norm checks
remain those of the reviewed original reference-interoperability profile.

- `c/adapter.c` reads the fixed low 40 response bits in at most six bounded bytes,
  rather than calling the single-bit reader 40 times. The variable unary part
  and its magnitude limit are unchanged. The end-of-buffer test precedes every
  extraction. Remaining zero padding is checked in its partial byte and then in
  whole bytes, including exact final-bit payloads. `adapter-bitwise.c` retains
  the earlier reviewed bounded decoder for differential controls.
- The local `plat_local.h` has alignment-checked, little-endian 64-bit paths for
  `get64u_le` and `put64u_le`, with the original bytewise fallback. The existing
  `-fno-strict-aliasing` compilation policy is retained. The header is explicitly
  included before reference headers; vendor files are not edited.
- Software Keccak uses the unchanged register-state kernel from the earlier
  `keccak-registers` trial, pinned to closed, unmerged upstream PR 605, head
  `c67701c037c11d229c563671419ccc48827b5c2d`. It executes all rounds as ordinary
  RISC-V instructions. There is no Keccak precompile, hash hint or changed cap.

## Execution and witness-plan results

These are completed raw-interpreter executions and separately checked production
`Program::measure` results. They are **not STARK production benchmarks**. The
diagnostic reproduces the pinned backend's public table layout without bypassing
the production proof checks. Every run returns the original expected public
output for the identical ordinary signature fixture at index zero.

| Variant | Instructions | Witness words | Production measure |
|---|---:|---:|---|
| Original 64-bit reference port | 8,238,032 | 419,337,656 | `TooLong` |
| Official CRT32 and SDK Keccak | 9,347,894 | 446,856,808 | `TooLong` |
| CRT32 and register Keccak | 8,862,206 | 438,214,248 | `TooLong` |
| 64-bit, bulk decoder and register Keccak | 6,848,407 | 284,071,352 | `TooLong` |
| Selected: add aligned byte helpers | 6,499,305 | 247,895,480 | Accepted |

The selected plan is below 268,435,456 words. The main study subsequently produced
and independently verified a complete one-signature STARK. Its three-run direct
sample and separate public-only verification are in
`risc-v/results/raccoon-runtime-study/raccoon/direct/count-1/`. The witness-plan
figures above remain separate from proof-production timings. Capacity beyond one
signature is checked separately on every prefix through the input limit.

The initial aligned-header trial without explicit forced inclusion had no effect:
reference headers found their own `plat_local.h` first. Its saved result is
retained, but it is not a distinct effective optimization.

## Correctness evidence

Eight original native and actual-ELF tests pass on the selected executable,
including positive signatures, changed public records, malformed encodings,
exact final-bit payloads, zero padding and challenge-consistent bad norms.
`correctness.log` records the run. The selected native fixture at index zero
matches the original fixture previously checked against the independent official
Python implementation byte-for-byte; see `fixture-0.json` and `validation.json`.

`decoder_alignment_controls.py` compares the bulk decoder with the reviewed
bounded bitwise decoder on 3,305 deterministic cases, including 300 structured
canonical encodings, 2,000 mutations, 1,000 random encodings and five saved
boundary/norm controls. All accept/reject decisions and accepted decoded values
match. An additional 1,024 read/write cases cover every byte alignment and check
the eight-byte result and surrounding guard bytes. Results are retained in
`decoder-alignment-controls.json`. These native controls supplement the actual
guest tests; they are not a full formal proof or a proof-system audit.

From the project root:

```sh
python3 risc-v/experiments/raccoon-crt32/build_guest.py
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/raccoon-crt32-target" \
  cargo +stable test --release --locked --offline \
  --manifest-path risc-v/experiments/raccoon-crt32/host/Cargo.toml --lib
.venv/bin/python risc-v/experiments/raccoon-crt32/decoder_alignment_controls.py
```

The native host preserves the original host API for the common benchmark runner.
Failed CRT32 and intermediate ELFs/layout reports remain separate from the
selected executable. The main study owns all resource-monitored production
proofs and complete proof verification.
