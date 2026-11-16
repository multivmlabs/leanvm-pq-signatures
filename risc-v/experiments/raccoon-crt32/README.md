# Selected Raccoon-128 implementation

This directory contains the measured optimized implementation of the ordinary
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

## Measured operating point

The selected guest executes 6,499,305 instructions and uses 247,895,480 witness
words for signature zero, below the 268,435,456-word cap. The actual direct
three-run proof measurement and public-only receiver are retained in
`risc-v/results/raccoon-runtime-study/raccoon/direct/count-1/`.
Earlier CRT32 and decoder trials are omitted; the directory name is historical.

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
The main study retains the measured production reports, final receipts and
complete public-only verification records.
