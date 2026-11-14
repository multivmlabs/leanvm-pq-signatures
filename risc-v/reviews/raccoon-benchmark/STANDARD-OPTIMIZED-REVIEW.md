# Independent review: fitting standard Raccoon guest

Reviewed 2026-11-09. Result: no actionable verification bypass or public-binding
omission was found in this bounded review. The implementation can proceed to an
actual production proof attempt. This is not a claim that proof production has
already succeeded or that a batch maximum has been established.

## Exact artifact and scope

- ELF: `risc-v/experiments/raccoon-crt32/raccoon.elf`
- SHA-256: `e375033cde726b2e988db2c433bf8d83b8516252c5954c1e43cb6720f3b25eac`
- Build-manifest SHA-256: `a78d542f365ef84d429456a73000a845209e72d11d3695be9b20117a1d4e2e82`
- All 56 recorded source hashes independently matched their files.
- Backend remains `06e5c9cd6981103786f9d0a17324241b559a50d3`.

Despite the directory's historical name, the selected variant uses the original
**64-bit Montgomery NTT**, not the CRT32 arithmetic trial. The signature relation,
parameters, original ordered public output and user-approved official reference
interoperability policy remain unchanged. The original failed guest and data are
preserved separately.

The reviewed changes are a bounded bulk read for 40 response bits, an equivalent
padding scan, alignment-checked little-endian 64-bit byte helpers, and the
separately pinned PR605 software Keccak register-state kernel. No norm, challenge,
matrix-expansion or byte-canonicality check was removed. There is no new backend
instruction, trusted arithmetic/hash hint or commitment-cap increase.

## Decoder equivalence

The bulk reader checks `position <= 8*11524-40` before reading any field byte.
For bit offset `s` in zero through seven it reads exactly `ceil((s+40)/8)`, five
or six bytes. The position bound implies those bytes are inside the signature.
Its maximum shift is 40, its accumulator is unsigned 64-bit, and masking the
shifted value recovers exactly the next 40 low-order bits. Position advances by
40 only after a successful complete read.

Unary magnitude/sign processing and response/hint bounds are unchanged. The
reader position cannot exceed the fixed signature bit length: every individual
bit is checked before access, and every bulk read is bounded before advancing.

After decoding, a partial final byte is masked to check **all unconsumed bits**,
then every remaining whole byte must be zero. A byte-aligned payload still checks
the next full byte. A payload using the exact last available bit reads no extra
byte and has no nonexistent padding to inspect. This preserves both canonical
padding rejection and the original completeness correction.

Independent native controls compare the previous frozen bitwise decoder and the
new decoder on 1072 inputs, comparing all decoded values whenever accepted.
Inputs include the independent full-EOF, byte-aligned and norm controls; 1000
distributed multi-bit mutations of an honest signature; all final-eight-byte bit
mutations; and all-zero/all-one malformed strings. All outcomes agree. Another
209 raw-field controls independently compute the expected 40 bits across all bit
alignments and around the exact EOF, including failed out-of-range reads.

Evidence: [standard-optimized-native-controls.json](standard-optimized-native-controls.json)
and [standard_optimized_controls.py](standard_optimized_controls.py). These are
native correctness controls, not proof-capacity or timing measurements.

## Byte helpers and Keccak

The eight-byte load/store fast paths apply only on little-endian targets and
after a runtime pointer-alignment check. Otherwise the original eight individual
byte operations remain. Each original helper call already requires eight valid
input/output bytes; the fast path does not read or write more. The C build keeps
`-fno-strict-aliasing`, and the relevant 64-bit accesses are aligned. The remaining
memory primitives are unchanged.

An independent byte oracle checks 1600 load/store cases across offsets zero
through fifteen and pseudorandom 64-byte buffers. Every load matches little-endian
byte decoding, and every store changes exactly eight intended bytes, preserving
all guard bytes. Both aligned and unaligned paths are exercised.

Both `register_keccak.rs` and `keccak_rv64.S` are byte-identical to the earlier
separately pinned PR605 trial. That earlier trial includes 1730 actual-VM full-state
differential controls. This reviewer checked source identity instead of claiming
those were rerun on the new guest. The new actual signature executions exercise
the linked assembly with its actual relocation and calling convention. All hash
absorption, padding and sampling logic remains in the reference code.

## Actual final-ELF controls

Nineteen independent controls run through the **final selected ELF** in the raw
RISC-V interpreter. Seven accept and twelve reject as expected. They cover:

- One/two honest records, reversed records and distinct original public outputs.
- The approved reference transcript and rejection of the conflicting literal
  NIST-PDF challenge order.
- Changed first/late public key and message fields, challenge, exchanged witnesses,
  noncanonical key coefficients and trailing signature padding.
- Valid payloads ending at a byte boundary and at the exact last signature bit.
- Challenge-consistent hint L2, hint infinity and response infinity failures.

All accepted public outputs match an independent raw-byte Python BLAKE2s
calculation over the unchanged domain, count and every ordered public key/message
pair. These checks do not use the new host's expected digest as their sole oracle.

Evidence: [standard-optimized-elf-validation.json](standard-optimized-elf-validation.json),
[standard-optimized-extra-elf-validation.json](standard-optimized-extra-elf-validation.json)
and their TSV execution logs. The reviewer used no `Prover` or `Program::measure`
call for these controls.

## Remaining benchmark obligations

An execution layout below the commitment cap is only a candidate. The actual
unchanged production prover must produce the proof, and a separate public-only
consumer must serialize/decode and fully verify it under this approved ELF.
Complete tree verification must also settle all residual polynomial/matrix claims.
Every fresh sample, padding slot and auxiliary byte remains part of the study's
accounting. Resource stops are not accepted proofs or cryptographic capacity
refusals. No universal scheme limit follows from this review.
