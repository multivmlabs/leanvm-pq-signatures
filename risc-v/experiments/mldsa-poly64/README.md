# ML-DSA: 64-bit twiddle loads

This isolated trial preserves full compact-input FIPS 204 ML-DSA-44 verification,
pure mode, empty context and 32-byte messages. It does not widen polynomial
storage. The baseline implementation and vendor repositories remain unchanged.

Only `ntt.c` differs from the pinned C reference: its 256 fixed twiddle constants
and the local `zeta` variables in the forward/inverse NTT use `int64_t` instead
of `int32_t`. The exact patch is [twiddle64.patch](twiddle64.patch). Polynomial
coefficients, NTT pointer arguments, Montgomery reduction, scalar truncations,
signature decoding, norm checks, hint checks, SHAKE and public claims are
unchanged. The software Keccak kernel is the baseline pinned SDK implementation,
not the later PR #605 kernel.

## Why this can change capacity

RV64IM can load a 64-bit constant directly. Loading a 32-bit item uses the
backend's more expensive narrow-load circuit. At seven signatures, this trial
reduces narrow-load rows from 534,127 to 511,559, below the `2^19 = 524,288`
padding threshold. One table's padded witness can therefore shrink even though
the total instruction reduction is small.

The one-signature execution changes from 1,071,681 to 1,070,114 instructions.
The seven-signature trial has 7,488,466 instructions and **261,315,688 committed
words**, below the unchanged `2^28 = 268,435,456` cap. It does not remove any
signature-verification operation or accept a host-computed intermediate result.

## Numerical equivalence

All 256 constants are unchanged and fit signed 32 bits: their minimum and maximum
are -4,083,598 and 4,108,315. Each local `zeta` therefore has the same integer
value under both types. In the forward transform the multiplication already
casts `zeta` to `int64_t`; widening its storage does not change that expression.
In the inverse transform, negating any table entry is representable in signed
32 bits, so the widened negation produces the same value. Coefficient arrays
and temporary `t` remain `int32_t`; Montgomery's explicit 32-bit casts and
reductions are untouched. There is no changed pointer ABI or serialization.

The reference's existing coefficient bounds remain applicable. Forward NTT
inputs and eight stages stay within signed 32-bit coefficient range, and the
twiddle product was already evaluated in signed 64 bits. The independent review
also compared complete arrays, not just residues or final signature verdicts.

## Validation

- [Native differential checks](native-checks.json): **3,783 cases passed** against
  separately compiled original and modified C libraries with hidden internal
  symbols. This includes 15 official ACVP internal-interface cases, 12 valid
  deterministic fixtures, changed messages/keys and single-bit changes at every
  signature byte and public-key byte for one fixture. The 12 deterministic
  key-generation/signing outputs are byte-identical. Independent Python checks
  agree on 51 pure/internal cases.
- [Actual VM controls](vm-controls.json): **16 passed**, including valid output,
  malformed hint ordering/counts, nonzero unused hints, exact norm-bound failure,
  changed keys/messages/challenges, transport padding and invalid batch counts.
- An [independent review](../keccak-registers/twiddle64-independent-review.md)
  compared **576 complete forward/inverse NTT arrays** from 192 bounded input
  arrays under AddressSanitizer and UndefinedBehaviorSanitizer. All passed.
- The production guest still uses the public pure verification entry point.
  ACVP internal-interface adapters are native test code only; they are not
  compiled into the guest.

The source and compiler manifest is [build-manifest.json](build-manifest.json).
The exact trial ELF SHA-256 is
`8d1a19b35874db7c3ffff15e851d0312a97c6c9b370ce58c300b674ac57922ee`.
Backend and SDK remain commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`; the C reference remains commit
`f9f4fe1d84e68304b425e054c273c276fe44ba11`, with the recorded local NTT patch.

## Actual proof and public-only verification

[capacity-proof.json](capacity-proof.json) records **one fresh seven-signature
STARK** produced by the unchanged backend, serialized to
[capacity-7.proof](capacity-7.proof), decoded and fully verified using
`Program::verify`. It is **411,502 bytes** and took 15.114881583 seconds in this
single capacity-confirmation run, at eight threads and logarithmic inverse rate
one. This is not a repeated timing benchmark and must not replace the baseline
three-sample timing curves.

The producer also rejects a changed output and rejects substitution of the
baseline ELF. A separate [public-only consumer](capacity-consumer.json) recomputes
the output from [public keys and messages](capacity-public.json) and verifies
the saved proof. A further [isolated consumer](capacity-isolated-consumer.json)
passes with only the ELF, public manifest and proof copied into a temporary
directory; no advice or signature file is present. [Independent Python BLAKE2s](capacity-public-independent.json)
agrees on that public digest. No signature witness is needed by that consumer.
The full test advice is retained in `capacity-advice.bin`; fixtures are public
test material, not wallet signing keys.

The same guest is attempted at eight signatures through the actual prover;
[capacity-next.json](capacity-next.json) records `TooLong` and no proof. These
counts describe this program and deterministic corpus, not a universal ML-DSA
limit. The approved program identity changes when its constant layout changes.

## Reproduce

From the project root:

```sh
python3 risc-v/experiments/mldsa-poly64/build_trial.py
.venv/bin/python risc-v/experiments/mldsa-poly64/native_checks.py
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
 cargo +stable build --release --offline --locked \
 --manifest-path risc-v/experiments/mldsa-poly64/probe/Cargo.toml
.venv/bin/python risc-v/experiments/mldsa-poly64/vm_controls.py
.cache/riscv-host-target/release/mldsa-twiddle64-probe --prove7
.cache/riscv-host-target/release/mldsa-twiddle64-probe --verify7
.cache/riscv-host-target/release/mldsa-twiddle64-probe --reject8
```

The original native producer-harness startup error is preserved in
`prove7-initial-threadpool-error.log`: its pool was initialized after program
loading, so it stopped before calling the prover. Initialization ordering was
fixed before the successful proof attempt. That failed startup is not a
capacity result.
