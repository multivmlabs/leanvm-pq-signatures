# Raccoon witness-size diagnosis

This diagnostic runs the unchanged guests to completion in the raw RISC-V
interpreter and reproduces the pinned backend's public fill and commitment-layout
rules. It separately calls the unchanged production `Program::measure`. Diagnostic
counts do not disable a prover check and never become a proof. No STARK is
produced by the commands below.

Backend: `06e5c9cd6981103786f9d0a17324241b559a50d3`. The layout replica is adapted
from `risc-v/reviews/lattice-capacity-reaudit`; it independently matches all 25
retained accepted production reports (`layout-crosscheck.log`).

| Original guest, one signature | Instructions | Committed words | Production result |
| --- | ---: | ---: | --- |
| Raccoon-128-1 | 8,238,032 | 419,337,656 | `TooLong` |
| Raccoon-G strict profile | 19,132,604 | 839,237,560 | `TooLong` |

The cap is 268,435,456 words. Both raw executions finish and return the exact
expected public commitment. Therefore these failures are not invalid signatures,
an advice-length overflow, or a failed public-output check. The normal production
run refuses while executing, once an intermediate padded layout is already too
large. Its first failing periodic checks occur at cycles 6,029,312 and 7,405,568.

## Keccak attribution

The unchanged final ELFs expose the same 2448-byte SDK permutation body. Symbol
addresses were read using LLVM `nm`: `0x100005bc` for standard Raccoon and
`0x100021c4` for Raccoon-G. The raw interpreter attributes instructions whose
program counter lies in that body.

| Original guest | Keccak calls | Instructions in body | Share of total |
| --- | ---: | ---: | ---: |
| Raccoon-128-1 | 588 | 3,380,412 | 41.03% |
| Raccoon-G | 1,996 | 11,475,004 | 59.98% |

This excludes SHAKE absorption, squeezing and rejection-sampling code outside the
permutation body. It must not be presented as the total cost of SHAKE.

For Raccoon-G, even the instruction rows from this Keccak body alone, with every
other executed instruction removed, require at least 388,777,392 words under
the same layout rules. Consequently, optimizing only its polynomial Montgomery
arithmetic cannot make the original whole-signature guest fit. This is a bound
for this software kernel, not a lower bound on all possible Keccak circuits or
all RISC-V implementations.

## Official CRT32 trial

`standard-crt32/` copies the standard guest and adapter, selects the official
`POLYR_Q32` arithmetic and compiles `ntt32.c` instead of `ntt64.c`. No signature
parameters, parser, transcript, public-output commitment or proof cap change.
The preliminary one-record diagnostic returns the original expected output,
but grows to 9,347,894 instructions and 446,856,808 words. Production measurement
still refuses. This does not establish complete correctness of the trial; it is
only a rejected optimization candidate. Further review/testing belongs to the
separate CRT investigation.

## Reproduction

From the project root:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/raccoon-fit-target" \
 cargo +stable build --release --locked --offline \
 --manifest-path risc-v/experiments/raccoon-fit/Cargo.toml

.cache/raccoon-fit-target/release/raccoon-fit raccoon 1 0 /tmp/raccoon-layout.json
.cache/raccoon-fit-target/release/raccoon-fit raccoon-g 1 0 /tmp/raccoong-layout.json
.cache/raccoon-fit-target/release/raccoon-fit check-reports
```

An optional fifth positional argument loads a separately built ELF while retaining
the selected scheme's original deterministic witness. A sixth argument overrides
the permutation's hexadecimal start address for instruction attribution. The
2448-byte body assumption must be changed for a different permutation kernel;
it does not affect full execution counts or commitment sizes.

The JSON reports retain every table, fill operation and periodic size check.
`diagnostic-summary.json` records original ELF, probe-source and probe-binary
hashes. The earlier actual prover refusals remain in the approved benchmark
study; diagnostic results are not replacement proof benchmarks.
