# Segmented Raccoon-G under RISC-V

The original full Raccoon-G verifier cannot fit one signature under the selected
backend's `2^28` witness cap. This guest keeps the same signature relation and
splits its nine matrix-row equations into **five linked partial proofs**. Parts
check rows `(0,1)`, `(2,3)`, `(4,5)`, `(6,7)` and `(8,8)`. The repeated final row
is executed and charged; it is not an additional signature.

Every part still checks all compact encodings, the complete exact norm, full-key
BUFF binding and the original challenge hash over the complete commitment vector.
It expands its two selected matrix rows through SHAKE inside the VM. Two separated
SDK BLAKE2s hashes bind the complete shared signature and commitment witness.
The final receiver must require all five parts with the same binding for each
authorized key/message pair. One part alone proves only a partial claim.

The [specification](SPEC.md) gives the precise codec, equations, public statement
and composition assumptions. The Raccoon-G profile remains the authors' PoC with
strict decoding and the exact integer norm threshold. Full paper conformance and
parameter-security claims are still pending. The unchanged backend pin is
`06e5c9cd6981103786f9d0a17324241b559a50d3`.

## Identity and first capacity check

The uniform two-row ELF is
`5c48b8f39b14521773493692034fa601a9df89992552870addd68416cc926eac`,
28240 bytes. `build-manifest.json` pins the source/dependency files and independent
codec controls. The program imports the unchanged original G arithmetic and
norm predicate. It introduces no unchecked arithmetic or hash advice.

The unnormalized candidate used 226,492,856 words per part for the first signature.
An exhaustive check of all 500 parts from the unchanged 100-signature corpus
found one part, signature three's final part, with a different padded store-table
height. All parts fit the cap, but that shape difference prevents one native tree.
The uniform guest executes **32768 fixed volatile stores** to an aligned local
scratch cell after every signature check and public-value commit. The count
does not depend on any input, and the scratch is never read. This is charged
execution padding, with no acceptance or public-output change. Original store
counts ranged from 506140 to 525147; the fixed addition moves all of them into
the same padded store-table height of 1048576. It retains every corpus record.

The final executable's actual instruction trace for the former outlier confirms
exactly 32768 store instructions and 98309 ALU instructions inside the padding
function, with no other instruction classes. That part still has the original
public output and passes production measurement at **234,357,176 words**.
`review/uniform-padding.json` records this. A fresh production planning pass
under the final executable checked all 500 parts: every part fits at 234,357,176
words and has the same padded shape. The selected per-part layouts and complete pipeline measurements are retained in
`risc-v/results/raccoong-segmented-uniform-trees/`. These layout measurements do
not mean that the whole signature fits a direct proof.

## Preparation and host API

The host crate is `raccoong-segmented-host` in `host/`. Its interface is:

- `ELF`, `ROW_COUNT=9`, `PARTS_PER_SIGNATURE=5`, `ROWS_PER_LEAF=2`;
- `Record` and `PublicRecord`, using the original raw key/message/signature corpus;
- `record(index)` and `records(start,n)`;
- `prepare(&Record) -> PreparedRecord`, freshly reconstructing complete `w` and
  its 64-byte binding;
- `row_run(&PreparedRecord, part)` and
  `expected_row_output(&PublicRecord, part, &binding)`;
- `rows_for_part(part)`, the fixed coverage mapping.

`PreparedRecord` contains `public`, `signature`, packed canonical `w` and
`binding`. No prepared witness or advice is cached. Every fresh pipeline must
include reconstruction of `w`, binding calculation and advice packing in its
prover-work total. Only original key generation and signing are fixture work.
The final receipt carries 64 binding bytes per original signature, in addition
to its root proof. The receiver needs no signature, `w` or child proof files.

## Correctness evidence

Five native/interpreter tests pass on the reviewed ELF. They include 35 actual
ELF executions, with 19 acceptances and 16 rejections:

- Every part of three independent original signatures accepts, and all 6912
  reconstructed commitment coefficients match the authors' Python arithmetic.
- Malformed full keys, messages, challenges, responses, selected hints, commitment
  coefficients and part indices reject. The final commitment coefficient is
  checked even when it is outside the selected rows.
- Python `hashlib.blake2s` independently checks 20 witness hashes and 50 public
  part outputs, including both binding halves and all part/row identifiers.
- Seven challenge-consistent norm controls test the exact threshold, threshold
  plus one, both signs, a larger response and the hint midpoint.
- Changing an unselected row-eight hint can leave part zero valid, but changes
  its binding and makes part four fail. This explicitly demonstrates why full
  receipt verification must enforce common witness binding and complete coverage.

`review/uniform-correctness.log` and `review/codec-controls.json` retain the final
guest evidence. The same independent public-output vectors remain unchanged.
These correctness fixtures are excluded from the benchmark corpus and are never
used as free cached witness preparation. Guest/host Clippy passed with warnings
denied. An actual final-ELF padding probe separately checks the fixed store count
and the old shape outlier. The independent review adds second-row mutation controls; its evidence
is under `risc-v/reviews/raccoon-benchmark/`.

## Reproduction

From the project root:

```sh
.venv/bin/python risc-v/experiments/raccoong-segmented/build_guest.py
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/raccoon-fit-target" \
 cargo +stable test --release --locked --offline \
 --manifest-path risc-v/experiments/raccoong-segmented/host/Cargo.toml
```

Proof production and the full public-only receiver are in `runner/`, with the
matrix launcher `matrix.py`. The repository retains the selected 10/30/70/100
measurements and their final receipts; pilot and intermediate proof files have
been removed. Use a new output directory when regenerating a tree.

Report five fresh partial leaves per original signature, every merge and padding
slot, all witness preparation, the complete root plus auxiliary binding bytes,
and full verification. Do not substitute partial-proof counts for signature counts.
