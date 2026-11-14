# RISC-V signature proofs

This study proves batched verification of Falcon-512, ML-DSA-44 and FORS using
leanVM's official **`riscv-exploration`** branch at commit
[`06e5c9cd6981103786f9d0a17324241b559a50d3`](https://github.com/leanEthereum/leanVM/tree/06e5c9cd6981103786f9d0a17324241b559a50d3).
Vendor checkouts remain unchanged. Falcon reuses the official guest introduced
by [PR #490](https://github.com/leanEthereum/leanVM/pull/490), including its checked-in
ELF. Earlier implementation work is preserved separately in [`../leanISA`](../leanISA).

The guests are:

- **Falcon-512:** [`../vendor/leanVM-riscv/programs/falcon/guest`](../vendor/leanVM-riscv/programs/falcon/guest), standard round-3 SHAKE Falcon.
- **ML-DSA-44:** [`mldsa/guest`](mldsa/guest), FIPS 204 pure mode with empty context, compact keys/signatures and in-VM matrix expansion.
- **FORS:** [`fors/guest`](fors/guest), `n=32, k=16, a=8`, Keccak-256. This is a few-time forest component; its measurements exclude a full SLH-DSA hypertree.

All use 32-byte benchmark messages. Public fixtures use reproducible test keys.
The measured backend proofs are plain proofs, **not zero knowledge**.

The [Raccoon extension](raccoon-study/STATUS.md) adds original Raccoon-128-1
and a separate Raccoon-G HD-wallet profile on the same backend pin. Its
[experiment plan](raccoon-study/PLAN.md) is approved. The extension uses an
optimized ordinary Raccoon guest and a five-part Raccoon-G verifier; complete
study has 22 complete, fully verified tree pipelines. All requested points have
three fresh runs except Raccoon-G at 100 signatures: one run completed before
the user stopped further repetitions and requested an estimate.
The [status record](raccoon-study/STATUS.md) identifies the separate cohorts.
Existing baseline commands and measurements below remain unchanged.

## Build

From the project root, with the pinned Rust toolchains, clang and cached Cargo
dependencies installed:

```sh
export CARGO_HOME="$PWD/.cache/riscv-cargo"
python3 risc-v/mldsa/build_guest.py
./risc-v/fors/build.sh
CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
  cargo +stable build --release --locked --offline --manifest-path risc-v/bench/Cargo.toml
pqbench="$PWD/.cache/riscv-host-target/release/riscv-pqbench"
```

Guest builds use `nightly-2026-10-03`; the native harness uses Rust 1.99.0. Build
provenance is recorded in [ML-DSA's manifest](mldsa/build-manifest.json) and
[FORS's manifest](fors/build-manifest.json). Each [measurement report](results/direct)
also records its backend revision, selected ELF SHA-256, thread count and proof rate.

## Measure, prove and verify

Replace `falcon` with `mldsa` or `fors` and choose the batch count:

```sh
"$pqbench" measure --scheme falcon --n 1 --out /tmp/falcon-measure.json
"$pqbench" prove --scheme falcon --n 1 --threads 8 --rate 1 \
  --warmup 1 --repeat 3 --proof /tmp/falcon.proof --out /tmp/falcon-prove.json
"$pqbench" verify --scheme falcon --proof /tmp/falcon.proof \
  --statement /tmp/falcon.proof.statement.json \
  --expect-statement-sha256 "$pq_intended_statement_sha256" \
  --expect-elf-sha256 "$pq_approved_elf_sha256" --out /tmp/falcon-verify.json
```

The receiver sets both expected hashes from its own intended public claims and
approved program. Hashes supplied alongside a received proof do not authorize
that statement. Verification recomputes the output from the public records and
calls full `Program::verify`; it needs no signature witnesses or child proof files.
`measure` records execution/witness capacity but produces no proof.

Proving time includes execution, trace, witness construction and the STARK.
Fixture generation, compilation, program loading, serialization and subsequent
proof verification are outside that timer. Verification time includes proof
decoding and full verification, excluding statement derivation, ELF loading and
file reads. RSS is the process memory high-water mark, including setup and
warmup, rather than the guest heap alone.

A measured capacity applies to the selected guest, input profile, fixture prefix
and backend pin. Tables are padded to powers of two; the `2^28` commitment cap
limits internal witness words, not transmitted proof bytes. A successful
`measure` alone does not establish successful proof production.

## Review and figures

Independent scoped reviews are recorded for [ML-DSA](reviews/mldsa-security.md)
and [FORS](reviews/fors-security.md), with raw controls beside them. They do not
audit the entire leanVM backend or establish a deployed wallet policy.

Regenerate the [LaTeX/PGFPlots figures](figures/README.md) from completed, accepted
and verified proof reports:

```sh
python3 risc-v/scripts/figures.py --render
```

The generator writes CSV, TeX, PDF, PNG and source-hash provenance, without
extrapolating missing measurements.

## Recursive Falcon and ML-DSA trees

The [separate tree runner](tree-bench/README.md) uses the pinned backend's native
recursive aggregation API with the unchanged signature guests. The article
selects ten Falcon signatures or two ML-DSA signatures per leaf, binary merges
and disclosed repeat-last padding. Padding slots never count as new signatures.

The [matrix runner](scripts/tree_matrix.py) produces three complete fresh
pipelines at each of 10, 30, 70 and 100 distinct signatures, with a separate
public-only receiver for every root. Every leaf and merge proof is produced
again for each sample. Full `Tree::verify` checks the root and settles all
folded claims; no child proof files or signature witnesses are required by the
receiver. Source review and independent controls are in the
[tree integration review](reviews/riscv-tree-security.md).

```sh
python3 risc-v/scripts/tree_matrix.py --output risc-v/results/trees-rerun
python3 articles/scripts/mine_figures.py --render
```

The combined article figures use these RISC-V tree results and the new
[sumcheck-reduced Python leanISA FORS results](../leanISA/reduction/README.md),
retaining its specialised Keccak circuit. The earlier FORS wrapper remains
archived separately. Raw RISC-V trees, exact padding, component
timings, setup-inclusive verification and prepared verification are retained in
[`results/trees`](results/trees/). The article does not mix proof backends in one
measured tree.

## Capacity recheck

The original prefix boundaries are not universal signature-count limits.
An unchanged Falcon guest has now proved 33 distinct signatures from a different
valid input window. The baseline ML-DSA guest reproduces six, while a separately
reviewed 64-bit NTT-constant storage variant proves seven with identical FIPS 204
checks and the same commitment cap. FORS's RISC-V Keccak is software; its eighth
signature doubles the ALU table and exceeds the cap.

See the [lattice recheck](reviews/lattice-capacity-reaudit.md),
[FORS recheck](reviews/fors-capacity-reaudit.md),
[fresh baseline proofs](results/reaudit/baseline-fresh), and
[reviewed ML-DSA optimization](experiments/keccak-registers/twiddle64-independent-review.md).
Original measurements and guest identities remain unchanged. Fresh single-proof
checks are capacity evidence, not replacements for the original timing samples.
