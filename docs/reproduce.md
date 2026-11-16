# Reproduce the article

Run commands from the repository root. Existing reports are the measured data;
write new experiments to a new directory. Generating the figures needs only
Python 3 and the retained evidence. Proving requires the dependencies below.

The [cleanup validation](validation.md) records the complete release builds,
test suites and retained-receipt verification completed on 16 November 2026.

## Check the data and regenerate figures

```sh
python3 scripts/bootstrap.py --check
python3 articles/scripts/raccoon_figures.py --output build/figures
```

The figure command validates 51 direct points and 20 recursive points from
58 fresh pipelines, including the single Raccoon-G run at 100 signatures. It
checks frozen measured sources, complete receiver records, final receipts,
public statements, timing sums and part coverage. It writes CSV, TeX and a
source-hash manifest. It does not rerun cryptographic verification. Intermediate
proofs were removed; their recorded hashes, sizes and timings remain in reports.

Add `--render` to a new output directory to produce PDF and PNG with Tectonic
and Poppler's `pdftoppm`. The renderer uses an existing Tectonic resource cache
at `~/Library/Caches/Tectonic`; it reports an error if that cache is unavailable.
Alternatively compile the emitted TeX with a local PGFPlots installation.
The [nine article figures](../articles/figures/README.md) are already rendered.

## Dependencies and builds

The original host toolchain was Rust 1.99.0; guest builds used
`nightly-2026-10-03`. Install those toolchains and a C compiler supporting the
guest build scripts. Builds use the repository's `target-cpu=native` setting.
Saved guest ELFs are included, so rebuilding them is optional when reproducing
host benchmarks. Exact code revisions are in [upstream.lock.json](../upstream.lock.json).

```sh
python3 scripts/bootstrap.py
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
export CARGO_HOME="$PWD/.cache/riscv-cargo"
export CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target"

cargo +stable build --release --locked --manifest-path risc-v/bench/Cargo.toml
cargo +stable build --release --locked --manifest-path risc-v/tree-bench/Cargo.toml
cargo +stable build --release --locked --manifest-path risc-v/raccoon-optimized-study/direct/Cargo.toml
cargo +stable build --release --locked --manifest-path risc-v/raccoon-optimized-study/tree/Cargo.toml
cargo +stable build --release --locked --manifest-path risc-v/experiments/raccoong-segmented/runner/Cargo.toml
CARGO_TARGET_DIR="$PWD/target" cargo +stable build --release --locked --manifest-path leanISA/Cargo.toml
CARGO_TARGET_DIR="$PWD/target" cargo +stable build --release --locked --manifest-path leanISA/reduction/Cargo.toml
```

The first build fetches registry dependencies. Historical build scripts use
`--offline`; fetch their locked dependencies before invoking them on a clean
machine. `CARGO_HOME` is deliberately explicit; the removed Aerie cache aliases
are not needed. Guest sources, ELFs and build manifests live together in the
scheme directories. Rebuilding a guest can change its ELF with a different
compiler, so preserve the measured manifest and use separate output for trials.
The historical `build_guest.py` scripts expect a guest-local `target/` directory;
unset `CARGO_TARGET_DIR` before using those scripts. To build without replacing
measured ELFs or manifests, enter the guest directory and run
`cargo +nightly-2026-10-03 build --release --locked --offline` with a separate
`CARGO_TARGET_DIR` instead.

## Direct proofs

Falcon and ML-DSA share the direct runner. Replace `falcon` with `mldsa` and
choose the batch size. `measure` tests witness capacity without proving.

```sh
mkdir -p build/direct
.cache/riscv-host-target/release/riscv-pqbench prove \
  --scheme falcon --n 1 --threads 8 --rate 1 --warmup 1 --repeat 3 \
  --proof build/direct/falcon-1.proof --out build/direct/falcon-1.json
```

Raccoon uses the same direct interface through
`.cache/riscv-host-target/release/riscv-raccoon-optimized-direct`, with
`--scheme raccoon`. Match its allocator policy by setting
`_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0` and leaving `MALLOC_CONF`
unset. Its selected direct batch is one signature.

Prepare a FORS fixture from the retained corpus and run its direct prover:

```sh
PYTHONPATH=leanISA/python .venv/bin/python -m pqbench.article_inputs fixture \
  --scheme fors --count 5 --out build/direct/fors-5.input.json
target/release/pq-leanbench prove --input build/direct/fors-5.input.json \
  --proof build/direct/fors-5.proof --report build/direct/fors-5.json \
  --repeat 3 --warmup 1 --rate 1
```

For the original FORS series use counts 1 through 30, 70 and 100. Existing
direct receipts and witness-free statements are in
[`artifacts/article/fors`](../artifacts/article/fors); reports and separate
verifier timings are in [`leanISA/results/article/direct`](../leanISA/results/article/direct).

## Recursive proofs

Falcon uses ten signatures per leaf, ML-DSA two, FORS five, Raccoon one and
Raccoon-G five partial leaves per signature. All trees are binary with repeat-last
padding. Use the matrix runners for separate producer and public-only receiver
processes:

```sh
python3 risc-v/scripts/tree_matrix.py --output build/riscv-trees
.venv/bin/python leanISA/reduction/run_benchmarks.py --output build/fors-trees
```

Raccoon's launchers default to a command preview. Freeze a new cohort before
running the selected stages; `--execute-approved` is the launcher's execution
switch. The original source-frozen runners and their flags are retained:

```sh
python3 risc-v/raccoon-optimized-study/runtime_study.py --help
python3 risc-v/experiments/raccoong-segmented/matrix.py --help
```

For standard Raccoon, use stages `freeze`, `tree-plan`, then `tree`, with
`--scheme raccoon --leaf-size 1`, a new `--output`, and `--direct-binary` /
`--tree-binary` pointing to the binaries built above. Set the allocator policy
as for direct proofs. For G, use `freeze` then `matrix`, pass the new `--output`
and `--binary .cache/riscv-host-target/release/raccoong-segmented-treebench`.
Its `--counts` and `--samples` select the matrix; use one sample for count 100
to match the article. Both runners expose timeout and RSS limits. Recorded
successful runs used 19 or 20 GiB operational RSS thresholds and 21,600-second
timeouts. These sampling thresholds are not hard allocation caps.

## Verify a retained receipt

For Falcon and ML-DSA trees, use the native runner's `verify` action with the
retained statement and root. For example, after independently approving the
statement's keys/messages and the ELF identity:

```sh
.cache/riscv-host-target/release/riscv-pq-treebench verify \
  --outdir build/receiver \
  --statement risc-v/results/trees/falcon-10/statement.json \
  --proof risc-v/results/trees/falcon-10/sample-0/root.proof \
  --expect-statement-sha256 "$TRUSTED_STATEMENT_SHA256" \
  --expect-elf-sha256 "$TRUSTED_ELF_SHA256" --threads 8 --controls true
```

The hashes are verifier policy inputs, not values to trust from a proof sender.
[FORS's receiver](../leanISA/reduction/README.md) takes the intended `public.json`
and its approved leaf identity. [G's receiver](../risc-v/experiments/raccoong-segmented/SPEC.md)
also derives all five part claims from the untrusted witness binding in the
receipt. Every receiver must perform its complete verification operation.

```sh
.venv/bin/python -m unittest discover -s leanISA/tests -v
```

The FORS integration cases require the direct binary; the test runner explicitly
reports them as skipped if it has not been built. Other scoped controls are
kept beside their implementation reviews. The measured benchmark matrices take
substantial time and are not run by figure generation or setup.
