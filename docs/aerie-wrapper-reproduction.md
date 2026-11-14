# Full Aerie verifier wrapper

This experiment compiles Aerie's complete scalar verifier into an RV64IM guest and proves its execution with a separate leanVM checkout. The earlier custom-ISA signature and arithmetic benchmarks keep their original checkout and data.

Use clean checkouts at these revisions:

| Directory | Repository | Revision |
|---|---|---|
| `vendor/aerie` | [a16z/aerie](https://github.com/a16z/aerie) | `49b6c212c209286c536196f53618823ffdf0e899` |
| `vendor/leanVM-riscv` | [leanEthereum/leanVM](https://github.com/leanEthereum/leanVM) | `06e5c9cd6981103786f9d0a17324241b559a50d3` |

The guest uses `nightly-2026-10-03` with `rust-src`. The native executables use Rust 1.99.0, selected here by `+stable`. The lockfiles are separate from the original project. The runtime adapters live under `experiments/aerie-port`; upstream checkouts remain unchanged.

```sh
rustup toolchain install nightly-2026-10-03 --profile minimal --component rust-src
export CARGO_HOME="$PWD/.cache/aerie-cargo"
CARGO_TARGET_DIR="$PWD/.cache/aerie-target" cargo +stable build --release --locked \
  --manifest-path experiments/aerie-wrapper-inputs/Cargo.toml
CARGO_TARGET_DIR="$PWD/.cache/aerie-wrapper-host-target" cargo +stable build --release --locked \
  --manifest-path experiments/aerie-leanvm-host/Cargo.toml
```

The default guest embeds fixed public verification setup and terminal NTT data. Generate and validate them before compiling. The setup exporter derives each setup from the pinned public seed, checks an exact validated roundtrip, and saves its descriptor and measurements. The upstream terminal-cache format only supports Q128; the owned Akita overlay adds a separately tagged Q64 format and retains the original arithmetic and proof checks.

```sh
for count in 1 10 30 70 100; do
  .cache/aerie-target/release/aerie-wrapper-inputs --export-setup "$count" \
    "artifacts/aerie-wrapper/public-setup/n$count"
done
```

Prepare the honest Falcon-v1.2 fixtures using the [native instructions](aerie-native-benchmarks.md). The Q64 checker uses real development proofs for interoperability checks and exports the immutable cache bank:

```sh
python3 scripts/aerie_wrapper_bench.py prepare \
  --inputs artifacts/aerie-wrapper/development --out results/aerie-wrapper/reproduction-prep \
  --repeat 1 --warmup 0
CARGO_TARGET_DIR="$PWD/.cache/aerie-q64-cache-target" cargo +stable build --release --locked \
  --manifest-path experiments/aerie-q64-cache-check/Cargo.toml
.cache/aerie-q64-cache-target/release/aerie-q64-cache-check "$PWD"
python3 experiments/aerie-leanvm-guest/build_guest.py
cp .cache/aerie-wrapper-target/riscv64im-unknown-none-elf/release/aerie-leanvm-guest \
  artifacts/aerie-wrapper/guest-16m-trusted-q64-cache.elf
```

The guest builder uses `-Zbuild-std=core,alloc` for `riscv64im-unknown-none-elf`, explicit generic RV64IM code generation, and the local linker script. It first builds the single-hart standard-library subset, then injects it into target consumers. Its cache invalidation accounts for that implicit dependency. A first build needs the Cargo dependencies in the configured cache because the actual guest build is offline. Fetch the guest manifest's locked dependency graph beforehand if needed.

Run the serial wrapper matrix:

```sh
python3 scripts/aerie_wrapper_bench.py all \
  --host .cache/aerie-wrapper-host-target/release/aerie-leanvm-host \
  --elf artifacts/aerie-wrapper/guest-16m-trusted-q64-cache.elf \
  --counts 1 10 30 70 100 --repeat 3 --warmup 1 --threads 12
```

For the matched preprocessing comparison, build the same sources without the terminal cache:

```sh
python3 experiments/aerie-leanvm-guest/build_guest.py --no-terminal-cache
cp .cache/aerie-wrapper-target/riscv64im-unknown-none-elf/release/aerie-leanvm-guest \
  artifacts/aerie-wrapper/guest-final-no-terminal-cache.elf
python3 scripts/aerie_wrapper_bench.py prove \
  --host .cache/aerie-wrapper-host-target/release/aerie-leanvm-host \
  --elf artifacts/aerie-wrapper/guest-final-no-terminal-cache.elf \
  --out results/aerie-wrapper/baseline --proofs artifacts/aerie-wrapper/baseline-proofs \
  --counts 1 10 30 70 100 --repeat 3 --warmup 1 --threads 12
```

`--all-schedules` retains preparation for every admitted schedule. `--derive-setup` also regenerates the public matrix inside the VM. These are separate profiling variants, not the final measured default.

Native Aerie setup, inner proving, guest execution, outer proving, serialization and fresh receipt verification have separate timers. The native proof and outer proof sizes are separate. The sum of the two prover timers is measured stage work; it is not browser latency or distributed throughput. Signing and fixture generation are outside the timers.

`--zk` selects the separate hiding protocol and output directory. The default is plain STARK proving. A completed plain run does not establish zero knowledge. A capacity error is recorded as a failure with no inferred proof size. The bounded reference interpreter can still measure full execution after such a failure, but that execution is not a STARK.

The receiver supplies its own intended ordered canonical statement and count, a trusted guest ELF/hash, and the outer proof. It does not need an Aerie proof file, salts or original signatures. The canonical statement still contains the public keys and messages, unless the receiver reconstructs them from transactions and account state. The public claim excludes the inner proof, while committing the exact profile and intended statement.

The orchestration script records an ELF hash for reproduction. A real receiver must obtain that hash from its trusted installation/configuration, rather than trust a hash sent with a received proof. See the [target contract](aerie-wrapper-target.md) and [scoped review](aerie-wrapper-review.md).

After freezing the executables, save their source closure and regenerate the figures:

```sh
python3 scripts/aerie_wrapper_provenance.py \
  --elf artifacts/aerie-wrapper/guest-16m-trusted-q64-cache.elf \
  --host .cache/aerie-wrapper-host-target/release/aerie-leanvm-host \
  --producer .cache/aerie-target/release/aerie-wrapper-inputs
.venv/bin/python scripts/aerie_wrapper_figures.py --modes non-zk
```

All new measurements live under `results/aerie-wrapper`. Generated inputs, trusted public setup and proof files live under ignored `artifacts/aerie-wrapper`. The original native Aerie, custom-ISA and recursive signature results remain separate.
