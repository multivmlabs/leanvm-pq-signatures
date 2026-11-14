# Native Aerie reproduction

These harnesses measure native Aerie code. The separate [full verifier wrapper](aerie-wrapper-reproduction.md) now implements and measures complete guest execution, with actual outer proving attempts refused by leanVM's capacity limit. Keep those results separate from the native timers below.

The checkout is pinned to `49b6c212c209286c536196f53618823ffdf0e899`. Its workspace lockfile pins Akita `e023b6a46143f7b23199ccecb2684192baf7b640`, Jolt `c7c2d08d5bb0c7c80501f29f723e595af7fcff3c` and Spongefish `ef9741346a150039427d9e0c02d6b2d73e93ec81`. Preserve the vendor checkout unchanged. The release selects Akita's `dev-protocol` profile and BLAKE2b transcript; these are protocol choices, not interchangeable implementation details.

## Timed runs

The original project setup does not fetch Aerie. Clone it into the ignored vendor directory and select the recorded revision first:

```sh
gh repo clone https://github.com/a16z/aerie.git vendor/aerie
git -C vendor/aerie checkout --detach 49b6c212c209286c536196f53618823ffdf0e899
```

Build the unmodified upstream harness using the same compiler as the local leanVM study, with its Cargo lockfile. The recorded compiler is Rust 1.99.0; `+stable` selected that version here. Select the recorded toolchain explicitly if the stable alias has advanced:

```sh
export CARGO_HOME="$PWD/.cache/aerie-cargo"
export CARGO_TARGET_DIR="$PWD/.cache/aerie-target"
cargo +stable bench --manifest-path vendor/aerie/Cargo.toml --locked \
  -p aerie-bench --features falcon-bench --bench falcon --no-run
```

The build prints the benchmark binary under `.cache/aerie-target/release/deps/falcon-*`. Pass that exact binary path to:

```sh
.venv/bin/python scripts/aerie_native_bench.py all --binary /absolute/path/to/falcon-BUILDHASH
```

The default matrix uses live record counts 1, 10, 30, 70, 100, 1,024, 8,192 and 32,768, with one and twelve Rayon workers. Every case runs in a separate process, with one warmup followed by three fresh proof roundtrips. Verification is measured with both the selected worker pool and a separate one-thread pool. Changing the worker count changes execution parallelism, not the proof profile.

Fixture generation first creates one deterministic `fn-dsa` corpus at the largest requested count and writes prefixes for the smaller cases. It uses distinct keys, signatures, per-record salts and ASCII messages. The original harness rechecks distinctness on every load and natively validates each signature while preparing the measured proving witness. These messages and the key-prefixed Falcon v1.2 framing differ from the earlier article's synthetic 32-byte round-3/ETH Falcon corpus. They do not establish a matched-relation speedup.

The proof path starts from canonical public keys, signatures and messages, and includes native signature checking, witness construction and wire encoding. Fixture keygen/signing and reusable setup are excluded. Setup is separately timed in each pass. Verification starts with a canonical-parsed public statement and includes proof decoding, source-bound public input derivation, streamed key/target evaluation, statement binding, three sum-check stages and the Akita verifier. Parsing the canonical public statement is outside that timer. The fresh verifier-only consumer times it separately.

The `verify_hash_to_point_ms` phase includes key hashing, target sampling and target contraction in the proof field; it is not a SHAKE-only benchmark. Early commitments and signature preprocessing overlap in the parallel prover, so phase intervals need not add to its total wall time. Use `prove_ms` for the total. The upstream TSV rounds timings to 0.1 ms; the JSON summaries preserve that precision rather than inventing finer measurements.

The report separates the full wire size, the 40 bytes per live signature for salts, header/non-salt PIOP bytes, and PCS commitments/opening. Public keys and messages are additional transport. RSS is the whole process peak, including warmup and setup. A fresh Python wrapper per case reads `getrusage(RUSAGE_CHILDREN)`, which reports bytes on macOS. This avoids `/usr/bin/time -l` failing on a sandbox-denied `kern.clockrate` sysctl after an otherwise successful child process.

The scripts preserve original stdout/stderr, commands, source revision, backend/compiler metadata, binary hashes, every timed sample and observed median/range under `results/aerie/native`. Public fixture material lives under ignored `artifacts/aerie/honest-fixtures`; signing secret keys are not serialized.

## Public-verifier controls

`experiments/aerie-native-controls` reads one of those exact fixture envelopes through Aerie's canonical parsers, proves it once, verifies the honest result, and checks rejection after changing a canonical key, message, record order, salt, proof body, record count, truncation or trailer. It calls the unchanged public `verify_aggregate` API. This is a correctness demonstration, not a security audit or a performance curve.

```sh
cargo +stable build --release --manifest-path experiments/aerie-native-controls/Cargo.toml
.cache/aerie-target/release/aerie-native-controls \
  artifacts/aerie/honest-fixtures/SELECTED-FIXTURE.bin artifacts/aerie/controls
```

`experiments/aerie-native-verifier` is a separate consumer with `aerie-verifier` default features disabled. It reads only the saved canonical public statement and Aerie aggregate bytes. It has no signer, signature-witness, prover or Rayon dependency. Check the resolved dependency tree and run it as a fresh process:

```sh
cargo +stable build --release --manifest-path experiments/aerie-native-verifier/Cargo.toml
cargo +stable tree --manifest-path experiments/aerie-native-verifier/Cargo.toml
.cache/aerie-target/release/aerie-native-verifier \
  artifacts/aerie/controls/statement.bin artifacts/aerie/controls/aggregate.aerie \
  results/aerie/native/fresh-verifier.json
```

The intended public keys and messages are supplied by the receiver. Aerie's wire proof cannot authorize a different transaction list merely because its embedded algebraic proof is valid.

The measured native curves use the upstream Cargo lockfile unchanged. Both final external correctness lockfiles retain every shared upstream package version and source; each adds only its local consumer package and uses a subset of the original graph. This check, exact lock hashes and the preserved initial-resolution audit are archived in `results/aerie/native/dependency-provenance.json`. The Aerie, Akita, Jolt and Spongefish source revisions and wire/profile choices remain pinned. The final verifier-only graph excludes Rayon, `fn-dsa`, Aerie's prover/witness crates and Akita's producer crates. Its feature tree is archived separately from the producer consumer's graph.
