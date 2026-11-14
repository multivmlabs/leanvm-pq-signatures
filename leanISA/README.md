# Post-quantum signature proofs in leanVM

A working research project for **real leanVM proofs of ethFalcon-512, SHAKE Falcon-512, ethDilithium2, ML-DSA-44 and a standalone Keccak FORS variant**. Verification happens inside the VM: no host-verified receipt stands in for a signature check. It includes valid inputs, adversarial witness tests, saved proof files, independent proof verification, native verification baselines, direct-batch benchmarks and an upstream leanSPHINCS/recursion reference.

This is an **experimental EIP-8288 variant**, not an Ethereum client integration. Current leanVM proofs **are not zero knowledge**. The project includes an actual fixed-arity recursive proof of six five-signature ETHFALCON leaves, covering 30 signatures, and a generic runner for bounded multilevel trees. It does not implement EIP dependency unions/discards or produce block-valid EIP objects. Direct batches still encounter the pinned backend's witness-size limit. See [architecture and integration boundary](docs/architecture.md).

The [article](articles/leanvm-signature-aggregation.md) compares ETHFALCON, SHAKE Falcon, ETHDILITHIUM, ML-DSA-44 and the research FORS relation, with [methodology](articles/leanvm-signature-aggregation-methodology.md) and [raw data](results/article/). The primary, fan-in and leaf-size benchmark matrix is complete; [final validation status](docs/ethresearch-article-plan.md) is tracked separately. To reproduce it, `make article-inputs` prepares 100 public benchmark records per scheme, `make article-bench` runs the sequential native/direct/tree matrix including leaf-size sensitivity, and `make article-figures` exports figures and machine-readable results. Use `ARTICLE_SCHEMES=fors ARTICLE_ARGS='--counts 10 30 --repeat 3 --warmup 1'` for a smaller run; `ARTICLE_FIGURE_ARGS=--allow-incomplete` labels partial previews. The [tree format](docs/tree-format.md) pins intended leaf statements and every program, retains deferred checks for all edges, and verifies one root proof. Auxiliary data and native checking grow with tree size. Merge programs specialize to a complete global plan; this benchmark does not implement reusable online mempool subtrees. Rerun leaf-size sensitivity alone with `.venv/bin/python scripts/article_bench.py sensitivity`.

`make setup` installs the proving/input dependencies. Plotting dependencies are optional: `make article-figures` first installs the pinned `requirements-plots.txt` through `make article-plot-deps`. Before invoking the figure script directly in a clean virtual environment, run `.venv/bin/python -m pip install -r requirements-plots.txt`.

The [Aerie study](articles/aerie-under-leanvm.md) now includes a complete RV64IM verifier guest, native Falcon-v1.2 aggregation, immutable public preprocessing and matched 1/10/30/70/100 execution benchmarks. Real aggregates pass and twelve altered-input controls trap, but every actual outer prover attempt exceeds the pinned backend's capacity. No complete Aerie leanSTARK was produced. See the [full report](results/aerie-wrapper/REPORT.md), [reproduction guide](docs/aerie-wrapper-reproduction.md), [wrapper review](docs/aerie-wrapper-review.md), [native commands](docs/aerie-native-benchmarks.md) and separate [kernel review](docs/aerie-kernel-review.md).

## Implemented relations

| Guest | Verification performed in the VM | Key and signature boundary |
|---|---|---|
| [ethFalcon-512](docs/falcon.md) | Keccak hash-to-point with rejection sampling, full negacyclic polynomial product via three NTTs, canonical coefficient bounds and squared-norm checks | Canonical expanded key commitment; canonically encodable signature witness. Exact upstream compressed KATs checked independently outside the VM. |
| [Falcon-512, SHAKE256](python/pqbench/falcon_standard.py) | Round-3 Falcon SHAKE256 hash-to-point with rejection sampling; the same constrained polynomial product, coefficient and squared-norm checks | Canonical expanded key commitment and signature witness. Compact key/signature decoding happens outside the VM; independent C/Python checks establish fixture compatibility. |
| [ethDilithium2](docs/dilithium.md) | Keccak challenge generation, five forward/four inverse NTTs, matrix-vector products, norm, hints, rounding, packing and challenge hash | Registered expanded `(A_hat,t1_hat,tr)` key commitment. Compact-key expansion is checked by fixture generation, not proved in the guest. |
| [ML-DSA-44, SHAKE](python/pqbench/mldsa.py) | FIPS 204 pure verification of 32-byte messages with empty context; SHAKE message/challenge generation and the constrained polynomial, norm, hint and packing checks | Registered expanded `(A_hat,t1_hat,tr)` key commitment. Compact-key expansion and compact-signature decoding happen outside the VM. |
| [FORS research variant](docs/fors.md) | Message-derived indices, all leaf/path hashes, forest root authentication and batch binding | Keccak-256; `n=32,k=16,a=8`; 4,608-byte signatures, 64-byte keys. Few-time research component, not full leanSPHINCS or FIPS 205. |

ethFalcon and ethDilithium are the pinned ZKNOX **Keccak variants**. The standard comparisons use round-3 Falcon-512 with SHAKE256 and FIPS 204 ML-DSA-44; ML-DSA-44 is not round-3 Dilithium2. All four lattice guests use the expanded witness/key boundaries documented above. The schemes and parameters are not security-equivalent. The signature guests are tested research code, without a security audit or formal proof.

## Setup

Requires Rust/Cargo, Python 3.9+, Git and Clang, on a machine supported by the pinned leanVM kernels. Benchmarks here use Apple silicon. Sources are fetched at exact commits and remain unmodified; `vendor/`, generated fixtures, native builds and proof artifacts are ignored by Git. `Cargo.lock`, Python dependency pins and `upstream.lock.json` capture the dependencies.

```sh
make setup
make build
make test
make smoke
```

`make setup` downloads public sources and installs dependencies into `.venv`. It refuses to reset an existing source checkout at a different revision or with local edits.

## Produce and independently verify a proof

```sh
export PYTHONPATH="$PWD/python"
.venv/bin/python -m pqbench fixture --scheme ethfalcon --count 1 --out artifacts/falcon.json
target/release/pq-leanbench prove --input artifacts/falcon.json \
  --proof artifacts/falcon.proof --report artifacts/falcon-report.json \
  --rate 1 --repeat 3 --warmup 1
target/release/pq-leanbench verify \
  --input artifacts/falcon.proof.statement.json --proof artifacts/falcon.proof
```

Change `--scheme` to `ethdilithium` or `fors`. The exported statement contains no signature witness. A verifier must trust the selected guest and recompute the expected public batch commitment from its intended key/message claims. Accepting a prover-chosen key or message would prove the wrong authorization statement.

The `verify` command reports bytecode setup, uncached verification and repeated verification with cached bytecode separately. Use `--repeat 3 --warmup 1` for repeated cached samples. `scripts/verify_saved.py` applies this check to saved benchmark artifacts. Randomized Dilithium inputs can be reconstructed exactly from versioned reports with `fixture --scheme ethdilithium --count 1 --replay results/2026-11-03-dilithium/ethdilithium-1.json --out artifacts/replayed.json`.

For received artifacts, pin both expected values from trusted local configuration and the intended claims:

```sh
target/release/pq-leanbench verify --input received.statement.json --proof received.proof \
  --expect-guest-hash "$TRUSTED_GUEST_HASH" --expect-public-input "$EXPECTED_BATCH_DIGEST"
```

The runner reports `statement_pinned=true` only when both checks were requested and passed. Reading the expected values out of the received statement would not authenticate it. The generic unpinned `verify` command checks the execution relation supplied in its input; it does not establish that the supplied program is a signature verifier or that its key/message claims are the ones the caller intended. Scheme labels and fixture metadata are descriptive and are not authenticated. Proof decoding rejects trailing bytes.

For an experimental dependency-frame encoding, first verify the proof and then export its local codec:

```sh
.venv/bin/python -m pqbench dependency \
  --statement artifacts/falcon.proof.statement.json --proof artifacts/falcon.proof \
  --out artifacts/falcon-dependency.json
```

The output is explicitly marked invalid under the current EIP-8288 draft. It is a reviewable proposal for the generic-proof route, not a transaction to broadcast.

## Benchmark and model larger workloads

To generate 30 distinct, real ETHFALCON signatures and prove six leaf proofs plus one recursive root:

```sh
make experiment-30
target/release/aggregate-falcon verify \
  --manifest artifacts/falcon-30-recursive/public.json \
  --leaf-source artifacts/falcon-30-recursive/leaf-program.py \
  --proof artifacts/falcon-30-recursive/proofs/aggregate.proof \
  --expect-leaf-guest-hash 4b4502f2a1a4231617baba69b86e1e4470cff3c3815c66eb8fdcb6e2c2db8a2e
```

The final command uses public key/message claims, the trusted leaf program and one root envelope. It uses no child proofs or signatures. Six deferred bytecode evaluations are recomputed natively and bound into the root statement; the envelope carries their points. See [the actual recursive experiment](results/recursive-30/REPORT.md) for costs and [the integration review](docs/recursive-envelope-review.md) for validation. `prove` reuses existing leaf proofs only after verifying them against the expected program and claims; choose an empty output directory for a cold full run.

Run prover jobs sequentially. Each workload gets a separate process, one warmup and three measured proofs. The output directory must be empty to prevent mixing stale measurements. Start with one lattice signature and check memory before increasing counts.

```sh
export PYTHONPATH="$PWD/python"
.venv/bin/python -m pqbench bench --schemes ethfalcon --counts 1 2 4 \
  --out results/my-falcon --name my-falcon
.venv/bin/python -m pqbench bench --schemes ethdilithium --counts 1 \
  --out results/my-dilithium --name my-dilithium
.venv/bin/python -m pqbench bench --schemes fors --counts 1 16 64 256 \
  --out results/my-fors --name my-fors
.venv/bin/python scripts/baseline.py --counts 1 16 64 256 --recursion \
  --out results/my-upstream
```

Use `--mode execute` to collect cycles without producing proofs. `--rate 1..4` exposes the backend's proof-size/proving tradeoff; all committed results here use rate 1. `LEANVM_NUM_THREADS` controls the upstream pool. `--continue-on-error` records unsupported workloads and continues. The raw proof excludes the public claim list, public keys, bytecode distribution and networking overhead. No gas or hardware-wallet signing estimates are inferred from proof time.

```sh
.venv/bin/python -m pqbench project results/my-falcon/ethfalcon-4.json --total 10000
```

This reports **projected leaf prover work**, not a measured aggregate or parallel wall time. Adding `--merge-seconds VALUE` makes an explicit user-supplied binary-recursion assumption. The built-in upstream recursion experiment measures leanSPHINCS children. The separate `experiment-30` target measures a real ETHFALCON merge; the article workflow records actual multilevel tree measurements separately under `results/article`.

## Measurements and interpretation

The follow-up [1-to-30 proof-size study](results/size-growth/REPORT.md) contains an actual curve and exact byte counts. The [encoding review](docs/encoding-review.md) records compatibility fixes, adversarial checks and remaining semantic/security boundaries. Falcon sizes in the older comparison use the pre-review restricted guest; the new study uses the corrected verifier.

See [the measured comparison](results/COMPARISON.md), with raw samples, exact guest hashes and per-scheme reports under `results/`. Each successful proof was verified. Proof time includes VM execution, witness construction and proving, and excludes compilation, fixture generation, serialization and subsequent proof verification. Peak RSS is the entire process's high-water mark, including warmups. Native verification timing is recorded separately; Python reference and upstream C results are labeled separately.

The main design question is not just signature size. Current leanVM has a dedicated Keccak operation and binary-field arithmetic. Prime-field lattice arithmetic must be explicitly constrained. Larger batches can amortize fixed proving overhead, but the backend's finite witness cap bounds each direct leaf. Crossing that cap needs a more efficient guest, a deliberately changed proof-system configuration, or an implemented recursive wrapper.

[The recursion plan](docs/recursion-plan.md) identifies the reused upstream verifier and further designs. Its first fixed-arity wrapper stage is implemented and benchmarked by `experiment-30`; [the tree runner](docs/tree-format.md) extends it to bounded multilevel trees while retaining every deferred evaluation.

For EIP-8141 wallets, aggregators can run away from the signing device, but the wallet must still bind the canonical transaction digest and enforce nonce, chain, expiry, policy and approval rules. Aggregation is not a threshold signing protocol; MPC security and hardware-wallet signing latency/memory require separate evaluation. FORS's omitted key-authentication layer makes full leanSPHINCS the relevant hash-based wallet baseline.

Primary motivation: [recursive mempool aggregation](https://ethresear.ch/t/recursive-stark-based-bandwidth-efficient-mempool/23838), [signature merging](https://ethresear.ch/t/signature-merging-for-large-scale-consensus/17386), [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288), and [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141).
