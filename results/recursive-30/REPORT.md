# Actual recursive aggregation of 30 ETHFALCON signatures

One leanVM root proof was generated and independently verified for **30 distinct ETHFALCON key/message claims**. Six leaf proofs each verify five real signatures. The root guest executes leanVM's recursive proof verifier for all six leaves. This is a measured recursive proof, rather than a projection or a proof of host verification receipts.

```text
30 signatures → 6 independent proofs of 5 signatures → 1 recursive root
```

The final receiver needs the intended public keys/messages, the trusted leaf program and the root envelope. It needs neither signature witnesses nor child proof files. It also recomputes six deferred child-bytecode polynomial evaluations; omitting these checks would weaken the authorization claim.

## Measured result

Single complete run on Apple M4 Pro, 24 GiB RAM, 12 logical CPUs, macOS 26.3, Rust 1.99.0. Release build uses `target-cpu=native`, upstream jemalloc and the default upstream thread pool. Inverse-rate logarithm is 1. Leaf proofs were generated sequentially; **zero leaf proofs were reused**. These are preliminary single-run timings, without controlled thermal state or background activity.

| Measurement | Result |
|---|---:|
| Signatures / leaf proofs / recursive roots | 30 / 6 / 1 |
| Sum of six child proof sizes | 2,155,072 bytes (2.055 MiB) |
| Root core proof | 366,080 bytes (357.500 KiB) |
| Complete root envelope | **369,348 bytes (360.691 KiB)** |
| Envelope metadata and deferred points | 3,268 bytes |
| Six leaf proofs: total prover work | 27.521 s |
| Recursive root: prover work | **1.251 s** |
| Leaf + root prover work | **28.772 s** |
| Experiment process elapsed time | 31.802 s |
| Fresh-process root verification | **0.314 s** |
| Whole prover process peak RSS | 9.155 GiB |
| Root VM cycles | 1,914,234 |

Proof work includes VM execution, witness construction and proving. It excludes fixture generation, guest compilation, serialization and native verification. Experiment process time additionally includes advice preparation, native checks and adversarial guest executions; the initial leaf compilation precedes that timer. This is neither signing time nor a hardware-wallet/MPC benchmark.

The separate fresh-process verification took 152.46 ms to compile the root, 82.74 ms to prepare/evaluate the child bytecode at all six deferred points, and 78.22 ms to check the core proof, with approximately 0.19 ms for claim hashing and bookkeeping. The 313.61 ms total excludes CLI file loading, deserialization and initial leaf compilation. It includes uncached root bytecode preparation. No cached steady-state verification benchmark is claimed here. See [fresh verification JSON](fresh-verification.json).

| Leaf | Signatures | VM cycles | Proof bytes | Prove seconds |
|---|---:|---:|---:|---:|
| 0 | 5 | 8,044,153 | 359,408 | 6.146 |
| 1 | 5 | 8,044,486 | 358,832 | 5.665 |
| 2 | 5 | 8,044,396 | 359,536 | 3.532 |
| 3 | 5 | 8,044,261 | 360,080 | 3.424 |
| 4 | 5 | 8,044,306 | 359,024 | 4.554 |
| 5 | 5 | 8,044,333 | 358,192 | 4.200 |

Each leaf commits 168,080,384 witness words; the root commits 65,142,784. See [machine-readable report](report.json) and [complete run log](full-fresh-run.log).

## What is compressed

The envelope is **5.83 times smaller than the six child proof files combined**. However, the 30 detached compressed signatures total only **19,652 bytes (19.19 KiB)**. At this count, the aggregate is larger than the original signatures. This experiment demonstrates recursive verification and compression of proofs; it does not demonstrate a signature-bandwidth saving at 30 signatures.

The size above excludes the public claims and shared trusted code. Compact public keys total 26,910 bytes and messages total 960 bytes. The generated verbose JSON manifest occupies 135,281 bytes because it duplicates advisory metadata; a minimal JSON key/message manifest is 56,988 bytes. Neither JSON encoding is a proposed wire format. The shared leaf source occupies 25,783 bytes. Registration and distribution of keys/code would change the marginal cost in a deployed system.

## Statement and deferred checks

Each leaf verifies the ETHFALCON Keccak variant's signature equation, norm, ranges and hash-to-point relation, then hashes its ordered five canonical key/message claims. The receiver independently decodes each compact public key, derives the canonical polynomial-key commitment, hashes the actual message and reconstructs the leaf commitments. It ignores advisory public-input and claim-hash metadata in the manifest.

The root pins the leaf program seed and calls the upstream `verify_sub` six times. That verifier deliberately defers one child-bytecode evaluation per proof. The root binds each resulting point and claimed value, together with all six child public inputs, into its public statement. Each coordinate and value retains all 192 bits. The envelope transmits the six points; the receiver computes their values from the expected leaf bytecode and reconstructs the expected root public input before native root verification. It never accepts prover-supplied deferred values as the final answer.

This makes the envelope and final `aggregate-falcon verify` procedure the verification interface. Checking only `aggregate.core.proof`, or accepting a prover-chosen root public input, is insufficient for the advertised signature claim.

## Validation and review

[The independent integration review](../../docs/recursive-envelope-review.md) checked claim derivation, program pinning, in-VM child verification, all six deferred evaluations, field encoding and witness-free final verification. No demonstrated binding omission remains in the exercised implementation. This is a scoped correctness review, not a proof of the underlying proof system's soundness.

- A fresh subprocess accepted with only a stripped public key/message manifest, trusted leaf source and the root envelope. No child proofs or signature witnesses were present.
- Mutating a child scalar, actual Merkle leaf-row word or child public input **after host child verification** caused the recursive guest to reject.
- Changed intended messages, canonical public keys, claim order, duplicate/missing claims, wrong program identity, a changed top limb of a deferred coordinate, corrupted proof bytes and trailing transport bytes were rejected.
- A stronger, test-only control constructed a proof for a different tiny program under a cached expected seed. The partial recursive verifier accepted it with its claimed deferred value; discharging the obligation against the expected bytecode changed the required statement and rejected the root. This confirms why the outer evaluation is essential. The unchecked preparation helper exists only under `cfg(test)`. See [control result](deferred-boundary.json).
- `make test` passed two Rust encoding tests and all 40 Python tests. The expensive deferred-boundary test is normally ignored and was run separately successfully. Release Clippy with warnings denied also passed. See [validation log](validation.log).

## Reproduce

From the project root after `make setup`:

```sh
make build
PYTHONPATH=python .venv/bin/python -m pqbench.falcon_aggregate_inputs \
  --out artifacts/falcon-30-recursive
target/release/aggregate-falcon prove \
  --manifest artifacts/falcon-30-recursive/public.json \
  --leaf-source artifacts/falcon-30-recursive/leaf-program.py \
  --leaf-dir artifacts/falcon-30-recursive/leaves \
  --out-dir artifacts/falcon-30-recursive/proofs-fresh \
  --expect-leaf-guest-hash 4b4502f2a1a4231617baba69b86e1e4470cff3c3815c66eb8fdcb6e2c2db8a2e
target/release/aggregate-falcon verify \
  --manifest artifacts/falcon-30-recursive/public.json \
  --leaf-source artifacts/falcon-30-recursive/leaf-program.py \
  --proof artifacts/falcon-30-recursive/proofs-fresh/aggregate.proof \
  --expect-leaf-guest-hash 4b4502f2a1a4231617baba69b86e1e4470cff3c3815c66eb8fdcb6e2c2db8a2e
make test
cargo test --release --offline --bin aggregate-falcon \
  deferred_evaluation_is_required_for_root_authorization -- --ignored --nocapture
```

Use an empty output directory for a complete run: existing leaf proofs are reused after native verification against the expected program and claims. `make experiment-30` uses the `proofs` directory and permits this reuse. Input generation uses 30 distinct keys and 30 distinct 32-byte messages, real native C signatures and independent Python verification. Its deterministic public seeds are benchmark material, unsuitable for funds. The proof relation uses an expanded signature witness and canonical expanded key commitment; it does not parse the compact signature bytes inside the VM.

Local generated artifacts: [root envelope](../../artifacts/falcon-30-recursive/proofs-fresh/aggregate.proof), [public claims](../../artifacts/falcon-30-recursive/public.json), [trusted leaf source](../../artifacts/falcon-30-recursive/leaf-program.py). They are generated files excluded from Git; the source and deterministic generator reproduce them.

Pinned leanVM revision: `575df819d9c857f38068cecf7b1640e0ce4bfb29`. Root program hash: `060e083a0243654602cec9027882a63733c30fe659f0d75b7de802405a06f7c1`. Root public input: `14e79461da9b749201566751671ee0dba6b0979051f63e28bdbff918da8083a7`. Other dependency revisions are in [upstream.lock.json](../../upstream.lock.json).

## Scope

This is **one level of fixed six-to-one recursion**, all children using the same five-signature ETHFALCON guest. It does not measure arbitrary-depth trees, mixed signature schemes or Dilithium/FORS recursive aggregation. The copied generic verifier helpers are attributed and extracted under an exact upstream source hash; the vendor checkout remains unchanged.

It uses the current custom leanISA and the ZKNOX Keccak ETHFALCON variant, rather than [PR #490](https://github.com/leanEthereum/leanVM/pull/490)'s RISC-V SHAKE-Falcon implementation. It does not implement dependency unions, discards, EIP-8141 transaction validation or block-valid EIP-8288 objects. The pinned proofs **are not zero knowledge**. These results do not establish production readiness or a many-level aggregation cost curve.
