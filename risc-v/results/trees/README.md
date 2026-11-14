# RISC-V recursive tree results

All eight requested configurations completed three actual fresh proving
pipelines, with a separate full public-only receiver for each saved root.
These are measured proofs, not sums projected from a single leaf benchmark.

The backend is unchanged leanVM RISC-V commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. The Falcon and ML-DSA guests retain
their baseline ELF identities. The native runner SHA-256 is
`2cb5d8a5ba86283e26cd327f78211b293526c2410cdb4fb20d936dbb89e0c668`.
The commitment cap remains `2^28` words and logarithmic inverse rate is one.
The host is an Apple M4 Pro with 24 GiB RAM; the runner requests eight workers.

| Workload | Signatures | Proving work, s | Root, KiB | Full verify prepared, ms | Full verify including setup, ms |
|---|---:|---:|---:|---:|---:|
| Falcon-512 | 10 | 1.384 | 260.44 | 1.637 | 51.22 |
| Falcon-512 | 30 | 3.579 | 260.53 | 1.847 | 52.22 |
| Falcon-512 | 70 | 8.222 | 261.62 | 1.957 | 52.67 |
| Falcon-512 | 100 | 12.593 | 260.41 | 1.892 | 52.77 |
| ML-DSA-44 | 10 | 8.385 | 260.16 | 1.919 | 53.31 |
| ML-DSA-44 | 30 | 23.711 | 260.78 | 1.943 | 54.54 |
| ML-DSA-44 | 70 | 60.131 | 261.75 | 2.004 | 55.23 |
| ML-DSA-44 | 100 | 82.561 | 260.84 | 1.969 | 55.42 |

Points are medians of three complete pipelines, each in a new process. There is
no in-process proving warmup, cross-sample proof reuse or simultaneous prover
job. Every actual leaf and every merge proof is freshly produced. Only the
explicit padding slots reuse the final real leaf within their own pipeline.
The 24 measured pipelines call the actual prover 378 times for leaves and 522
times for merges. They execute 1,260 signature-verification instances across
all sample repetitions and requested sizes, using the first 100 distinct keys
per scheme as the common benchmark corpus. These are 100 unique keys per
scheme, not 1,260 unique keys.

## Parameters and accounting

Falcon uses ten signatures per leaf; ML-DSA uses two. Both use binary first-level
and higher merges. The balanced output tree requires a power-of-two slot count,
at least two, so the last actual proof fills the disclosed remaining slots.
These repetitions never increase the reported signature count. All merge work,
including padding, is included. The ten-signature Falcon point wraps one real
batch proof in a two-slot first-level node. Larger points have multiple real
leaves and higher recursion nodes.

See the [declared plan and preflight choices](PLAN.md),
[runner and exact padding table](../../tree-bench/README.md), and
[preflight log](preflight/run.log). In particular, five-signature Falcon groups
had incompatible padded table heights, and ten-signature groups did not. The
ML-DSA two- versus five-signature choice follows actual verified preliminary
pilots under `pilot/`; those pilots are excluded from every median above.

Proving work is the sum of the recorded actual leaf and merge API calls. It
includes signature execution and proof production, and merge input verification
performed by the native API. Fixture preparation, program loading, tree setup,
serialization, files and separately timed receipt checks are outside that sum.
`pipeline_elapsed_s` retains the broader pipeline cost. These are sequential
work measurements, not a claim about distributed prover latency.

## Complete verification

Each configuration's `statement.json` contains public key/message records,
approved ELF and proof-shape descriptors, expected leaf outputs and canonical
padding rules. A receiver must obtain its expected statement hash and approved
ELF hash from its own trusted application. A sender-selected hash does not
authorize different transactions or programs.

The separate receiver derives every real leaf commitment from public records,
checks the cached outputs, reconstructs padding, decodes the root and invokes
complete upstream `Tree::verify`. It verifies the recursion proof and ordered
output digest, then settles all folded bytecode, initial-image,
recursion-fixed-polynomial and circuit-matrix claims. It reads no signature
advice or child proof files. This is the RISC-V native tree protocol, not the
older leanISA wrapper's O(E) list of external edge obligations.

Prepared verification includes decoding and complete verification with the
trusted program/tree key already present. Each receiver uses one verification
warmup and three timed prepared calls. Its including-setup measurement adds
program loading and `Tree::new` to the first complete decoding/verification.
Public-claim derivation is separate: at 100 signatures its medians are 0.968 ms
for Falcon and 1.409 ms for ML-DSA. File reads precede the timed regions.

The [independent review](../../reviews/riscv-tree-security.md) includes saved-root
mutation controls and Python reconstruction of leaf commitments and the entire
tagged/padded root digest. The 100-signature controls cover higher recursion
nodes as well as padding. This is bounded integration evidence, not a full
backend soundness audit or a deployed wallet implementation. Proofs are not
zero knowledge and the test keys are publicly reproducible.

## Files and reproduction

- `SCHEME-N/plan.json` measures every group in the original 100-record corpus.
- `SCHEME-N/statement.json` records the public intended claims and trusted shape.
- `SCHEME-N/sample-I/report.json` records actual component times and hashes.
- `SCHEME-N/sample-I/{leaf-J,merge-J,root}.proof` retains the saved proofs.
- `SCHEME-N/sample-I/verification.json` is the separate public-only receiver.
- `SCHEME-N/sample-I/pipeline-completed.json` records exact commands and binary.
- [summary.json](summary.json), [validation.json](validation.json) and
  [environment.json](environment.json) retain numeric results and provenance.

Run the complete matrix into a new directory:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
 cargo +stable build --release --locked --offline --manifest-path risc-v/tree-bench/Cargo.toml
python3 risc-v/scripts/tree_matrix.py --output risc-v/results/trees-rerun
python3 articles/scripts/mine_figures.py --render
```

The article's plot generator reads the published matrix at `results/trees` and
requires all 24 verified producer/receiver pairs. It also retains the leanISA
FORS measurements with their own backend, parameter and timing boundaries.
