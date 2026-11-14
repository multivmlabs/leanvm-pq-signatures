# RISC-V signature trees

This isolated runner uses the unchanged Falcon and ML-DSA-44 guests and the
native recursive-tree API of leanVM commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. It never changes the commitment cap,
removes verifier obligations, or changes signature relations.

The article's selected layout is ten Falcon signatures or two ML-DSA signatures per
leaf, binary first-level merges and binary higher merges. All 100 deterministic
corpus records are measured during planning, in their original order. Every
leaf must announce the same padded table heights. Five-signature Falcon groups
did not satisfy that condition; choosing ten avoids those shape differences
without selecting a favourable subset of records.

The runner supports several leaf sizes. Its ML-DSA default is five; the article
explicitly requests `--leaf-size 2`. A preliminary ten-signature pilot with
five-signature leaves took 56.999 s, versus 8.053 s with two-signature leaves,
including every merge. Both are actual verified roots, kept separately under
`results/trees/pilot/`. This comparison selected a smaller operating point
before the three-sample matrix; it does not weaken the signature verification.

The native positional tree requires a power-of-two number of leaf slots.
Actual leaves are padded to the next power of two, at least two, by copying the
last actual leaf proof into the remaining slots. Padding is explicit, does not
count as additional signatures and does not require another signature proof.
Every merge proof, including those over padding slots, is freshly produced and
charged. Distinct intended public keys are checked on their decoded bytes.

| Scheme | Signatures | Actual leaves | Leaf slots | Fresh merge proofs |
|---|---:|---:|---:|---:|
| Falcon | 10 | 1 | 2 | 1 |
| Falcon | 30 | 3 | 4 | 3 |
| Falcon | 70 | 7 | 8 | 7 |
| Falcon | 100 | 10 | 16 | 15 |
| ML-DSA | 10 | 5 | 8 | 7 |
| ML-DSA | 30 | 15 | 16 | 15 |
| ML-DSA | 70 | 35 | 64 | 63 |
| ML-DSA | 100 | 50 | 64 | 63 |

## Commands

From the repository root:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
 cargo +stable build --release --offline --manifest-path risc-v/tree-bench/Cargo.toml

.cache/riscv-host-target/release/riscv-pq-treebench plan \
 --scheme falcon --n 10 --outdir risc-v/results/trees/falcon-10 --threads 8 --rate 1

.cache/riscv-host-target/release/riscv-pq-treebench prove \
 --scheme falcon --n 10 --outdir risc-v/results/trees/falcon-10 \
 --sample sample-0 --threads 8 --rate 1

# All eight configurations, three fresh producer/receiver pairs each.
# Select a new output directory to avoid overwriting the article measurements.
python3 risc-v/scripts/tree_matrix.py --output risc-v/results/trees-rerun
```

`plan` writes `plan.json` and a public-only `statement.json`. `prove` creates a
new sample directory, produces each actual leaf once, serializes and fully
verifies it, then proves every tree node. It saves individual proof files and
an incremental `report.json`. It refuses an existing sample directory. Progress
goes to stderr and the final stdout record is a small JSON summary.

The caller-trusted statement contains the intended key/message records, the
exact guest ELF hash, leaf/table shape, rate, layout and independently derived
leaf outputs. The receiver must obtain its hash from its application, not read
an expected hash from an untrusted sender.

```sh
.cache/riscv-host-target/release/riscv-pq-treebench verify \
 --outdir risc-v/results/trees/falcon-10/sample-0 \
 --statement risc-v/results/trees/falcon-10/statement.json \
 --proof risc-v/results/trees/falcon-10/sample-0/root.proof \
 --expect-statement-sha256 "$TRUSTED_STATEMENT_SHA256" \
 --expect-elf-sha256 "$TRUSTED_ELF_SHA256" --threads 8 --controls true
```

The receiver reads no advice, signatures or child proof files. It recomputes
the outputs from public records, applies the canonical padding, constructs the
approved tree and invokes complete `Tree::verify`. That call verifies the root
recursion proof and settles the folded bytecode, image, fixed-polynomial and
Flock-matrix claims. Unlike the archived leanISA wrapper, it does not send an
O(E) list of edge obligations for separate checking.

The public `LeafShape` API takes a `Stats` value, whose constructor is private.
The receiver obtains a container by measuring an exit-only local program and
replaces its public table counts with the trusted shape descriptor. Only those
counts enter `LeafShape::measured`; the exit program supplies no signature
claims and is not accepted in place of the approved ELF. No unsafe code or
backend changes are involved.

## Timing and sampling

`report.json` records the actual sum of all leaf and merge proving calls,
separate components, complete serialized root bytes, table budgets and peak
process RSS. The pipeline elapsed time also includes setup, fixture generation,
serialization, file writes and verification; it is not the same quantity as
proving work.

A separate `verify` process writes `verification.json`. Public-claim derivation
is timed separately. `cold_complete_verify_s` is program loading plus tree-key
setup plus the first decoding and complete root verification. Prepared timings
perform one warmup and three measured decoding-and-verification calls on the
same approved tree. Both verify all folded claims. File reads precede the timed
regions. The complete root byte count includes its protocol header, statement
and recursion transcript; public key/message records and trusted code are
separate transport.

Each producer invocation is one complete fresh pipeline, without an in-process
proving warmup. The article's sample matrix uses three new sample directories
in separate processes for each configuration. Preliminary pilots are retained
separately and are not in-process warmups or timing-curve samples. No real leaf
or merge proof is cached between pipelines.
Requested worker counts and the exact backend/guest pins are recorded; the
upstream pool may add efficiency-core workers.

`--controls true` additionally checks corrupted roots, trailing bytes, wrong
outputs, reordered leaves, changed counts, and changed public keys/messages
with recomputed commitments. Those controls are outside the verifier timing.
Independent review controls supplement them. These checks do not constitute a
proof-system soundness audit. The benchmark uses plain, non-zero-knowledge
proofs and publicly reproducible test keys.
