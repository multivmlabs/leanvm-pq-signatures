# Raccoon benchmark integration

These isolated runners extend the original direct and recursive RISC-V runners.
They preserve the original Falcon/ML-DSA runner sources, frozen binaries and
results. See [PLAN.md](PLAN.md) for the proposed experiments and approval gate.

The standard `raccoon` scheme uses the compact-key host API at
`risc-v/raccoon/host`. The public-only direct receiver independently commits the
intended count and ordered public key/message records, pins the guest ELF and
statement digest, and verifies the complete ordinary leanVM proof.

The tree receiver retains the original complete `Tree::verify` path: all intended
public records are committed, canonical padding is checked, and all folded
bytecode, image, fixed-polynomial and matrix claims are settled. It does not use
child proof files or signature witnesses. The producer records every actual leaf
and merge proof. Distinct public keys are enforced for the tree corpus and
intended statement.

The separate `raccoon-g` identifier uses `raccoong-riscv-host`, a 16,144-byte
public key, 32-byte message and 20,768-byte signature. Its guest and domain
separator are separate from standard Raccoon. Both guests explicitly allow at
most 64 input signatures. These transport limits do not establish proof capacity.

Build after the source-pinned guest ELF exists:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/raccoon-study-target" \
  cargo +stable build --release --offline --locked --manifest-path risc-v/raccoon-study/direct/Cargo.toml
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/raccoon-study-target" \
  cargo +stable build --release --offline --locked --manifest-path risc-v/raccoon-study/tree/Cargo.toml
```

Do not point the new build at `.cache/riscv-host-target`: that directory contains
the frozen historical runner binary. Lockfiles extend the original pinned
dependency versions with both local Raccoon crates. Both runners passed offline
release checks and all-target Clippy with warnings denied. Each runner's three
native correctness tests pass: both schemes bind count, order and every record's key
and message, and reject malformed public fields and variant substitution. Those
tests execute native commitment code only, without a RISC-V guest or proof.
The third test hashes the embedded ELFs and checks the embedded build manifests.

The `identity` action also reports each final native executable's embedded guest
hash and build-manifest hash without initializing the VM or prover:

```sh
.cache/raccoon-study-target/release/riscv-raccoon-direct identity \
  --scheme raccoon-g --out /tmp/raccoon-g-direct-identity.json
.cache/raccoon-study-target/release/riscv-raccoon-tree identity \
  --scheme raccoon-g --outdir /tmp/raccoon-g-tree-identity
```

`study.py` supports `freeze`, `capacity`, `direct`, `tree-plan`, and `tree`.
Without `--execute-approved` it only prints commands. The explicit flag is used
only after the user's approval in the chat. Every expensive command runs in a
fresh process and receives a 30-minute/18-GiB default stop bound. Producer and
separate public-only receiver logs and command hashes are retained. Tree samples
are always new pipelines, with no in-process proving warmup or cross-sample proof
reuse. Direct samples retain the historical one-warmup/three-measurement sampling
convention.

The provenance-only `freeze` stage records both build manifests, guest/source
hashes and native runner hashes. Expensive stages refuse modified sources or
binaries. The RSS bound fails closed: an unavailable `ps` monitor aborts the
command with `rss_monitor_unavailable`, preserving its error. This stop cannot
be reported as a backend capacity rejection.

The separate `articles/scripts/raccoon_figures.py` can later combine the existing
three schemes with both Raccoon studies. It requires fully verified new reports
before writing anything, validates all retained proof/statement/runner hashes,
and writes to a new figure directory. Proving and complete tree verification use
logarithmic timing axes. It has not produced performance figures before the
approved measurements exist.

No Raccoon performance or capacity experiments have been run during integration.
