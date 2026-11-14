# Complete segmented Raccoon-G trees

This runner proves the unchanged strict signature relation using authenticated
matrix parts. A single part is not a signature proof. The selected guest uses
five parts per original signature, covering rows `(0,1)`, `(2,3)`, `(4,5)`,
`(6,7)` and `(8,8)`. The repeated final row is checked and charged. All parts
include the complete original canonicality, norm, key/message binding and
challenge checks. See the parent [specification](../SPEC.md).

The caller-authenticated statement contains original public keys/messages,
program identity and tree policy. It contains no witness-binding digest or
sender-provided expected output. The receipt supplies one untrusted 64-byte
binding per original signature. The consumer internally constructs every
canonical part output using the authorized pair and its common binding, applies
the specified padding, and calls complete native `Tree::verify`. Signatures,
the reconstructed commitment vector and child proof files are not receiver inputs.

The strict `RGSTK001` envelope is:

```
magic[8] || LE32(signatures) || LE32(parts_per_signature) || LE32(leaf_slots)
|| guest_sha256[32] || one binding[64] per signature
|| LE64(core_proof_bytes) || native TreeProof
```

It rejects inconsistent policy/count, wrong guest, truncation and trailing bytes.
The receipt adds exactly `60 + 64*N` bytes to the core proof. Public keys/messages
and the shared program remain additional transport. The benchmark policy requires
distinct public keys; it is not a proof of wallet derivation-path membership.

## Build and commands

From the project root, after the source-pinned guest build:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/raccoon-optimized-study-target" \
 cargo +stable build --release --locked --offline \
 --manifest-path risc-v/experiments/raccoong-segmented/runner/Cargo.toml
```

The distinct binary name is `raccoong-segmented-treebench`. `identity` reports its
embedded ELF and manifest hashes without executing the VM. `plan` inspects all
100 deterministic corpus signatures and their 500 parts, requiring the same
padded execution shape before producing the intended public statement. `prove`
requires that plan and refuses an existing sample directory. Counts 1 and 2 are
available for separate pilots; article counts are 10, 30, 70 and 100.

```sh
binary="$PWD/.cache/raccoon-optimized-study-target/release/raccoong-segmented-treebench"
"$binary" identity --outdir /tmp/g-identity
"$binary" plan --n 10 --outdir /tmp/g-tree-10 --threads 8 --rate 1
"$binary" prove --n 10 --outdir /tmp/g-tree-10 --sample sample-0 --threads 8 --rate 1
"$binary" verify --outdir /tmp/g-receiver \
 --statement /tmp/g-tree-10/statement.json \
 --proof /tmp/g-tree-10/sample-0/root.proof \
 --expect-statement-sha256 "$TRUSTED_STATEMENT_SHA256" \
 --expect-elf-sha256 "$TRUSTED_ELF_SHA256" --controls true --threads 8 --rate 1
```

The expected statement hash comes from the caller's authorized original claims,
not from a sender's proof package. Its binding digests are deliberately absent
from that authorization pin. They are accepted only through the verified parts.

`../matrix.py` previews commands by default. After approval, its `freeze` stage
pins guest and runner identities, build sources, backend and runtime allocator
settings. The `matrix` stage uses three completely fresh pipelines per requested
count, followed by isolated receivers initially containing only the public
statement and complete receipt. An explicit timeout override is available for
longer pipelines; the RSS monitor remains active. `--resume` skips only fully
completed samples. It does not reuse partial work or proofs across samples.

## Work and verification accounting

Every fresh producer loads raw signature fixtures outside the proving timer.
It then freshly reconstructs the complete commitment vector, computes the common
binding and constructs every part's advice. This preparation is charged once per
original signature in `native_prepare_s`. It is not read from a cached oracle.
Every real partial leaf is proved afresh, and every native merge is proved afresh.
Only canonical padding slots reuse the final real leaf within that pipeline.

`total_prove_s` is `native_prepare_s + leaf_prove_s + merge_prove_s`. Reports
retain every proof file, hash, per-call duration and actual execution statistics.
They distinguish original signature count, real partial leaves, padding slots
and merge count. For 100 signatures, the selected layout has 500 real partial
leaves, 512 slots and 511 fresh merges.

The production prepared consumer decodes the envelope, derives all part outputs
from authorized pairs and sender bindings, decodes the native proof and settles
every folded terminal claim. Its samples are `prepared_complete_verify_s`.
`prepared_core_verify_s` separately measures native proof decoding and complete
`Tree::verify` with expected outputs already derived, matching the earlier
RISC-V core-verifier timing boundary. `public_claim_derivation_s` records the
auxiliary parsing/output derivation independently. Cold complete verification
includes public configuration preparation, program loading, tree setup and the
first complete consumer call. File reads precede the timing regions.

Consumer controls reject changed binding digests, original keys/messages,
signature counts, part policy, missing/duplicated/reordered parts, corrupt roots,
truncation and trailing bytes. These controls run outside the verification timer.
The scope is implementation correctness under the documented hash assumptions.
It is not an audit of leanVM's proof system, a new signature security proof or a
completed Raccoon-G paper-conformance review. Proof mode is plain, not ZK.
