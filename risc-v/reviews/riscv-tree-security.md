# RISC-V recursive signature tree review

Reviewed 6 November 2026.

Status: source review, 103 independent saved-root consumer controls and public
binding checks of all 24 selected matrix samples passed. The controls include
both selected 100-signature roots with higher recursion nodes.
This is a scoped integration review, not a new audit of leanVM's proof system.

## Scope and intended statement

The backend is the unmodified experimental RISC-V revision
`06e5c9cd6981103786f9d0a17324241b559a50d3`. The new
[`tree-bench`](../tree-bench/src/main.rs) uses the existing signature guests:

- Falcon ELF SHA-256: `421470c0aef38d3b2c2ca392edd7786c7425085f6a430b0286a679c69f0f9a4c`.
- ML-DSA ELF SHA-256: `73fa19d855adbd0ad6d8368260b5e1b173cc57a854e52624dd1b8e65d95f69d6`.

The consumer must authenticate its intended public key/message records and the
approved ELF. Acceptance should establish verification of every intended
signature under that guest. The producer controls advice, intermediate proofs,
serialized root and untrusted transport metadata. The consumer supplies both an
expected public-statement digest and expected ELF digest independently of those
received artifacts. These benchmark proofs are not zero knowledge.

The final benchmark uses ten signatures per Falcon leaf and two per ML-DSA
leaf. At 100 signatures, Falcon has ten fresh real leaves in sixteen total
slots, while ML-DSA has fifty fresh real leaves in sixty-four total slots.
Padding repeats the last real proof, and every merge is charged. The earlier
five-signature ML-DSA pilot below remains an additional validity control; its
timing is not part of the final selected matrix.

## Binding and full verification

The receiver rejects a mismatched caller pin, validates the strict statement
schema and embedded guest identity, independently derives every real leaf's
output from public records, and checks the cached outputs against that
derivation. Public-key distinctness is checked over decoded bytes. It then
reconstructs the disclosed repeat-last padding, decodes the root, and calls the
complete upstream `Tree::verify`.

This call checks the root proof and ordered output digest, then settles the
reduced bytecode, initial-image, recursion-fixed-polynomial and circuit-matrix
claims. It is not a call to `verify_core` or an uncompleted recursion verifier.
The native tree protocol reduces these obligations inside each merge; unlike
the older FORS wrapper, it does not return a separate obligation for every tree
edge. The relevant upstream paths are `rec/tree/mod.rs:731-749,813-842` and
`rec/tree/reduce/mod.rs`.

The public shape adapter uses an exit-only program solely to obtain the
non-exhaustive `Stats` container. It replaces every table count with the
caller-pinned power-of-two descriptor. `LeafShape::measured` reads only those
counts and the supplied commitment rate. `Tree::new` is still built against the
actual signature program, not the exit-only program, and validates the shape.
No signature advice or child proof is necessary for this adapter or receiver.

Each real leaf is freshly proved, serialized, decoded, and fully verified under
the approved signature program. Its announced shape must match the tree. Every
first-level and higher merge is freshly proved and included in measured work.
Repeated padding proofs are explicitly reused slots, not additional signatures
or fresh leaf proofs. The public records retain all distinct original claims;
the receiver constructs the same canonical padding independently.

## Independent controls

The [review script](riscv-tree-controls/consumer_controls.py) uses Python's
standard BLAKE2s implementation to reconstruct leaf commitments. Its encoder
matches all 18 existing saved Falcon/ML-DSA direct-batch statements.

It also reconstructs the complete tagged tree digest, including the
`tree-fst`/`tree-nod` domains, child counts and canonical padding, and compares it
with the actual digest halves serialized in the root's `LVMT` version-19
statement. This checks the public binding independently of the Rust SDK; it is
not a replacement for STARK verification.

Saved-root acceptance controls run the unchanged production receiver from a
temporary directory containing only public records and one root proof. Changed
keys/messages/order receive independently recomputed outputs and fresh caller
pins, so a rejected altered statement is not merely a stale-file-hash check.
Additional controls cover cached outputs, counts, padding, arities, backend and
ELF pins, rates, malformed table heights, strict schema and damaged proof
transport. The following actual saved roots passed all expected outcomes:

| Root | Independent receiver controls | Receipt |
|---|---:|---|
| Falcon, 10 signatures, pilot | 25 passed | [Falcon controls](riscv-tree-controls/falcon-pilot-controls.json) |
| ML-DSA, 10 signatures, five-signature-leaf pilot | 26 passed | [ML-DSA pilot controls](riscv-tree-controls/mldsa-pilot-controls.json) |
| Falcon, 100 signatures, selected sample 0 | 26 passed | [Falcon full-tree controls](riscv-tree-controls/falcon-100-controls.json) |
| ML-DSA, 100 signatures, selected sample 0 | 26 passed | [ML-DSA full-tree controls](riscv-tree-controls/mldsa-100-controls.json) |

These ran the frozen consumer SHA-256
`2cb5d8a5ba86283e26cd327f78211b293526c2410cdb4fb20d936dbb89e0c668`.
The reviewed harness source SHA-256 is
`560e6babfd0195e38080dee1502adf1d1dbd767735553d232f83f5c87b12ac0c`,
and the independent control script SHA-256 is
`dd3fc1e3fe8fdee5090a40035f2a08cf8deb6313f1cd770e2516a574ceae2d42`.
All independently reconstructed root digests match their serialized public
statements. The honest public-only receiver accepted; every altered statement
and damaged proof control rejected. Falcon's single real leaf at this count is
repeated into the two minimum slots, so swapping those identical padding outputs
would not be a negative control. Reordering records within the real leaf is
tested instead. The two 100-signature controls cover higher recursion nodes,
ordered real leaves and nontrivial canonical padding. They each contain 100
distinct public keys. The script independently checks every real leaf's
commitment and the full root digest before invoking the native receiver.

The separate [matrix binding check](riscv-tree-controls/matrix-binding-checks.json)
reconstructs all real leaf digests and root digests for the 24 selected samples:
three complete pipelines at each of 10, 30, 70 and 100 signatures, for both
schemes. Root bytes and hashes match the producer and public-only receiver
receipts. Every receiver reports full folded-claim settlement and no child
proof or signature use. Real-leaf counts, merge counts, padding slots and the
sum of fresh leaf-plus-merge proving work agree with the recorded plans.

## Findings and limits

No accepting invalid-signature or incorrect-public-binding path was found in
the inspected integration or executed saved-root controls. Two implementation
issues identified during review were corrected before freezing the benchmark
binary: decoded-key distinctness
instead of hex-string distinctness, and skipping a leaf-order negative control
when one real leaf is intentionally duplicated into both minimum slots. Input
count validation was also placed before slicing the corpus.

The review does not establish backend soundness, compiler correctness, the
security of Falcon or ML-DSA, or Ethereum integration. It reuses the already
reviewed unchanged guest relations. Invalid arbitrary-proof denial of service,
production transaction canonicalization and account-policy enforcement remain
outside this benchmark's integration scope.
