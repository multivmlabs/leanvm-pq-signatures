# FORS under leanVM RISC-V

This guest verifies FORS with `n=32`, `k=16`, `a=8` and Ethereum Keccak-256.
It uses leanVM's official `riscv-exploration` backend pinned at
`06e5c9cd6981103786f9d0a17324241b559a50d3`. The vendor checkout is unchanged.

The signature is 4,608 bytes: 16 opened 32-byte secrets, each with eight 32-byte
Merkle authentication siblings. The public key is the 32-byte seed and 32-byte
forest root. Messages have exactly 32 bytes. Domain and address encodings are
fixed in `guest/src/lib.rs` and independently checked byte-for-byte by
`tests/cross_check.py`.

FORS is a few-time forest signature component. These measurements do not include
an SLH-DSA hypertree or key-authentication structure and do not establish the
security of an unlimited-use wallet signature. Every benchmark record has a fresh
key; deterministic signing seeds are public test material.

## Proved computation

For each record, the guest derives all 16 indices from
`Keccak256(MSG_domain || seed || root || message)`, hashes each opened secret,
recomputes its eight address-bound authentication nodes, then compresses all tree
roots and checks equality with the claimed public root. Secret values,
authentication paths, public keys and messages are read as complete fixed-width
word arrays. Nothing is accepted as a host-side verification result.

Domain labels are the ASCII string `FORS:` followed by `LEAF`, `NODE`, `ROOT` or
`MSG`, zero-padded to 12 bytes, then the bytes `[1,32,16,8]`. Addresses are
`tree_LE32 || height_LE32 || index_LE64`. All digest words represent little-endian
bytes. Every node's left/right order and parent address are recomputed in the
guest from the message-derived index.

The guest commits the public words, in order:

```
[FORSv001 as one little-endian u64, 32, 16, 8]
count_u64
(seed[4], root[4], message[4]) for each record
```

The SDK hashes these words with BLAKE2s to produce the public output. A receiver
pins the intended ELF and derives this output from its intended public records.
The host helper `expected_output(&[Header])` needs no signatures. The count and
profile are committed as well as the ordered claim list. Duplicate claims are
allowed by the batch relation; deduplication is application policy.

Advice is `count` followed by each 12-word public header and 576-word signature.
The guest refuses zero or more than 445 records. Its 2 MiB advice region is sized
above the measured commitment capacity; increase it and rebuild if a future
backend makes that input region the binding constraint. RAM is the upstream
1 MiB map. Guest verification reuses fixed-size stack buffers; it allocates no
heap and stores no full Merkle trees. The host constructs full trees outside the
proving timer.

Keccak uses the official SDK software permutation. The RISC-V backend's BLAKE2s
compression instruction accelerates the public output and proof infrastructure,
not the FORS hash function. A signature needs 150 Keccak permutations: one
message hash, 16 leaf hashes, 128 internal-node hashes and five permutations for
the final forest-root hash.

## Build and checks

Guest compiler: `rustc 1.101.0-nightly (0abfedbc7 2026-10-02)`, selected by
`guest/rust-toolchain.toml` (`nightly-2026-10-03`). Native host: Rust 1.99.0.

```
./risc-v/fors/build.sh
cargo +stable test --release --locked --offline --manifest-path risc-v/fors/host/Cargo.toml
cargo +stable run --release --locked --offline --manifest-path risc-v/fors/host/Cargo.toml -- 2 > /tmp/fors-fixtures.json
.venv/bin/python risc-v/fors/tests/cross_check.py /tmp/fors-fixtures.json
```

Set `CARGO_HOME` to a writable populated cache when using a sandbox. Build and
fixture generation are excluded from proof timings. Actual measurement and
capacity results are recorded by the common RISC-V runner.

Release tests execute the genuine ELF in leanVM's RISC-V interpreter. They check
the honest output and guest rejection of changes to the seed, root, message,
opened secret, first and last authentication siblings, and invalid counts. Native
controls additionally swap tree openings. The independent Python oracle uses
PyCryptodome Keccak and a byte-based generator, and matches every byte of two
complete Rust-generated signatures and keys. It also rejects a changed
Merkle sibling and a wrong node domain. These tests do not replace the separate
security review or prove the soundness of leanVM's backend.
