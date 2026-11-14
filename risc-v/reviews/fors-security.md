# FORS RISC-V guest: independent security review

Reviewed 6 November 2026. This is a scoped source and guest-execution review,
not a proof of the soundness of the entire leanVM backend.

## Result

No accepting invalid FORS execution was found in the reviewed implementation.
The guest verifies all authentication paths and binds the intended public
seed, forest root and message to its output. The review added an independent
probe with **162 rejecting malicious-advice cases**, plus honest and valid
reordering controls. All behaved as expected.

An integration gap identified during review was fixed before publication: the
benchmark receiver originally accepted only an opaque expected output digest.
It now takes public records, recomputes the output, checks that the declared
count equals the number of records, and checks the expected ELF hash and
statement hash. The runtime proof-consumer controls were subsequently completed
against saved one-, two- and seven-signature proofs. The independent review's
**46 saved-proof consumer controls all passed**, including changed forest roots,
seeds and messages with freshly recomputed public outputs. This is separate
evidence from the interpreter controls.

## Scope and provenance

- Backend: official `leanEthereum/leanVM`, `riscv-exploration`, commit
  `06e5c9cd6981103786f9d0a17324241b559a50d3`.
- Vendor patch state at review: clean.
- Guest: `risc-v/fors/guest/src/{lib,main}.rs`; host fixture and receiver helper:
  `risc-v/fors/host/src/lib.rs`; consumer: `risc-v/bench/src/main.rs`.
- Guest target: `riscv64im-unknown-none-elf`, release, optimization level 3,
  LTO, one codegen unit, aborting panics; nightly `2026-10-03`.
- Guest ELF SHA-256:
  `64480a3bf424f97578f6477a7a4045c2452853a0801f45fc191648eb253e36da`.
- Compiler and implementation hashes are in `../fors/build-manifest.json`.
  The independent review's source hashes and raw controls are in
  `fors-probe/source-hashes.json`, `fors-probe/results.json`, and
  `fors-probe/python-oracle.json`, and `fors-probe/receipt-controls.json`.
  Regenerate source hashes after any subsequent runner edit; the guest hash must
  remain equal or the guest must be reviewed and tested again.
- No deployed contract, consensus client or wallet authorization policy was
  supplied. The consumer is a local benchmark CLI.

## Intended statement and attacker controls

For an approved guest ELF and the independently intended ordered list of public
records, the proof states that there exists one valid FORS witness for each
record. A record is `(seed[32], forest_root[32], message[32])`. The fixed scheme
has `n=32`, `k=16`, `a=8`, Ethereum Keccak-256, and the domains and addresses
documented in the guest README.

The prover controls all advice, including the count, public records, secret
openings, and authentication siblings. None of their host-side verification
results are used as a guest assertion. The receiver controls the approved ELF,
the intended public records, and the independently trusted statement identity.
The guest commits its profile, count and every record. Witnesses contain no
unchecked intermediate hash or host-computed acceptance bit.

## Checked paths

1. **Representation and bounds.** `Header` and `Signature` are fixed arrays of
   `u64`; every bit pattern is valid and there is no struct padding, pointer,
   enum or boolean reinterpreted from advice. SDK `read` uses checked slice
   bounds. The guest requires `0 < count <= 445` before iterating; there is no
   narrowing cast of an unchecked count. The fixed 2 MiB advice and 1 MiB RAM
   maps are part of the approved ELF/program identity.
2. **Message-derived indices.** All 16 eight-bit indices are derived inside the
   guest from Keccak over the `MSG` domain, seed, root and entire 32-byte message.
   Each index is naturally in `[0,255]` and is shifted at every tree level.
3. **Leaf and node authentication.** Each secret opening is hashed with its
   seed, tree and leaf index. Every sibling is used exactly once. The guest
   chooses left/right order from the current index and hashes the parent with
   the tree, height and parent index. All 16 resulting roots are compressed in
   their specified order and compared with the public forest root.
4. **Domains and hash semantics.** `LEAF`, `NODE`, `ROOT` and `MSG` have distinct
   fixed 16-byte encodings including the parameter tuple. Addresses are
   `tree_LE32 || height_LE32 || index_LE64`. All words are interpreted as
   little-endian bytes. The SDK function is Ethereum Keccak-256, including its
   `0x01` padding, rather than SHA3-256. Its hash input lengths are fixed from
   arrays; no prover length can omit bytes.
5. **Public statement.** Guest and native public-only helper commit the same
   profile, count and ordered full records through SDK `PublicValues`. The
   final consumer reconstructs FORS headers from exact-length hex fields and
   invokes `fors_host::expected_output`; it rejects a mismatching cached
   `expected_output` or count. The statement and ELF pins must come from the
   receiver's application, never merely from the sender's accompanying files.
6. **Complete outer verification.** The common consumer calls
   `Proof::from_bytes` and full `Program::verify`. At the pinned backend,
   `Program::verify` calls both `verify_core` and `check_deferred`
   (`crates/leanvm_core/src/cpu/program.rs:363`). It does not discard the
   fixed-polynomial obligations returned by the core verifier.

## Reproduced controls

Commands, from the project root:

```sh
CARGO_HOME="$PWD/.cache/aerie-cargo" CARGO_TARGET_DIR="$PWD/.cache/aerie-wrapper-host-target" \
  cargo +stable test --manifest-path risc-v/fors/host/Cargo.toml --release --locked --offline
CARGO_HOME="$PWD/.cache/aerie-cargo" CARGO_TARGET_DIR="$PWD/.cache/aerie-wrapper-host-target" \
  cargo +stable run --manifest-path risc-v/reviews/fors-probe/Cargo.toml --release --locked --offline
.venv/bin/python risc-v/fors/tests/cross_check.py risc-v/fors/tests/rust-fixtures.json
```

The cache names are inherited build-cache locations only; no Aerie workload was
executed. The system `python3` lacks PyCryptodome, so the oracle requires the
project virtual environment as shown.

Predetermined positive controls:

- An honest one-record execution returns the independently prepared public
  output; a two-record execution also returns its expected output.
- Reversing two complete valid records succeeds and changes the expected
  output. This tests ordered claim binding without confusing valid reordering
  with a signature forgery.
- Unread trailing private advice has no effect on the statement. It is not
  interpreted as an additional verified signature.
- The independent Python/PyCryptodome byte oracle matches all bytes of two
  complete Rust fixtures, including every authentication sibling, and accepts
  their paths. It rejects a changed path and substitution of the leaf domain
  for the node domain.

Predetermined negative controls, all run against the unchanged optimized ELF:

- 144 mutations cover every tree and all nine opening positions (the secret
  plus eight siblings), varying the affected 64-bit limb and bit position.
- Twelve more mutations flip a high bit in every public header word.
- Counts zero, two with only one supplied record, 446 and `u64::MAX` reject.
- Swapping two trees' complete openings rejects.
- Removing the last 32-byte sibling rejects, despite unused advice memory
  being initially zero.

All **162** negative executions trapped. The implementation's own three release
test methods also passed. These controls establish relevant guest behavior;
they do not by themselves establish malicious-prover soundness of the STARK.

## Final saved-proof consumer verification

After the fresh proving campaign, the reviewer independently ran:

```sh
python3 risc-v/reviews/fors-probe/receipt_controls.py
python3 risc-v/reviews/fors-probe/provenance.py
```

This ran **46 controls** across the actual saved proofs for one, two and seven
signatures. Each invocation copied only a public statement and one proof to a
fresh temporary directory, and ran the final compiled consumer from there. No
original signatures, authentication paths, leaf proofs or private advice were
provided. The consumer uses an embedded trusted ELF and independently expected
ELF pin. The reviewer independently recomputed the public output using Python's
BLAKE2s from the fixed profile, count and exact public record bytes.

- All three honest saved proofs verified.
- Changing the public seed, forest root or message, recomputing the expected
  output and supplying a fresh trusted statement hash, failed inside STARK
  verification. The error reaches the reduction's zerocheck rather than an
  unchanged cached-output or statement-hash check.
- Reordering two or seven records, or substituting a duplicate for one of those
  records, likewise failed against the original proof after recomputation.
- Invalid public hex (including non-ASCII input) and wrong 32-byte lengths
  rejected cleanly. Incorrect counts and cached output values rejected.
- Corrupted, truncated and extended proof encodings rejected. A wrong ELF pin
  rejected before attempting acceptance under an unintended program.

The final reviewed consumer executable SHA-256 is
`afd2c1625c2e21b060a9a2005cb74bf5350a4c1262e9a27f9e12491df1018783`.
The raw campaign's proving executable hash is
`3ebadbc341e04bdf96201af2a247234f0c5dc210a454337725595a1b7cc72629`.
The subsequent runner changes added formatting, strict public-hex handling and
two equivalent Clippy style changes (`is_multiple_of` and fixed-size `as_chunks`).
Both the common 87-control suite and this review's 46-control suite were rerun
successfully against the final executable above.
The FORS guest ELF hash remained unchanged. Full source, proof, statement,
consumer-script and result hashes are in `fors-probe/source-hashes.json`.

The common campaign's `../results/consumer-controls.json` also records 87
passing public-only controls across all three schemes, with 29 of those for
FORS. The reviewer inspected its script and outcomes; the 46-control rerun
above is independently implemented and adds public-root, malformed-encoding and
substitution coverage.

The measured seven-signature proof fully verifies; the next eight-signature
attempt returns `ProveError::TooLong` from both measurement and actual proving.
See `../results/direct/fors-{7,8}.json`. This is a capacity boundary for this
guest, input schedule and backend, not a cryptographic soundness finding.

## Boundaries and remaining checks

- FORS here is a **few-time component**, not complete SLH-DSA and not an
  unlimited-use wallet signature. This review does not establish a security
  level or safe number of signatures per key for these parameters.
- Fixtures use fresh keys per record and public deterministic test seeds.
  They must not become production signing keys. The guest permits repeated
  public records; deduplication and signing-key reuse policies are application
  responsibilities.
- The 32-byte message must be derived from the intended transaction and account
  policy by the receiver. The guest does not enforce chain ID, nonce, expiry,
  spending policy or replay prevention independently of that digest.
- Plain leanVM proofs do not provide a zero-knowledge guarantee. Omitting
  original signature files from a receipt is not a privacy proof.
- This scoped review does not audit the VM instruction circuits, compiler,
  transcript, memory bus, WHIR, hashes, proof decoder or cryptographic security
  of the FORS construction as a whole. Their pinned implementations are assumed.
- The saved-proof checks above establish application statement binding for the
  exercised paths and counts. They do not exhaust all malformed proofs or
  replace an audit of the pinned backend.
