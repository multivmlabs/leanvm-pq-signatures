# Raccoon-G fixture and oracle record

These are correctness controls, not benchmark results. The generator is
[`../generate_fixtures.py`](../generate_fixtures.py), using authors' commit
`461a5ed9b6d57e3bf8c381be3bb79325ab21d906` without changes. The local environment
uses Python 3.9.6, PyCryptodome 3.23.0 and mpmath 1.3.0. The reference Gaussian
sampler retains its 256-bit mpmath precision. The generator explicitly checks
mpmath 1.3.0 and the reference revision and cleanliness.

## Ordinary records

`host/testdata/record-{0,1,2}.json` contains three independent public-key,
32-byte-message and signature records. Index-specific SHAKE domains derive the
key-generation entropy and signing coins; a separate SHA-256 domain derives
the message. These are public, reproducible test keys.

Each signature uses exactly one fixed 32-byte randomness draw from the authors'
signer. There is no selection of favourable signatures and no retry. A failure
of either the reference predicate or the strict integer profile causes fixture
generation to fail explicitly. The ordinary record function does not read the
synthetic norm, arithmetic or HD controls.

`oracle-record-{0,1,2}.json` stores source identity, index, entropy, signing coins,
hashes and reconstructed verifier intermediates. These include the full-key hash,
`mu`, challenge polynomial, first matrix polynomial, matrix hash, rounded public
vector, reconstructed commitment and exact squared norm. Python's `hashlib`
independently checks the byte hashes; the pinned source supplies its lattice
arithmetic. The Rust tests additionally compare arithmetic with schoolbook
negacyclic convolution.

## HD and synthetic controls

`host/testdata/hd-controls.json` covers a master node, two non-hardened levels, a
hardened child and a hardened child after a non-hardened step. Public-only and
private derivation agree on the child public key and chain code. The executable
hardened HMAC input includes the stored derivation seed, as documented in
`SPEC.md`. Signatures from the master and derived keys are checked by the actual
RISC-V guest. This establishes tested agreement with the authors' code, not a
STARK proving derivation-path membership.

`host/testdata/norm-controls.json` contains seven synthetic, challenge-consistent
controls. A four-square decomposition constructs response norms exactly at the
chosen bound and one integer unit above it, including both signs. The challenge
equation remains satisfied, so rejection cannot be attributed merely to a
corrupted challenge. These inputs use algebraic zero public keys to isolate the
norm check and are explicitly excluded from benchmark fixtures.

`oracle-norm.json` records the directed 512-bit interval calculation and the
separate binary64 acceptance boundary. `norm-bound-certificate.json` supplies an
additional exact rational enclosure. The strict profile accepts the integer
norm bound and rejects the next integer; the upstream floating-point predicate
accepts the latter. This difference is deliberate and documented.

`oracle-arithmetic.json` contains five ring-product vectors, checked against a
naive negacyclic convolution independently of the source NTT schedule. It covers
zero, identity, wraparound, maximum residues and dense deterministic inputs.

The recorded fixtures support implementation correctness. They do not certify
the paper's parameters, Gaussian-security proof, derivation bound or leanVM's
proof-system soundness. No STARK or performance/capacity experiment was run to
produce this evidence.
