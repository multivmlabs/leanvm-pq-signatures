# leanISA sumcheck-reduction integration review

Reviewed 6 November 2026. Source inspection, independent protocol vectors,
actual DSL execution controls and an actual two-level malicious-producer proof
control have passed. Eighteen isolated production CLI controls and independent
public binding checks of all twelve measured reduced FORS trees also passed.

This is a scoped integration review. It does not establish full soundness of
leanVM, its compiler, Keccak argument, PCS or the new Fiat-Shamir composition.

## Scope and statement

The backend remains unmodified leanVM
`575df819d9c857f38068cecf7b1640e0ce4bfb29`, with its specialised Keccak circuit.
The implementation is isolated in `leanISA/reduction`; earlier wrappers and
benchmark reports remain separate.

A received root should establish the approved leaf relation for every intended
public key/message pair. The receiver must authenticate its intended public
records and approved leaf program, rebuild the bounded wrapper program family,
verify the root proof and settle each final reduced claim against the actual
trusted bytecode table. The producer controls witness streams, child proofs,
inherited records, sumcheck messages and terminal hints.

## Reviewed joins

- Fresh point/value claims are copied from each actual in-guest `verify_sub`
  output. They are not accepted as a separate unauthenticated claim list.
- A child accumulator record reconstructs the full child public input before
  that public input is supplied to `verify_sub`.
- Application digests combine only child application digests. Full public
  inputs separately commit those digests and the accumulator records. Thus the
  root's application digest can be derived from intended leaf records without
  receiving all intermediate records.
- Program families and dimensions follow a fixed, bottom-up chain. A wrapper
  refers to already-built descendant code, avoiding a self-hash dependency.
  Each new level reduces fresh child-bytecode claims and all inherited claims;
  it does not silently omit an inherited family.
- The initial reduction transcript binds the program identity, context,
  dimension, claim count and every full-width input point/value. Each round
  binds its messages before deriving the round challenge.
- Characteristic-two degree-two rounds derive `c1 = target + c2`. The terminal
  identity multiplies by the combined eq weight and never divides by it.
- Canonical digest halves and full 192-bit scalar packing are constrained in
  the guest. Third limbs are preserved in both transcript and public-state
  encodings.
- A new point and value enter the wrapper's public input. They remain claims,
  not trusted host results. The production receipt verifier checks the root
  STARK and every final claim through cached `verifier::Bytecode::evaluate`.
- The CLI authenticates both the public statement hash and approved leaf
  program hash from caller-supplied expectations. It independently hashes every
  intended FORS public key/message pair and derives the padded semantic tree.

The native witness generator's checked-child and true-claim prechecks are
admission conveniences. They are not used as security arguments in this review.

## Independent primitive evidence

`oracle.py` independently implements GF(2^64) polynomial multiplication modulo
`x^64+x^4+x^3+x+1` and the cubic extension modulo `y^3+y+1`, plus byte-level
Ethereum Keccak-256 transcript encodings. Twelve small-table vectors cover
dimensions one through four and one through three claims. Eighty-four altered
reference cases reject. These are reference checks, not STARK verification.

The native helper matches those vectors exactly: initial digest, all round
messages, every derived point coordinate and the terminal value. The separate
guest controls execute the actual compiler/interpreter with the trusted small
table evaluated inside the guest. Twenty-four positive and sixty-nine negative
outcomes passed. The negatives include third-limb mutations in original claims,
round messages and terminal values, plus changed round order. They do not
depend on asserting an expected precomputed output point.

Receipts: [`oracle-vectors.json`](oracle-vectors.json) and
[`../guest/controls/summary.json`](../guest/controls/summary.json).

## Actual two-level proof control

The ignored Rust test in [`proof_controls.rs`](proof_controls.rs) produced six
real STARKs: an honest leaf and two wrappers, followed by a deliberately
inconsistent leaf and two wrappers. Both chains use the same approved wrapper
programs and the unchanged production receipt verifier.

The malicious producer changes a cloned leaf's execution bytecode while
retaining its cached approved Fiat-Shamir seed. It executes a three-step halt
instead of the approved leaf relation. The full native child verifier rejects
that proof. Test-only unchecked replay supplies the partial recursive core's
advice, and the producer constructs sumchecks using the wrong bytecode table
while retaining the approved program identity.

Both resulting wrapper executions have no unconstrained reads. Both actual
wrapper STARKs verify under the approved wrapper code and their declared public
inputs. A false claim on the approved leaf bytecode survives into the second
wrapper, exactly as a deferred claim should until it is settled. The unchanged
complete receiver then rejects with **`terminal family 0 is false`**. The honest
two-level root accepts. Strict receipt decoding also rejects appended bytes.

This discriminates genuine guest reduction and final anchoring from relying
solely on the honest witness generator. It is a generic recursion control using
a small approved leaf relation, not a demonstrated FORS signature forgery.

Receipt: [`proof-controls/two-level-malicious.json`](proof-controls/two-level-malicious.json).
Saved honest and dishonest root envelopes are alongside that receipt. The
run log is [`proof-controls-run.log`](proof-controls-run.log).

## Production FORS receipts

The selected approved five-signature FORS guest hash is
`9f26663ec851871efc147c210850edbf0f2b4b49a43bc22684a2e53df878a14b`.
It exactly matches the archived five-signature FORS guest, confirming that the
signature relation and specialised Keccak guest were retained. All twelve
measured samples have actual Keccak opcodes in their leaf executions.

`consumer_controls.py` independently hashes every intended 64-byte FORS public
key and 32-byte message into each leaf commitment, reconstructs the complete
tagged binary semantic tree and compares it with the semantic digest decoded
from the actual root envelope. It ran eighteen actual receiver outcomes in
temporary directories containing only a public statement and one root proof.
The honest 100-signature root accepted. Recommitted key, message, record-order
and count changes rejected, as did duplicate pairs, wrong program/pins/backend,
changed root metadata, third-limb changes in accumulator points and values,
damaged proof bytes, appended bytes and truncation.

The frozen receiver SHA-256 was
`1d683e440929570d459dca6747f18b74760fa94ee385d7adb0261129fbba38b5`.
Receipt: [`consumer-100-controls.json`](consumer-100-controls.json).

The independent [matrix check](matrix-binding-checks.json) repeats semantic
binding reconstruction for all twelve selected samples at 10, 30, 70 and 100
signatures. Root bytes/hashes, public statement pins, unchanged approved leaf
identity, required terminal-family counts, padded shape and complete native
receiver flags match. The sum of actual leaf calls and every merge's native
preparation plus wrapper STARK calls matches the reported total proving work.

At 100 signatures, this binary tree has 62 edges and five terminal program
families. The older article's fan-in-four tree has 26 edges. Their timing
comparison therefore changes topology as well as the reduction protocol.

## Limits

No accepting invalid-statement path was found in the reviewed joins or controls.
One final evaluation remains per distinct descendant program family. In this
bounded implementation that count grows with wrapper depth, rather than being
an unconditional constant. The receiver still needs approved code and intended
public records; no signature advice or child proof files should be necessary.

The evidence does not cover arbitrary malicious AIR witnesses, complete
Fiat-Shamir security proofs, production denial-of-service budgets, or Ethereum
transaction/account-policy integration. Plain benchmark proofs are not zero
knowledge, and publicly reproducible fixture keys are not production keys.
