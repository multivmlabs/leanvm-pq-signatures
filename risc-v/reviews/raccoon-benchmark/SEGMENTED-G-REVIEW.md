# Segmented Raccoon-G: composition review

Status: specification and current guest/consumer source reviewed, 2026-11-09.
The final uniform guest and accepted complete pilot passed independent actual-ELF,
public-binding and full receiver controls. The final user-reduced multi-count evidence now passes the separate final review.
This document does not certify the underlying STARK or signature parameters.

## Intended statement

For each caller-authorized ordered `(public_key,message)` pair, the receipt must
establish the entire original strict Raccoon-G verification relation. It may split
the nine matrix rows across proofs. A row proof alone establishes only a partial
claim and must not be counted as a verified signature.

The prover controls the signature, reconstructed commitment vector `w`, row
witnesses, auxiliary binding values and received proof bytes. The caller controls
the intended original pairs and approved program, backend, tree shape and
decomposition policy. The caller does not have to trust or pin sender-selected
witness bindings as application authorization.

## Required guest invariants

Each two-row part guest must do all of the following with ordinary constrained execution:

1. Reject part indices outside zero through four and derive the fixed row pairs
   `(0,1),(2,3),(4,5),(6,7),(8,8)` internally.
2. Enforce the full original canonical public-key/signature encoding and exact
   norm bound. Enforce canonical `w` coefficients below 2048, including rows
   other than the selected arithmetic row.
3. Compute the full original public-key hash, BUFF message hash, challenge and
   `HashVec(mu,whole_w)`. Check the latter equals the signature challenge hash.
4. Expand both selected matrix rows from the original seed with the original
   SHAKE128 sampler. Check each entire `A*z-c*t_scaled` row and rounded-plus-hint
   equality against that row of the supplied `w`. Both rows share global checks
   and response transforms, but both equations execute, including row eight
   twice in the final part.
5. Compute the witness binding from the exact fixed byte representation of the
   **whole signature and whole `w`**, not a selected row or a host digest.
6. Commit the original key/message, exact public part and both derived row indices and all binding bytes
   under the approved row domain. No limb truncation or alternate residue
   encoding may erase part of those values.

The proposed fixed codec is suitable: 20768 signature bytes followed by 4608
canonical LE16 `w` bytes, row-major then coefficient-major. Explicit length words
and separate 32-byte domains bind the format and purpose. All quantities are
whole words, with no unspecified transport padding. Both proposed witness domains
and the proposed public-row domain are exactly 32 bytes.

The public key and message need not be repeated inside the witness binding if
every row's public statement binds the same caller-authorized pair. Omitting
them from **both** bindings would be invalid. This property must be checked in
the production consumer, not inferred from an honest fixture helper.

## Required receiver invariants

For each original pair at index `i`, the receiver must construct outputs for all
five canonical parts itself, covering all nine distinct row indices and use exactly one 64-byte `D_i` in every one of them.
It must not accept a sender-provided list of row outputs or let a sender omit,
repeat or relabel a row. Original pair count and order are checked against the
caller's intended records. Different original pairs may share a binding value;
that alone does not indicate an invalid signature, but each pair still needs all
nine row equations.

The expected row list is formed before native-tree padding. Any repeated padding
slots follow complete original coverage and are not extra signatures or a
substitute for a missing row. The receiver must then call **full** `Tree::verify`,
including the final dense-polynomial and matrix claim settlement. A root's core
STARK alone is insufficient.

The receipt must carry exactly `N` bindings, retain all 64 bytes of each, and
reject inconsistent lengths, counts, unknown versions and trailing data. The
original records and approved program/policy are caller-trusted; `D` is an
untrusted existential auxiliary value whose acceptance is authenticated by the
root proof's independently reconstructed public outputs. Reading a hash supplied
alongside a received receipt is not application authorization.

## Composition assumptions

The normal commit-and-prove argument is applicable: row proofs authenticate
openings of one common canonical witness binding, and the conjunction of all
nine row predicates yields the original full verifier. A mixed-witness attack
requires different canonical `(signature,w)` witnesses with the same accepted
binding, or a break of the row/public/root proof binding.

This is a **computational composition argument**, not a claim that a finite hash
is mathematically injective. A reduction from successful row proofs to an
explicit hash collision additionally relies on the row proof system's applicable
knowledge/extraction property. Plain language that “soundness alone means the
witnesses must be identical” would omit that assumption. This benchmark review
does not establish a new extraction theorem for the experimental backend.

Concatenating two domain-separated BLAKE2s-256 results is an explicit 64-byte
binding construction. Basic binding relies on the relevant collision-resistance
assumptions; claiming a full 512-bit output security level would require further
joint-hash analysis. It is not standardized BLAKE2b-512. In addition, native leaf
and tree public commitments remain 256-bit BLAKE2s, so the construction does not
upgrade the backend's end-to-end security. None of these observations justifies
loosening the signature norm or increasing the commitment cap.

## Required controls and accounting

Before reporting accepted complete signatures, test all nine honest rows and
reject invalid row indices, changed key/message, changed challenge/response/hint,
noncanonical `w`, exact norm-bound failures, and changes in an unselected `w`
row. A low-bit public-key mutation that preserves rounded `t` must still reject
through the full-key hash. Witness changes must alter the complete binding.

The complete receiver needs controls for missing, duplicated, reordered and wrong
row claims; mismatched bindings for one original signature; changed bindings with
recomputed public outputs; altered original pairs; incorrect counts, code pins
and shapes; malformed/truncated/trailing receipts; and corrupted root proofs.
Recommitted claim changes receive fresh caller statement pins, preventing stale
hash checks from masking a binding omission.

Report `N` original signatures, `5*N` part leaves, `9*N` distinct row equations
and `10*N` actual row computations separately. Charge every fresh part leaf and
merge and disclose padding. Include the `64*N` binding bytes
and receipt framing in aggregate size. Public-claim derivation now hashes many
row outputs and must remain separately visible under the same timing convention
used in the existing figures. No direct-batch proof point may be invented from a
partial-row proof; the original whole-guest failures remain preserved.

Full paper conformance and parameter-security provenance remain pending. This
decomposition preserves the documented executable strict profile; it does not
resolve those separate questions.

## Current implementation source review

The guest delegates canonical parsing and the exact full norm to the unchanged
original `canonical_and_norm`. It computes `tr`, `mu` and the original seven-byte
HashVec encoding from all 2304 canonical W coefficients. All nine z NTTs execute
before either selected row equation. Reconstruction matches the original full
verifier's seed expansion, rounded/scaled t, Montgomery products, inverse NTT,
38-bit rounding and hint addition. No host accept bit, pre-expanded matrix or
trusted digest enters this predicate. D is computed after these checks inside the
VM through the SDK BLAKE2s instruction, over every signature and W byte.

The consumer's caller-authorized Statement contains original public records,
program identity and fixed shape/policy, with no D or cached output list. Its
`RGSTK001` receipt carries exactly N untrusted 64-byte D values. It derives the
five part outputs per pair itself, then repeats only the final complete claim
for power-of-two padding. `verify_full` decodes the exact-length envelope,
constructs this complete expected list, decodes the native TreeProof and invokes
full `Tree::verify`. The CLI checks independently provided statement and ELF
pins. Full Tree verification includes terminal dense-polynomial and matrix
claim settlement in the pinned backend, as checked separately in this audit.

The complete receipt framing costs `60+64*N` bytes beyond the native core root,
not just `64*N`. Preparation timing covers full host W reconstruction, canonical
checks/challenge consistency, both D hashes and all five advice packings once per
signature on every new sample. The prover creates every real leaf fresh, reuses
only final leaves as explicit padding and creates every merge fresh. All five
real part proofs are independently verified before aggregation. These source
checks do not establish successful proof production or measured performance.

The independent `segmented_binding.py` recomputes D and part commitments using
Python hashlib and raw byte codecs. It independently enumerates part coverage,
receipt framing, native padding and the protocol-19 tree public digest. The
independent 14-vector advice set additionally changes the second selected row
of parts zero through three, so a verifier accidentally checking only the first
row would be caught. Actual-ELF execution on frozen guest
`a9ab1a596f88a737200f96bd045ed4d8176d3f9bcf8eaa6ad06a85ffd9ebfddc`
passes all 14 controls: six accepts match the independently computed output bytes
and eight malformed/selected-row controls reject. The six accepts comprise all
five honest parts and one deliberately partial claim whose changed row-eight
hint must fail the required final part. All 44 manifest source hashes match.
See `segmented-elf-validation.json` for identities and exact controls. This
interpreter correctness check produces no STARK and has no performance claim.


Frozen consumer evidence: source `runner/src/main.rs` SHA256
`41fbd114ee0ae854263ecb9793ba2de70371146471f8796be4f6c1ef0c6875f3`,
runner binary SHA256
`6ce0210981e547a70355332b882221a910a9ef0d72942b96b17d1f217e2caedc`,
embedded guest manifest SHA256
`4d5dcc0295e16687dbfafc6bb82438629d0feda6efc3677fd1490a49547d59f5`.
The runner's three native codec/public-binding tests and warnings-denied Clippy
pass, and every listed runner source hash matches. Full public-only receipt
controls still await a production root. Both prepared core verification and
prepared complete receipt verification are explicitly reported; only the latter
includes untrusted D decoding and all 5N output commitment derivations.


## Corpus-wide trace-shape issue, before proof production

The a9ab candidate passes the signature checks and every measured part fits the
witness cap. The all-100-signature planning pass nevertheless found that signature
index three, part four executes 525147 SD rows, crossing the 524288 padding
boundary while most parts stay below it. Its native leaf shape therefore differs.
This is not an invalid signature, a commitment-cap failure or a successful tree
benchmark. The candidate, source manifest and nonuniform planning evidence are
preserved. It must not be used for a purported uniform whole-corpus tree.

A new candidate adds fixed bounded writes to disjoint scratch storage after the
verification predicate so every part has the same higher SD table height. These
instructions are ordinary proved execution and must be charged as trace-shape
normalization. Exact memory-code review and fresh artifact controls are pending.
The independent advice corpus now includes the original index-three part-four
case, whose W is independently reconstructed by the pinned authors' Python
arithmetic. No signatures are discarded or replaced to select a convenient shape.


## Uniform-candidate static review

The preserved nonuniform source archive was independently diffed against the new
candidate. The only guest logic changes add constant `TRACE_PADDING_STORES=32768`
and call a non-inlined normalization loop after verification and all public
commits. The loop writes counter values to one naturally aligned, live local
u64 with volatile writes. Its bound is constant, it has no reads and does not
commit or alias the key, witness or public output. No signature predicate or
hash codec changes. The root process confirms that this ordinary execution is
charged. All 45 new manifest source hashes match.

Uniform guest SHA256:
`5c48b8f39b14521773493692034fa601a9df89992552870addd68416cc926eac`.
Independent execution on the 15-vector corpus now passes: seven accepted
outputs match the independent Python oracle exactly, and all eight expected
rejects trap. This includes the original high-SD index-three part-four case.
See `segmented-uniform-elf-validation.json`. The owner's 35 actual-ELF controls and Clippy pass on the
new artifact; those results are complementary to, not substitutes for, our
independent saved controls.


## Accepted complete pilot and independent receiver controls

The final uniform guest produced an actual complete N=1 pilot receipt, with all
five real part proofs and all seven merges for eight padded slots freshly
created. The saved-evidence audit independently reconstructs the complete public
claim and protocol-19 root digest, checks every leaf/merge proof file hash,
coverage/depth, exact timing sums and receipt sizes. The received D64 exactly
matches the previous independent Python full-witness commitment. Complete size
is 266115 bytes: 265991-byte core plus 124-byte envelope and D. Pilot proving
work is 48.226641 seconds including preparation. This one pipeline is a pilot,
not a point in the requested three-run curves.

The isolated public-only production consumer verifies the entire receipt and
settles all final claims. All 46 independent adversarial receiver controls pass,
including every D limb, changed D and original pairs with consistently updated
public-root hash headers, new caller statement pins, policy/code/count/shape
changes, malformed framing, truncated/trailing data and inner STARK corruption.
The unchanged production consumer's eleven additional controls reject missing,
duplicated and reordered part obligations. The trusted caller statement excludes
D and sender-provided output/order lists. Receiver test directories contain only
the original public statement and one complete root receipt as inputs.

Current native runner SHA256 is
`74b2b0125f7e04d6cb390eecb1582c3f5a18fcd5b9da4d419e4eba2b24c766a8`.
See `segmented-pilot-evidence-validation.json` and
`segmented-pilot-consumer-controls.json`. No missing signature predicate,
part-coverage check, public binding or terminal native-tree obligation was found
in this bounded review. This is not a formal proof or a whole-backend audit;
composition knowledge/extraction assumptions and paper-conformance limitations
remain as stated above. Final N10/30/70 three-run evidence and the user-retained single N100 pipeline
now pass `MATRIX-REVIEW.md`; the two remaining N100 producer repetitions were
stopped by the user and are not claimed as measured.


Final scope: the complete user-reduced G dataset has three fresh producer
pipelines each for N10, N30 and N70, plus one N100 pipeline. All ten final G
roots pass independent saved-file/public-binding checks, and final N100
public-only controls pass all 62 independent mutations plus eleven production
coverage controls. Full source/ELF/native identities and stop archives match.
The actual G100 result and separate G70-based estimate are explicitly labelled;
no missing repetitions are invented. See `FINAL-MATRIX-VALIDATION.json`.
