# Final independent Raccoon benchmark review

Status: **all 22 complete pipelines required by the user's final sampling policy
pass**. No further proving was run after the user stopped the remaining N=100
repetitions. This is a bounded implementation and evidence review, not a formal
proof or an audit of the whole experimental backend.

## Final sampling and results

The user reduced the original 24-pipeline plan after the first complete G N=100
pipeline had already finished. All completed results are retained; the remaining
G N=100 repetitions are not represented as measured data.

| Original signatures | Standard fresh complete pipelines | G fresh complete pipelines |
|---:|---:|---:|
| 10 | 3, checked | 3, checked |
| 30 | 3, checked | 3, checked |
| 70 | 3, checked | 3, checked |
| 100 | 3, checked | 1, checked and labelled single run |

Every accepted pipeline independently passed saved proof-file hashes, ordered
public commitments, canonical padding and depth, fresh real leaf/merge counts,
exact timer sums and complete receiver evidence. Standard trees have N real
leaves. G trees have 5N real parts, covering 9N distinct row equations using 10N
row computations. Both produce every merge fresh and repeat only the final
complete leaf for explicit power-of-two padding. Repetition of deterministic
plain-proof hashes does not imply proof reuse; the reviewed source always calls
the prover for each real leaf and merge in each new sample directory.

The actual G N=100 sample has 500 fresh parts and 511 merges. Its complete
receipt is 273403 bytes, including 6460 auxiliary/framing bytes. Proving work is
4906.049766408 seconds, including fresh native W/binding/advice preparation.
This is one measured producer pipeline. Its receiver's three prepared
verification calls are not three independent producer pipelines.

See `FINAL-MATRIX-VALIDATION.json`, all `matrix/*final-evidence.json`, and the
user's recorded scope in `risc-v/results/raccoon-full-matrix/sampling-policy.json`.

## Verification and public binding

The standard optimized guest retains the original 64-bit Montgomery NTT. Its
bounded bulk decoder, alignment helpers and register Keccak kernel passed the
independent source and actual-executable checks in
`STANDARD-OPTIMIZED-REVIEW.md`. It does not use the discarded CRT32 arithmetic.
All 64 main-runtime capacity prefixes were checked: one accepts, 2 through 64
return `TooLong`. Actual direct prover attempts for counts 2 through 30 also
return `TooLong`, with no accepted proof bytes. Refusal latency is not plotted as
proof performance. All 100 singleton leaf shapes match, and all 100 public
outputs were independently recomputed from complete key/message bytes.

The G uniform guest enforces full canonical encoding, the complete strict norm,
full-key BUFF/message hashing and the full challenge relation in every part.
It computes both selected matrix-row equations and binds the complete canonical
signature and W inside the VM. Its five fixed parts cover every original row.
The receiver takes one untrusted D64 per original pair and derives all five
expected outputs itself, rather than accepting a sender's output or part list.
The fixed 32768 volatile writes after checking and public commits are charged
trace-shape normalization. The final 500-part corpus plan fits the unchanged
witness cap and has one uniform layout. See `SEGMENTED-G-REVIEW.md`.

For all 22 accepted roots, independent Python byte codecs reconstruct every
expected leaf/part commitment, padding slot and protocol-19 public root digest.
Every statement's key/message list matches the canonical corpus prefix for its
count. The actual native receivers call complete `Tree::verify`, including all
terminal dense-polynomial and matrix claim settlement. They start in separate
public-only directories with the intended statement and one root receipt;
signature witnesses and child proofs are not receiver inputs.

Final active controls on the N=100 roots pass: thirty independent standard-tree
mutations and sixty-two independent G-receipt mutations, plus eleven G production
coverage controls. They cover first and last original pairs, every D limb,
changed claims and D with coherently updated root headers, fresh caller statement
pins, missing/duplicated/reordered part obligations, policy/code/count/shape
changes, malformed framing, truncation, trailers and corrupted inner STARK data.
These controls run verification only, without proving or VM workloads.

## Timing and memory definitions

Main cohorts use eight workers, `log_inverse_rate=1`, plain proofs and the same
explicit Jemalloc policy:
`_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0`.
The standard direct N=1 point uses one warmup and three timed proof calls. Every
tree sample is a new pipeline. Key generation/signing are fixture preparation;
G's fresh W reconstruction, binding and advice packing are charged prover work.

The standard prepared verifier timer measures complete native tree verification
with already derived public outputs; public derivation is recorded separately.
G records both that core scope and full receipt verification, which includes
untrusted binding decoding and all 5N output commitments. These raw timer fields
must not be compared as identical scopes or counted twice in a combined metric.

Memory is process-lifetime peak RSS from `getrusage(RUSAGE_SELF).ru_maxrss`.
On macOS it is bytes and reflects resident memory, not physical footprint or a
Wasm linear-memory allocation. Standard main tree processes peak at 18.149 to
18.938 GiB; G main trees peak at 17.987 to 18.866 GiB. The earlier cold pilot and
old allocator cohort remain separate. See `RSS-DEFINITION.md`.

## Stops, archival and operational guard changes

Seventeen accepted pipelines used the sampled 19-GiB guard; five accepted
pipelines used 20 GiB. Rate, workers, allocator policy, signatures, guest code,
native binaries, security parameters and the `2^28` witness cap never changed.
The guards sample current RSS approximately every 0.25 seconds plus polling
overhead and are operational stop policies, not hard allocation bounds.

The old 19-GiB guard stopped G N=70 sample two after 71 saved parts, with no
merges or complete root. All 77 archived file hashes match their original
manifest and mapping. Its 627.917-second aborted duration is not an accepted
benchmark, and its triggering RSS sample/final high-water mark are unknown.
The replacement sample starts from zero and freshly proves all 350 parts and
511 merges. The seventeen earlier complete root and marker identities remain
unchanged. See `resource-stop-archive-validation.json`.

The user later stopped G N=100 sample one after seven saved parts, with no
merges/root; sample two never started. All twelve archived file hashes match.
This is a user stop, not a signature failure or backend capacity result. Both
stop archives, their manifests and logs remain intact. Neither interrupted
attempt supplies a plotted time or size, and no partial proof is reused.

## Separate G N=100 estimate

The explicit model uses only the three G N=70 component measurements:
`(leaf_prove_s + native_prepare_s) * (100/70) + merge_prove_s`.
Both counts use 512 padded slots and 511 merges, so the merge component stays
fixed. The model gives 78.299 minutes, with the three propagated inputs spanning
78.112 to 80.426 minutes. That range is not a confidence interval. Its size model
is `median(G70 core bytes) + 60 + 64*100 = 273275` bytes.

All basis report hashes, components, arithmetic, size accounting and labels pass
`G100-ESTIMATE-VALIDATION.json`. The already completed actual G N=100 run is 4.43%
slower and 128 bytes larger. The model excludes its values, but was calculated
after the actual result existed; this is a G70-based model comparison, not a
blinded prospective forecast. The model remains separate from measured rows and
does not replace the missing producer repetitions.

## Immutable provenance and limits of this review

All frozen source hashes, selected guest ELF hashes and native executable hashes
match both final cohort environments. Coordinator SHA256 remains
`c117ef5be9437638c5802f109362d4108b822ed3c8d4c97d16da950cae4ab09d`.
All 1277 old `leanISA` archive hashes match. The three source repositories are
clean at the expected revisions:

- Backend: `06e5c9cd6981103786f9d0a17324241b559a50d3`.
- Standard reference: `e789b4b72a2b7e8a2205df49c487736985fc8417`.
- G authors' code: `461a5ed9b6d57e3bf8c381be3bb79325ab21d906`.

Selected guest SHA256 values are
`e375033cde726b2e988db2c433bf8d83b8516252c5954c1e43cb6720f3b25eac`
for standard and
`5c48b8f39b14521773493692034fa601a9df89992552870addd68416cc926eac`
for uniform G. No missing signature predicate, canonical part coverage, public
binding or terminal native-tree check was found in the reviewed scope.

Standard follows the user-approved official C/Python interoperability profile,
with PDF discrepancies preserved. G proves the documented strict authors' PoC
profile; full-paper conformance and parameter-security provenance remain
unverified. The segmented composition has explicit witness-knowledge/extraction
and collision-resistance assumptions. D64 does not upgrade the backend's own
hash/security level. The receipts do not prove threshold signing or an HD
key-derivation path. Distinct public keys are a benchmark harness policy, not a
restriction of the signature scheme.
