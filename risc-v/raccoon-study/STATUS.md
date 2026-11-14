# Raccoon study

The user approved both complete experiment matrices on 2026-11-09: direct
batches, capacity checks and trees at 10, 30, 70 and 100 signatures, with three
fresh runs and full verification. The production record is
[`../results/raccoon-full-matrix/progress.json`](../results/raccoon-full-matrix/progress.json).
No additional approval is pending.

The user later stopped further N=100 repetitions and requested an estimate.
All 12 standard Raccoon trees and ten G trees are complete and fully verified.
G's 10/30/70 points each have three fresh pipelines; G100 has one complete run
that finished before the stop request. It is not labelled a three-run median.
The second G100 attempt was stopped after seven partial leaves and no root;
the third never started. The [user-stop archive](../results/raccoon-full-matrix/user-stops/20261110T110242Z/)
retains the partial work. All proving has stopped.

The separate [component estimate](../results/raccoon-full-matrix/g100-estimate.json)
uses three G70 runs, scaling leaf/preparation work from 350 to 500 parts while
holding the 511 merges fixed. It predicts about 78 minutes and 267 KiB. The
already completed G100 run measured 81.77 minutes and 267.00 KiB. The model was
not fitted to that single validation result. The [sampling policy](../results/raccoon-full-matrix/sampling-policy.json)
records the revised scope and plotting rules.

## Sources and scope

- Standard Raccoon-128-1 follows the official C/Python reference at
  `e789b4b72a2b7e8a2205df49c487736985fc8417`, with the NIST PDF's conflicting
  pseudocode documented in the [implementation review](../raccoon/review/SECURITY-REVIEW.md).
  The user selected reference and known-answer interoperability.
- Raccoon-G follows the ePrint 2026/380 authors' code at
  `461a5ed9b6d57e3bf8c381be3bb79325ab21d906`. Its strict canonical encoding,
  exact integer norm and executable public-key rounding equation are specified
  in [`../raccoon-g/SPEC.md`](../raccoon-g/SPEC.md). Full paper-to-code
  conformance remains pending PDF access: approved download retries failed.
- Both use the unchanged experimental RISC-V backend
  `06e5c9cd6981103786f9d0a17324241b559a50d3`, inverse-rate logarithm one and
  eight requested workers. Neither raises its `2^28` witness cap.
- The proved statement is signature validity for the intended final public keys
  and messages. Threshold signing and an authorized HD derivation path are
  separate claims. All measured proofs use the backend's plain proof mode.

## Preserved whole-signature failures

The original ordinary Raccoon and Raccoon-G ports remain in `../raccoon/` and
`../raccoon-g/`. Both execute the full verification relation correctly, but
production witness planning and proof production reject even a one-signature
direct batch. The original cohort in `../results/raccoon-study/` preserves every
capacity prefix through 64, every direct attempt through 30 and all failed tree
preflights. Rejection latency is never plotted as successful proving time.

Independent diagnostics show 419,337,656 committed words for standard Raccoon
and 839,237,560 for Raccoon-G at one signature. The backend cap is 268,435,456.
These diagnostic counts are distinguished from accepted production plans and
actual STARKs. Software SHAKE accounts for much of the instruction cost; no
matrix expansion or hash result is accepted as unchecked advice.

## Selected implementations

The [optimized standard guest](../experiments/raccoon-crt32/README.md) keeps the
original 64-bit Montgomery NTT, uses a bounded bulk decoder and aligned byte
helpers, and executes register-state software Keccak. The historic directory
name refers to a discarded CRT32 trial. Selected ELF:
`e375033cde726b2e988db2c433bf8d83b8516252c5954c1e43cb6720f3b25eac`.
One signature uses 247,895,480 witness words. Fresh main-cohort capacity checks
accept prefix one and reject every prefix two through 64. Actual production
proof attempts two through 30 also refuse. The accepted direct point has one
warmup and three fresh proofs, plus a separate public-only receiver.

The [segmented G guest](../experiments/raccoong-segmented/SPEC.md) uses five
linked partial leaves per signature, covering all nine rows as `(0,1)`, `(2,3)`,
`(4,5)`, `(6,7)` and `(8,8)`. Every part repeats all global encoding, norm and
challenge checks, and proves its row equations. A common 64-byte witness
binding links the complete signature and commitment vector. The final receiver
constructs the exact five-part coverage for each authorized original key/message
pair, then runs complete native `Tree::verify`. Composition assumptions are
explicit in the specification. Selected uniform ELF:
`5c48b8f39b14521773493692034fa601a9df89992552870addd68416cc926eac`.
All 500 parts of the original 100-signature corpus fit the same shape at
234,357,176 words per part. Fixed, proved store padding retains the one original
shape outlier. The complete receipt includes `60+64*N` auxiliary bytes.

## Production cohorts

- `../results/raccoon-runtime-study/`: main standard direct and tree measurements.
- `../results/raccoong-segmented-uniform-trees/`: final uniform G trees. The N=1
  complete pilot is separate from the requested three-run curve points.
- `../results/raccoon-optimized-study/`: earlier standard pilot and preflights,
  preserved with the original allocator behavior and excluded from main medians.
- `../results/raccoong-segmented-trees/`: earlier nonuniform-G planning failure,
  with its original executable and source archive preserved. No tree is claimed.

The main new cohorts set `_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0`
to purge released pages, overriding the native benchmark crate's indefinite
dirty-page retention. Existing Falcon/ML-DSA/FORS curves retain their original
settings. This runtime difference is disclosed rather than treated as a
signature-algorithm speed comparison.

[`../scripts/raccoon_full_matrix.py`](../scripts/raccoon_full_matrix.py) runs
the approved expensive jobs serially. Each tree pipeline produces every real
leaf and every merge fresh, retains all proof files, and runs an isolated
public-only receiver. Only explicit last-leaf padding is reused within one
pipeline. Nothing is reused across counts or samples. G witness reconstruction,
binding and advice packing are charged on every pipeline.

The operational limits are six hours per command and initially a 19 GiB sampled
RSS stop target, on a 24 GiB host. At 2026-11-10 04:17:47 UTC that monitor stopped
G's third 70-signature attempt after 71 partial leaves and no root. The complete
attempt and logs are [archived](../results/raccoon-full-matrix/resource-stops/20261110T041747Z/).
Its 627.917 seconds are aborted process elapsed time, not a complete proof timing.
The failed sample restarted from zero with a 20 GiB target and completed with
all 350 fresh parts and 511 fresh merges. That guard was also used for remaining
commands. No partial proof was reused; all 17 previously complete pipelines
remain unchanged. Five further complete pipelines were collected before the
later user stop. This does not change the proof-system witness cap or any
security parameter.

A 250 ms sampler is not a hard allocation limit. Complete native reports retain
their process-lifetime peak RSS; the aborted attempt records only the monitor's
threshold and stop reason, not an exact failed-process peak. Stops remain
separate from backend capacity failures and accepted measurements. See the
[memory measurement definition](../reviews/raccoon-benchmark/RSS-DEFINITION.md).

## Review

Independent source, arithmetic, codec and actual-ELF controls cover both original
ports and the selected optimizations. The accepted complete standard and G
pilots pass separate public-only receivers. Independent receiver controls reject
changed keys/messages, bindings, counts, programs, shapes, coverage, framing and
inner proof bytes. The bounded review and sample audits are in
[`../reviews/raccoon-benchmark/`](../reviews/raccoon-benchmark/). Final
multi-count evidence is complete for all 22 retained roots; the
[final review](../reviews/raccoon-benchmark/MATRIX-REVIEW.md) records proof-file
hashes, independently reconstructed public bindings, complete verification,
the revised sampling policy and both stop archives.
These checks do not claim a formal proof, a full backend audit or G paper and
parameter-security certification.
