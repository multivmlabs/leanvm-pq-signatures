# Raccoon figure methods

The additive figure generator is
[`articles/scripts/raccoon_figures.py`](../../articles/scripts/raccoon_figures.py).
It reads completed reports and never runs a prover. A separate G100 estimate is
recomputed from G70 components and kept outside the measured curves.
The original three-scheme figures and their provenance remain unchanged.

The selected standard-Raccoon cohort is
`risc-v/results/raccoon-runtime-study/`. It uses the reviewed optimized whole
verifier and an explicit page-purging allocator policy. The historical folder
name `raccoon-crt32` does not describe its selected arithmetic: that port retains
64-bit Montgomery NTT arithmetic. The selected Raccoon-G cohort is
`risc-v/results/raccoong-segmented-uniform-trees/`, using five linked partial
leaves per signature. Its fixed execution padding is charged.

The requested output directory is `results/mine/raccoon-figures/`. It is created
only after the selected measurements pass validation. Generation refuses an
existing directory, so a rerender uses a new output path until the final visual
review is complete.

| Figure | Left panel | Right panel |
| --- | --- | --- |
| 1 | Direct-batch serialized proof size | Direct-batch proving time, logarithmic |
| 2 | Complete direct-proof verification | Peak process RSS |
| 3 | Committed witness budget used | Proving time per signature, logarithmic |
| 4 | Sum of every fresh leaf and merge proving call, logarithmic | Complete serialized recursive root |
| 5, top | Receipt verification including program setup and public processing, logarithmic | Receipt verification with prepared programs and public processing, logarithmic |
| 5, bottom | Native tree verification with intended outputs prepared, including every terminal claim, logarithmic | Public-record processing, logarithmic |
| 6 | Four one-signature or partial-leaf witness layouts, with the production cap shown | Hatched bars distinguish uncapped diagnostics from actual verified proof layouts |

Direct counts are ordered numerically. Lines connect measured, accepted points;
they do not fill capacity gaps or extrapolate a missing tree. A rejected attempt
is not a zero-size proof or a zero-second measurement. Resource stops and backend
refusals must remain distinct from successful proof points.

The new Raccoon measurements must match their frozen source, runner, guest,
statement and proof hashes. Direct points require a separate public-only
receiver. Tree points require the user-authorized sample set at the stated count,
all real leaves, every merge including padding, and complete public-only
verification of all folded claims. The generator checks the retained
intermediate proof files as well as the root. Changed public claims and corrupted
proof controls must reject.

The user stopped further 100-signature proving after one complete Raccoon-G
pipeline had finished. That point is one measured run, shown with a hollow marker
and a dashed link from 70. Every other tree point is the median of three fresh
pipelines, with minimum-to-maximum ranges where shown. G100 has three prepared
verification calls from its single receiver, not three producer pipelines. The
data contains 58 complete pipelines across 20 plotted points, including the
36 retained pipelines for the original three schemes.

The independent G100 estimate scales G70's native preparation and partial-leaf
work by `100/70`, keeping its 511 merges fixed because both counts use 512 slots.
The three G70 runs give an estimated 78.30 minutes, with an observed-input range
of 78.11 to 80.43 minutes. This is not a confidence interval. The predicted
receipt size is 273,275 bytes. The completed G100 run took 81.77 minutes and
produced 273,403 bytes. The model was calculated after the completed G100 run
existed, using only G70 inputs. It is a retrospective comparison, not a blinded
prediction. The estimate is retained in `g100-estimate.csv` and provenance, never as a
measured curve point.

The original monolithic implementations' failed capacity checks, actual direct
prover attempts and failed fresh tree preflights remain in a separate ledger.
There is no direct-batch G proof point. The complete G curve is a segmented-tree
receipt, not the sum of five independent unchecked row proofs. Its size includes
the root, the envelope and one 64-byte shared witness binding per signature.
Its proving work includes fresh native commitment reconstruction, binding and
advice preparation, every actual partial leaf and every merge over padding.

One later operational stop is retained separately from those backend refusals.
The initial G70 sample 2 attempt was interrupted after 627.917086 seconds when
sampled process RSS exceeded a 19 GiB operating target. It had saved 71 partial
leaf proofs and no complete root. The attempt's elapsed time and partial proof
sizes are excluded from every successful timing or size curve. Its 77 original
files are preserved under
`risc-v/results/raccoon-full-matrix/resource-stops/20261110T041747Z/`, with an
original-to-archived path mapping and hashes.

The same source, native executables, guest ELFs, proof rate, workers, allocator
policy and `2^28` witness cap were retained when the sampled operating target
changed to 20 GiB. The first 17 completed pipelines are preserved. Final figure
validation requires those same samples and five further complete pipelines
under the resumed target. The interrupted G70 pipeline is restarted in full,
with no partial proof reused. The authorized G100 singleton remains outside any
claim of three-run medians. These sampled stop
targets are not hard allocation bounds, and no exact failed-attempt peak RSS
was recorded. `resource-stops.csv` keeps that peak field empty and records the
stop independently of `refused-experiments.csv`.

The later user-requested stop saved seven partial G100 leaves and no root for
sample 1. Its 12 archived files are hash-checked under
`risc-v/results/raccoon-full-matrix/user-stops/20261110T110242Z/` and recorded
separately in `user-stops.csv`. This interruption is neither a witness-capacity
failure nor a memory failure. G100 sample 2 never started.

Figure 5 explicitly distinguishes raw timings and component sums. For Falcon,
ML-DSA, FORS and standard Raccoon, the receipt totals add separately measured
public-claim processing to the recorded complete proof-verification timer. For
segmented G, the complete-call samples already include envelope decoding and
derivation of every part's output from the supplied witness bindings; only its
separate public-configuration parsing cost is added. G's public-processing panel
contains both public-configuration parsing and the standalone envelope/output
derivation timer. It is not obtained by subtracting independent medians. The
raw component samples are retained in `verification-raw-timers.csv`.

The public-processing and native-verification panels are independently timed.
Their medians need not sum exactly to the complete-call median because they
come from different calls and cache states. In particular, segmented G's receipt
timer is not reconstructed by adding its standalone claim-derivation and native
verification timers. The old four receipt totals remain explicit component sums.

The native tree-verification panel checks the root and settles all terminal
verifier obligations. For segmented G, `prepared_core_verify_s` still invokes
the complete native `Tree::verify`; it excludes only the RGSTK001 envelope and
public-output derivation. FORS begins from a decoded envelope, while native
RISC-V timers include proof decoding. File reads and JSON deserialization remain
outside the plotted regions.

Proof-size panels count serialized proof receipts. Public keys, messages and
shared verifier programs are additional transport. In particular, Raccoon-G's
full public keys are larger than standard Raccoon's compact keys; a root-proof
curve alone does not measure a transaction's total bandwidth.

The Raccoon-G curve denotes the documented strict authors' HD profile, including
canonical encodings and an exact integer norm predicate. It does not establish
paper conformance or independently validated parameter security. Standard Raccoon
uses the user-approved official-reference interoperability policy, with the NIST
PDF discrepancies retained in the implementation review.

Segmented G's common-witness composition is conditional on the extraction and
joint commitment-binding assumptions stated in its specification and review.
These measurements do not provide a formal composition theorem.

The existing Falcon and ML-DSA workloads use RISC-V, and FORS uses leanISA with
the specialised Keccak circuit and sumcheck reduction. These are implementation
measurements with different acceleration and verifier setup costs. They do not
hold backend or signature security assumptions constant. The new standard and
segmented G cohorts set `_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0`;
the older workloads retain their recorded allocator settings.

LaTeX/PGFPlots produces the PDF figures, and Poppler rasterizes those same PDFs
to PNG at 180 dpi. Every final PNG is inspected for labels, legends, clipping,
axis scales and overlap. The final output also retains CSVs, TeX, render logs,
proof hashes and source provenance.
