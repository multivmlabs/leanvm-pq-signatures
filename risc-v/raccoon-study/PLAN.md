# Raccoon benchmark plan

The user approved the complete matrix on 2026-11-09: direct batches, capacity
checks and recursive trees at 10, 30, 70 and 100 signatures, with three fresh
runs and full verification. This file preserves the original plan. The
[status record](STATUS.md) identifies the selected implementations, preserved
failures and current production cohorts.

On 2026-11-10 the user stopped further 100-signature benchmark repetitions and
requested an estimate. Standard Raccoon already had all three complete N=100
runs; G had one complete, fully verified run. The final retained study therefore
has 22 complete tree pipelines. G100 is explicitly a single measurement, with
a separate estimate from the three G70 pipelines. No further proving is run.

Use the RISC-V backend at
`06e5c9cd6981103786f9d0a17324241b559a50d3`, the same rate (`1`) and requested
worker count (`8`) as the existing Falcon and ML-DSA studies. Keep all original
guest binaries, runners and results unchanged. The two new native binaries are
`riscv-raccoon-direct` and `riscv-raccoon-tree`, built in
`.cache/raccoon-study-target`.

The standard baseline is Raccoon-128-1, with one unmasked share and the official
serialized public key and signature. It is not a threshold signing implementation.
The user selected official C/Python and known-answer interoperability, with
the NIST PDF's conflicting challenge pseudocode documented. Raccoon-G uses the separate
reviewed profile in `risc-v/raccoon-g/SPEC.md`, based on the authors' code for the
HD-wallet paper ePrint 2026/380. The full paper was unavailable during the port;
the profile uses strict canonical decoding and an exact integer norm bound and
does not claim paper-level conformance or independently validated security
parameters. Both guests have completed independent implementation reviews.
Both guest input limits are
64 signatures, distinct from unknown proof capacity.

## Proposed stages

1. Freeze guest ELF, source, reference implementation and runner hashes after
   correctness and security review. Confirm every public key/message and every
   signature check is bound to the approved program. Correctness checks do not
   establish proving capacity or provide benchmark points.
2. Measure every deterministic prefix from one signature through the explicit
   guest input bound. Record interpreter instructions, table rows, padded table
   heights and total committed witness words. Do not stop at the first failure:
   table padding and signature-dependent control flow can make capacities
   non-monotone. An advice limit is separate from a proof-system limit.
3. Produce direct proofs for counts 1 through 30 wherever the full backend
   accepts them. Use the existing direct-study sampling convention: one untimed
   warmup and three timed proof calls, retaining the last complete proof. Run a
   separate public-only receiver for that retained proof. Explicitly retain
   actual prover refusals, rather than extrapolate gaps. Also prove the largest
   accepted prefix beyond 30 and attempt the next count where applicable. Call
   it the largest measured prefix in this corpus, never a universal maximum.
4. Before selecting a tree leaf size, test the candidate sizes 1, 2, 5 and 10
   against all 100 deterministic corpus records in their original order. Keep
   every candidate result. The native tree requires identical padded leaf table
   heights, so a candidate with differing shapes is unavailable. Do not reorder
   or choose favourable records. Choose an operating point from the compatible
   candidates, documenting any proof-time pilot used in the selection.
5. Run recursive trees for 10, 30, 70 and 100 distinct signatures, with three
   completely fresh producer processes per count and scheme. Use binary merges
   and canonical repetition of the last real leaf in power-of-two padding
   slots. Prove every real leaf once per pipeline and every merge afresh. Do not
   count padding as extra signatures or cache proofs between samples.
6. For every root, run the full native `Tree::verify` consumer in an isolated
   directory containing only the public statement and root proof. It must derive
   every intended public key/message commitment, check caller-pinned statement
   and ELF hashes, decode the complete root, and settle every folded bytecode,
   image, fixed-polynomial and Flock-matrix claim. Include changed-key,
   changed-message, changed-count, reordered-leaf and corrupted-proof controls.
7. Report total leaf and merge proving work, complete root bytes, peak process
   RSS, claim derivation, cold verification and prepared verification. Retain
   per-sample raw reports, commands, logs and proof hashes. Update the article
   and LaTeX-generated figures from accepted, fully verified measurements only.

The existing plain proof mode is used. This study measures verification of
signatures, rather than threshold signing rounds or wallet secret-key generation.
If the Raccoon-G guest verifies only the final derived public key's signature,
say so explicitly. A claim that a key follows an authorized wallet path requires
separate derivation verification and must not be inferred from signature validity.

## Resource bounds

Run expensive stages sequentially. The original proposal used an 18 GiB sampled
RSS target and 30 minutes per command. Actual complete pilots showed that the
requested large trees need more time. The main matrix initially used a 19 GiB
sampled RSS target and six hours per producer command, on the same 24 GiB host.
That RSS monitor stopped one incomplete G tree at 70 signatures. Its 71 partial
leaf proofs and logs are preserved in the [resource-stop archive](../results/raccoon-full-matrix/resource-stops/20261110T041747Z/).
The whole sample is rerun from scratch with a 20 GiB operational target, also
used for the remaining commands. The guest, backend cap and proof parameters
remain unchanged.
The monitor samples every 250 ms; this is an operational stop policy, not a hard
allocation cap. Reports retain actual peak RSS even if a brief peak exceeds the
sampled target. A resource stop is separate from a cryptographic rejection or a
backend capacity limit. Missing points are never filled with estimates.

Both selected complete pilots passed public-only verification before the main
matrix. The cost is substantial because every Raccoon-G signature needs five
fresh partial proofs. No proofs are reused between samples or counts.

## Preview commands

`study.py` prints commands unless `--execute-approved` is explicitly supplied.
These previews do not execute a guest or produce benchmark measurements.

```sh
python3 risc-v/raccoon-study/study.py capacity --scheme raccoon --input-limit 64
python3 risc-v/raccoon-study/study.py direct --scheme raccoon --input-limit 64
python3 risc-v/raccoon-study/study.py tree-plan --scheme raccoon --input-limit 64
python3 risc-v/raccoon-study/study.py tree --scheme raccoon --input-limit 64 --leaf-size 1
```

After review, final builds and approval, freeze provenance before the expensive
stages with `freeze --scheme raccoon --input-limit 64 --execute-approved`.
That stage only hashes existing files. No corpus is pre-generated during
implementation or the default command previews.

Replace the final leaf size only after the recorded compatibility and operating
point selection. For capacity boundary proof checks, pass explicit counts with
`direct --counts N M`. Use a new output directory for reruns: the runner refuses
to overwrite a completed command, and the tree producer refuses existing sample
directories.

Raccoon-G uses `--scheme raccoon-g --input-limit 64`. Its input bound comes from
its own 4-MiB advice allocation. No Raccoon-G proof capacity is inferred from
standard Raccoon.
