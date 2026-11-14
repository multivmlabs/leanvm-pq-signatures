# Approved Raccoon benchmark results

Figure regeneration reads retained data and produces no new proofs. Do not
restart the original coordinator for that purpose: it targets the original
24-pipeline plan. The revised 22-pipeline scope is in `sampling-policy.json`;
`g100-estimate.json` contains the separate G70-based model.

The user stopped further benchmarking after the first complete Raccoon-G tree for 100 signatures. The final scope contains 22 complete, publicly verified roots: all 12 standard Raccoon trees, three Raccoon-G samples at each of 10, 30 and 70 signatures, and one complete Raccoon-G sample at 100. No further proving is running.

Every accepted root passed a separate receiver using only the intended public statement and aggregate receipt. The statement pins the original ordered public keys and messages, guest identity and tree policy. Signature witnesses and child proof files are not receiver inputs.

| Scheme | Signatures | Complete fresh pipelines | Proving work, s | Receipt, KiB |
|---|---:|---:|---:|---:|
| raccoon | 10 | 3 | 120.327 | 260.562 |
| raccoon | 30 | 3 | 358.093 | 260.937 |
| raccoon | 70 | 3 | 828.704 | 259.968 |
| raccoon | 100 | 3 | 1164.905 | 261.374 |
| raccoon-g | 10 | 3 | 488.283 | 261.620 |
| raccoon-g | 30 | 3 | 1479.005 | 262.558 |
| raccoon-g | 70 | 3 | 3323.246 | 264.995 |
| raccoon-g | 100 | 1 | 4906.050 | 266.995 |

Rows with three pipelines report medians, with raw samples retained in `measured-summary.json` and the native reports. The Raccoon-G 100-signature row is one actual complete pipeline, not a three-run median or an extrapolation. It includes 500 fresh partial leaf proofs, all 511 fresh merges, and fresh native witness/binding/advice preparation. Its 273,403-byte receipt includes the 266,943-byte core and 6,460 bytes of auxiliary framing and per-signature bindings.

The separate G70-based model in `g100-estimate.json` gives 78.30 minutes and
266.87 KiB for G100. It scales only leaf and native-preparation work by 100/70;
both counts use 512 slots and 511 merges. Its three propagated estimates span
78.11 to 80.43 minutes, which is not a confidence interval. The completed G100
run took 81.77 minutes, 4.4% above the model. The model was calculated after
that run existed, using only G70 inputs, and is not a blinded prediction.

The unchanged native backend is pinned to `06e5c9cd6981103786f9d0a17324241b559a50d3`. All accepted commands use inverse rate one, eight requested workers, and the explicit Jemalloc policy `_RJEM_MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0`. The commitment cap remains 2^28 words. The coordinator source SHA-256 is `c117ef5be9437638c5802f109362d4108b822ed3c8d4c97d16da950cae4ab09d`.

The first 17 accepted roots used a sampled 19 GiB operating target. One G70 third-sample attempt crossed that target and was stopped after 71 partial leaf proofs, with no root. Its full evidence is preserved under `resource-stops/20261110T041747Z/`. The unchanged coordinator resumed under a sampled 20 GiB target; all 350 parts and 511 merges for that sample were freshly generated. All remaining complete roots use that target. This changes an operating guard, not a proof parameter or a hard allocation bound. The pause between the resource stop and restart is excluded from native proving-call sums and remains visible in command timestamps and `guard-policy-transition.json`.

The user then requested immediate termination of remaining G100 runs. The second sample had seven partial leaf proofs and no merges or root when stopped; the third sample never started. Evidence and original-to-archive path mappings are under `user-stops/20261110T110242Z/`. Both stopped attempts are excluded from success medians and remain auditable. The coordinator, producer group and idle-sleep assertion all exited.

Raw native datasets are `../raccoon-runtime-study/raccoon/` and `../raccoong-segmented-uniform-trees/`. Their frozen environments record native binary, guest ELF, build manifest and source identities. `progress.json` records the explicit user scope reduction. `measured-summary.json` retains timer components without changing their meanings: standard Raccoon prepared verification excludes public-claim derivation, whereas segmented G prepared complete verification includes envelope and part-claim derivation; its public configuration preparation is separate. Compare complete totals only with those boundaries accounted for.
