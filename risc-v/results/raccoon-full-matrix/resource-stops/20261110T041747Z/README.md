# Operational RSS stop, 10 November 2026

Raccoon-G N=70 sample 2 stopped at 04:17:47 UTC after 627.917086 seconds when the sampled process RSS exceeded the internal 19 GiB operating target. The harness sent SIGTERM (exit -15). This is not a witness-capacity failure: the backend cap stays at 2^28 committed words. No complete root was produced. There are 71 completed partial leaf proofs, no merges, and an interrupted report. This attempt is excluded from successful sample medians and is retained in full.

`manifest.json` records every original path and SHA-256 before archival. `archive-mapping.json` maps each original path to its unchanged file under `evidence/`. All 77 file hashes were rechecked. Only the failed sample directory and its producer command logs were moved out of their logical sample paths; the stopped coordinator progress was copied. The separate stopped-progress snapshot also remains here. No successful sample was moved or modified.

The unchanged coordinator will resume the 17 completed and independently verified samples, and restart this complete G sample from zero with a 20 GiB sampled RSS target. Every one of its 350 leaf parts and 511 merges will be freshly proved and charged. No partial proof from this stopped attempt is an input to the retry. Subsequent samples use that same 20 GiB operating target, with unchanged native binaries, guest ELFs, proof parameters, allocator policy and 2^28 commitment cap.

This is a sampled stop target, not a hard allocation bound or a claimed measured peak. The stopped process did not finish writing a peak-RSS report. The original 19 GiB configuration, stopped progress and exact source identity remain archived.
