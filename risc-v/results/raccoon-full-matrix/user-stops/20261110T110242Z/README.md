# User-requested stop, 10 November 2026

The user instructed us to stop additional benchmarking and use an estimate for 100 Raccoon-G signatures. The first complete 100-signature pipeline had already passed full public-only verification at 11:01:28 UTC. It is retained as one actual observation, not a three-run median. The next fresh pipeline was stopped immediately: SIGTERM was sent to its producer group and coordinator at 11:02:42 UTC, and both were confirmed exited. Idle-sleep prevention exited too.

The stopped second sample contains seven completed partial leaf proofs, no merges and no root. Its saved leaf work totals 68.670074626 seconds. The third sample never started. This is a user stop, not a witness-capacity failure or a memory failure. No partial work is an accepted curve point. No further benchmarking will be launched.

`manifest.json` records original paths and SHA-256 values. `archive-mapping.json` maps each path to its unchanged file under `evidence/`. Partial sample files and producer logs were moved out of the active cohort; the raw coordinator progress was copied. The 22 complete roots are unchanged. `stop-confirmation.json` records process and session exit evidence. The earlier 19 GiB RSS stop remains separately archived under `resource-stops/`.
