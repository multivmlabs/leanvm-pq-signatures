# Measured Raccoon benchmark runners

These runners embed the [selected Raccoon-128 guest](../experiments/raccoon-crt32)
and preserve its full signature relation and public commitment. Monolithic
Raccoon-G remains a linked identity/reference; its measured trees use the
[segmented runner](../experiments/raccoong-segmented).

`runtime_study.py` records the explicit Jemalloc page-purging policy, rate one
and eight requested workers. Proving is serial with a separate complete
public-only receiver. Source-frozen implementations are unchanged.

See the [reproduction guide](../../docs/reproduce.md) and
[selected measurements](../results/raccoon-runtime-study). Use a new output
location for any rerun; historical binaries and temporary proofs are omitted.
