# RISC-V signature proof figures

These figures are generated with LaTeX/PGFPlots, compiled to PDF with Tectonic,
then rasterized to PNG with `pdftoppm`. The PNGs are previews of those same PDFs.

Regenerate after the measurements finish:

```
python3 risc-v/scripts/figures.py --render
```

The script reads only actual completed `prove` reports under
`risc-v/results/direct`, requiring `status=accepted` and `verified=true`.
Rejected, missing and execution-only cases are not plotted. Lines connect
measured points, with no extrapolation beyond them. Counts use a base-two
logarithmic axis with explicit integer labels.

- `figure-1-batching`: proof size and median proving time.
- `figure-2-verification-memory`: median proof verification time and peak process
  RSS. RSS is the process high-water mark recorded by each measurement process,
  including its setup and warmup; it is not a separately sampled guest heap.
- `figure-3-capacity-efficiency`: committed words as a fraction of the pinned
  backend's `2^28`-word budget, and median proving time divided by signature count.

Points are the medians of the recorded proof/verification samples. Vertical error
bars span their full minimum-to-maximum range, including on the per-signature
proving-time panel. They are sample ranges, not confidence intervals. RSS and
commitment sizes have no error bars because each report records one value.

`measurements.csv` retains every plotted numeric value, the recorded sample
ranges and the asymmetric error-bar lengths. Per-scheme CSV files are the direct PGFPlots inputs. `provenance.json`
records each source report's SHA-256, backend revision, guest ELF identity,
thread count, proof rate and sample count. The script refuses mixed backend,
thread or rate settings and different guest identities within one scheme.

The renderer copies the existing macOS Tectonic cache into the ignored local
`.tectonic-cache` directory. It creates a local ZIP bundle from those cached
resources and compiles with `--only-cached`, avoiding network access and writes
to the user's cache. A machine without those resources must populate its TeX
cache before rendering.
