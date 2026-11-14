# Capacity re-audit

This is an independent capacity diagnostic for the unchanged RISC-V backend at
`06e5c9cd6981103786f9d0a17324241b559a50d3`. It preserves the original benchmark
reports. No guest, verifier, commitment cap or production guard is changed.

The diagnostic runs an honest guest to completion with the raw `Machine`
interpreter, counts every instruction class, and reproduces the backend's public
fill/layout arithmetic. This allows a rejected batch's final size to be examined
without constructing its witness or pretending to prove it. It separately calls
unchanged `Program::measure`. Its exact size calculation was checked against all
25 original successful production reports.

The optional `prove` mode calls the actual production `Prover::prove`, serializes
and decodes its proof, calls full `Program::verify`, and checks rejection of a
changed public output. A raw interpreter result is never labeled a proof.

## Commands

From the project root:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
  cargo +stable build --release --locked --offline \
  --manifest-path risc-v/reviews/lattice-capacity-reaudit/Cargo.toml
audit="$PWD/.cache/riscv-host-target/release/lattice-capacity-reaudit"
"$audit" check-reports
"$audit" falcon 33 0 /tmp/falcon33-prefix.json
"$audit" falcon 33 96 /tmp/falcon33-window96.json prove
"$audit" mldsa 7 0 /tmp/mldsa7.json
```

The second positional integer is the starting signer/record index. `start=0`
reproduces the original prefix corpus. Other starts use different valid records,
with the same verification relation and ELF. Proof mode currently exports
Falcon public statements only. Run memory-heavy proofs serially.

`SUMMARY.json` indexes all recorded cases. `results/` contains complete row and
periodic-check traces. The 33-signature validation proof is one fresh proof with
no warmup, not a replacement for a three-sample timing point.
