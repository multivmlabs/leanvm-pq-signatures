# Raccoon-128-1 under RISC-V leanVM

This is original Raccoon with one unmasked signing share. It verifies the NIST compact encoding: a 2256-byte public key, a 11524-byte signature and exactly 32 message bytes. Public-key hashing, message hashing, parsing, matrix expansion, challenge generation, norm checks and ring arithmetic all execute in the VM. It uses the experimental RISC-V backend at `06e5c9cd6981103786f9d0a17324241b559a50d3`.

[SPEC.md](SPEC.md) gives the exact relation and its correspondence to the NIST specification. The unchanged official C reference is pinned to `e789b4b72a2b7e8a2205df49c487736985fc8417`. The local adapter additionally enforces the specification's canonical key coefficients and complete zero padding, using a bounded signature decoder that also handles the exact last-bit boundary correctly. All C globals without an existing scheme prefix use a local namespace to keep independent signature implementations linkable together.

The [independent review](review/SECURITY-REVIEW.md) found differences between the NIST PDF's challenge pseudocode and both official implementations. The user selected reference-code and known-answer interoperability, with those discrepancies documented. This is the approved profile; exact literal PDF conformance is not claimed.

The default guest uses the SDK's software Keccak permutation, crosschecked against the reference on complete states. SHAKE domain separation and byte handling remain in C. The `--no-default-features` Cargo build retains the reference permutation. There is no Keccak precompile or host acceptance hint.

From the project root:

```sh
python3 risc-v/raccoon/build_guest.py
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/raccoon-host-target" \
 cargo +stable test --release --locked --offline --manifest-path risc-v/raccoon/host/Cargo.toml --lib
CARGO_HOME="$PWD/.cache/riscv-cargo" CARGO_TARGET_DIR="$PWD/.cache/raccoon-host-target" \
 cargo +stable run --release --locked --offline --manifest-path risc-v/raccoon/host/Cargo.toml --example export -- 0
```

The native host exposes the same interface as the ML-DSA port: `ELF`, `PublicRecord`, `Record`, `record`, `records`, `batch`, `batch_range`, `run_from_records`, and `expected_output`. The fixture generator uses the unchanged C key generator and signer, with public deterministic AES-CTR-DRBG seeds derived separately for every index. These are public test keys. Signing and fixture generation are outside any future proving timer.

`review/crosscheck.json` records byte-for-byte agreement with the independent official Python reference for a deterministic fixture and the first complete NIST known-answer record. `review/correctness.log` records the native and interpreter tests. These are correctness controls, not performance results.

**Benchmarks are pending user approval.** No capacity, proving, proof-size or recursive-tree measurement is reported for this new port. `MAX_BATCH=64` only bounds the advice transport, not the backend's proving capacity. The common study will determine capacity from actual execution plans and verified proofs after approval.
