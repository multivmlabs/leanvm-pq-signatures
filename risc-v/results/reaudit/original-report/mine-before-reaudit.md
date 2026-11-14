### Motivation

Post-quantum wallets should be able to choose a signature suited to their hardware and signing protocol. [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) provides programmable account validation, while [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288) proposes aggregating signature and proof dependencies into a recursive STARK. Together, these could let a wallet use an alternative signature while the network verifies a common proof.

There is concrete work behind this motivation: [Efficient Threshold ML-DSA](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_celi.pdf) constructs signatures compatible with standard ML-DSA verification, and [Falcon on Ledger Nano S+](https://github.com/ZKNoxHQ/ZKNOX-HW-FALCON) explores hardware signing. Aggregation does not implement MPC or secure the signer; it separates the wallet's choice of signature from the network's proof-verification interface.

### Implementation

All measurements use leanVM's **experimental `riscv-exploration` branch**, pinned to commit [`06e5c9cd6981103786f9d0a17324241b559a50d3`](https://github.com/leanEthereum/leanVM/tree/06e5c9cd6981103786f9d0a17324241b559a50d3). Falcon reuses the upstream implementation introduced by [PR #490](https://github.com/leanEthereum/leanVM/pull/490). The [code, build manifests and reproduction commands](../risc-v/README.md) accompany this post.

We test three verification workloads, all with 32-byte messages. Their parameter sets define separate workloads and security assumptions:

- **Falcon-512:** standard round-3 Falcon with SHAKE256. The guest checks packed public keys, compressed signature bodies, hash-to-point, polynomial multiplication and the norm bound. Its typed input fixes the headers and limits the compressed body to 625 bytes.
- **ML-DSA-44:** [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), pure mode with empty context. Compact public keys and signatures enter the VM. Matrix expansion, decoding, SHAKE, NTTs, norm bounds, hints and the final challenge comparison all execute inside it.
- **FORS:** a Keccak-256 forest with `n=32`, `k=16`, `a=8`. Every authentication path and the public forest root are checked inside the VM. FORS is a few-time component; these measurements exclude the SLH-DSA hypertree and its key-use policy.

ML-DSA retains the reference verifier's in-place integer arithmetic and fixed buffers. We replace only its Keccak permutation with leanVM's existing implementation, keeping SHAKE's padding and absorption unchanged. A controlled execution comparison reduced the one-signature witness from 65.4 million to 51.5 million words. The [optimization record](../risc-v/mldsa/optimization-trials.json) includes both builds and a discarded memory-copy optimization.

### Direct batching

A batch is one guest execution and one STARK, without recursion. The guest verifies every signature and commits the ordered public keys and messages. ML-DSA and FORS also commit their profile and count. The receiver derives the expected output from its own intended public records and verifies the proof under the approved guest program. It needs no signature witnesses.

The machine is an Apple M4 Pro with 24 GiB RAM. We use eight prover threads and logarithmic inverse rate one. Every point is the median of three fresh proofs after one warmup, in a fresh process for that batch size. Bars show the full sample range. RSS is peak resident process memory, including setup and warmup. Falcon uses the upstream same-message corpus; ML-DSA and FORS use distinct messages and keys. Proving includes execution, trace construction, witness construction and the STARK, excluding fixture generation, compilation and serialization. Verification includes proof decoding and full `Program::verify`, excluding public-record derivation, program loading and file reads.

![Proof size and proving time for direct batches](../risc-v/figures/figure-1-batching.png)

**The measured direct limits are 32 Falcon signatures, six ML-DSA signatures and seven FORS signatures.** Each boundary batch produces a proof that verifies. The next counts, 33, seven and eight respectively, are rejected by the prover. These limits apply to the pinned programs and deterministic input prefixes, not to every implementation of the signature schemes.

The backend permits at most $2^{28}$ committed witness words. This is the prover's internal record of the execution, not the final proof size. Individual instruction tables are padded to powers of two: one extra signature can force a table to double, so a batch can fail even when the previous one leaves apparent space. The proof-size curves also have steps because the commitment and opening layouts change. Missing points beyond the limit are not estimated measurements.

### Cost and operating point

![Verification time and peak resident memory](../risc-v/figures/figure-2-verification-memory.png)

A larger batch is not automatically a better proving workload. Falcon fits 32 signatures, but the witness jumps from about 145 million words at 28 signatures to 243 million at 29. Its measured proving cost rises sharply around that boundary. An aggregator should choose a batch size from both its latency budget and its available memory, rather than always fill the largest supported batch.

![Witness capacity and proving time per signature](../risc-v/figures/figure-3-capacity-efficiency.png)

FORS is dominated by software Keccak in this RISC-V profile. ML-DSA additionally pays for compact-key expansion and polynomial matrix arithmetic. These are different computations even when their final STARK sizes are similar. At the measured batch sizes, the proofs are still larger than the original signatures. A bandwidth benefit requires aggregation across many batches; this direct-batch experiment does not measure that recursive layer.

### Wallets and off-chain aggregation

A browser, phone or hardware wallet can sign locally and send the signature, public key and transaction digest to an off-chain aggregator. The aggregator checks inputs before admission and produces a batch proof. The receiver binds the proof's public claims back to the required transactions and account policy. The aggregator receives signatures, not signing keys, and cannot change the authorized messages without invalidating the proof.

This follows the [same-verifier batching suggestion in the EIP-8288 discussion](https://ethereum-magicians.org/t/eip-8288-frame-type-for-pq-sig-and-stark-aggregation/28723/14): prove many dependencies under one verifier before recursive aggregation. A further tree can combine those batch proofs and distribute block-level verification cost across different signature schemes. Fan-in, signatures per leaf, leaf proof rate and parallel scheduling are separate choices. These plots measure direct batches only.

EIP integration still needs an authenticated verifier identity, canonical per-transaction dependencies and a batch format that preserves each item's claim. The current EIP leaves the generic leanSTARK dependency digest and final aggregation parameters unfinished. These benchmark files are not block-valid EIP-8288 objects, and native milliseconds do not establish an Ethereum gas cost.

### Correctness review

Separate security agents reviewed [ML-DSA](../risc-v/reviews/mldsa-security.md) and [FORS](../risc-v/reviews/fors-security.md). They exercised malformed signatures and actual guest executions, checked public-statement binding and inspected build provenance. Independent oracles and sanitizer controls supplement those checks. Saved-proof consumer tests change public claims, corrupt proof bytes and substitute program pins. No accepting invalid execution was found in this scope. This is not a formal verification or a full audit of leanVM; the benchmark proofs are not zero knowledge.

### Wasm limitations

The native memory curves explain why an off-chain prover is useful for browser and phone users. One-signature runs peak at 1.06 GiB for Falcon, 6.53 GiB for ML-DSA and 5.18 GiB for FORS, despite their much smaller final proofs. A [wasm32 linear memory is limited to 4 GiB](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/Memory), while larger addressing does not supply additional physical RAM. Native process RSS includes more than a Wasm heap, so these figures cannot establish an exact browser limit. Falcon's single-signature case is the most plausible first port here; ML-DSA and FORS require particular attention to memory. Browser feasibility still needs an actual port and measurements.
