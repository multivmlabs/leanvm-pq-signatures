# Proof relation and integration boundary

The project pins leanVM and both ZKNOX implementations in `upstream.lock.json`. The Rust executable compiles a single-file zkDSL guest, supplies witness streams, executes it, and produces a real proof with `leanvm_core::cpu::prove`. Every generated proof is checked with the upstream native verifier. The witness-free `.proof.statement.json` contains the guest source and the two public input cells needed for verification.

A fixture's public input is a Keccak commitment to the ordered batch of claims. Each claim includes the public key identity and signed message. The guest checks each signature and computes the commitment itself. Signature witnesses and arithmetic advice are not trusted host verification results. Clients must compute the expected batch commitment from their intended key/message claims and select the expected guest hash. Accepting an arbitrary prover-chosen statement establishes no wallet authorization.

The guest hash reported by the runner is leanVM's Fiat-Shamir program seed, committing to the protocol tag and stacked bytecode. It changes when the batch specialization or proof relation changes. It is an experimental verification-key identity for this backend, not an EIP-assigned key or `AGGREGATED_VK`.

The runner accepts `--expect-guest-hash` and `--expect-public-input` to enforce the caller's expected statement. Both are required for its `statement_pinned` report flag. These values must come from a trusted circuit configuration and intended claims, not from the received artifact. The unpinned generic API verifies the supplied program's execution only. Its `scheme` and `metadata` fields remain unauthenticated labels. Both native verification and dependency export expose this distinction explicitly. The bincode proof decoder requires exact consumption and rejects trailing bytes.

The `verify` command reports both uncached `verify_s` (including rebuilding and hashing the bytecode table) and `verify_cached_s` (prepares the fixed bytecode once, includes proof type conversion). `bytecode_prepare_s` reports that one-time setup. The upstream leanSPHINCS API caches its bytecode. Compare cached verification times when considering steady-state client cost.

## Four different costs

1. Fixture generation/native verification: prepares valid inputs; excluded from proving time.
2. Direct batch execution: the VM's deterministic instruction count and an interpreter timing; this checks the guest but produces no proof.
3. Direct batch proof: includes execution, witness building and the polynomial/hash proof, followed by native proof verification. Compilation, serialization and fixture generation are separately excluded.
4. Recursive merging: proving verification of existing proofs. `aggregate-falcon` implements one fixed-arity root over six ETHFALCON leaf proofs, covering 30 distinct key/message claims. `aggregate-tree` adds bounded multilevel trees with heterogeneous child programs and exact tail batches. Both reuse the upstream in-VM proof verifier. The tree receiver reconstructs every node statement and discharges every edge's deferred child-bytecode evaluation against trusted code before checking one root proof; see [the tree format](tree-format.md). The upstream leanSPHINCS recursion benchmark remains a separate reference workload. Dependency unions/discards and reusable online subtree merging remain unimplemented.

`pqbench project` extrapolates measured leaf work. Its output explicitly identifies a projection. If supplied, recursive merge time is a user assumption, independent of the actual experiments. The separate `aggregate-falcon` result measures a six-to-one root directly; [the article workflow](ethresearch-article-plan.md) records bounded-tree measurements under `results/article`. A binary tree of L nonempty leaves has L-1 merges. Parallel scheduling, total work and networking remain separate quantities. The tree runner retains all deferred points, so auxiliary bytes and final native evaluation work grow with the number of edges. Its merge code is specialized to the complete intended plan and cannot be reused across changing online mempool plans.

## EIP-8288 variant

The [draft EIP-8288](https://eips.ethereum.org/EIPS/eip-8288) currently accepts scheme `0x10` for leanSPHINCS in dependency frames and reserves `0x11` until its digest is specified. Its final aggregate verification key and dependency hash are TBD. Consequently these proof files are experiments for a possible generic-STARK route, not block-valid EIP-8288 objects.

A possible extension maps one guest proof to `(0x11, public_input_hash, guest_verification_key_hash)`. Wallet validation must pin the allowed signature relation, bind each required public key and transaction digest into the batch statement, and check dependency membership. An aggregator must verify child proofs in its guest before it can claim a union. Host concatenation or native verification followed by proving a digest does not implement recursive aggregation.

`pqbench dependency` verifies an actual saved proof and emits a local 96-byte dependency-frame codec experiment. Here `data_hash=Keccak256(public_input_bytes32)` and `verification_key_hash=fs_seed(program)`, the leanVM protocol/bytecode commitment. It labels the object invalid under the present EIP draft and requiring a client extension. This command does not produce a recursive block proof or an Ethereum transaction, and does not imply that its experimental key-hash definition will become normative.

[EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) defines frame transactions and account validation/payment approval. Wallet code must enforce the canonical transaction signature hash, chain, sender, nonce, expiry, spending policy and approval behavior. The synthetic benchmark messages here are not serialized frame transactions. No client patch or contract deployment is included.

## Mempool merging and wallet consequences

The [recursive mempool proposal](https://ethresear.ch/t/recursive-stark-based-bandwidth-efficient-mempool/23838) motivates replacing propagated witnesses with proofs while combining, deduplicating and discarding dependencies. The [signature-merging post](https://ethresear.ch/t/signature-merging-for-large-scale-consensus/17386) explains why overlapping signer sets require a union operation. Ordered direct batches in this project neither implement that set-union relation nor provide discard proofs. A production recursive guest needs canonical claim identities and explicit subset/union checks.

Aggregation changes the cost of verifying and transporting signatures; it does not supply a threshold signing protocol. MPC implementations still need a suitable threshold construction and protection against aborts and leakage. Hardware wallets can sign independently of the server prover; their signing latency, memory use and secure-element hash support are additional measurements. Falcon and Dilithium's signer tradeoffs therefore remain relevant even if their aggregate proof sizes converge.

## Current limitations

At the pinned revision leanVM uses binary fields, Keccak and custom leanISA. [Upstream documentation](https://github.com/leanEthereum/leanVM/blob/575df819d9c857f38068cecf7b1640e0ce4bfb29/AGENTS.md) states that proofs are not zero knowledge, formal verification is incomplete, and the system is experimental. The target backend soundness setting is 128 classical bits; this project adds no cryptographic security proof for its guest implementations. The proof system's design target does not establish the signature variants' security.

FORS is a few-time signature component. Its standalone experiment excludes SPHINCS key authentication and hypertree costs. It must not be interpreted as an unlimited-use wallet signature or directly security-equivalent to the lattice schemes. The upstream full leanSPHINCS baseline supplies a more relevant hash-based wallet comparison.
