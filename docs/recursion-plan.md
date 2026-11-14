# Generic recursion for the custom signature guests

**Implementation update:** the first fixed-arity stage below is implemented by `src/bin/aggregate-falcon.rs`, `src/recursion_support.rs`, `src/recursion_guest.rs` and `guests/aggregate_falcon.py`. The measured experiment proves six distinct five-signature ETHFALCON leaves and one six-to-one recursive root, with all six deferred evaluations discharged by the final native verifier. See [the actual result](../results/recursive-30/REPORT.md).

The bounded multilevel extension is implemented by `src/bin/aggregate-tree.rs` and `src/tree_guest.rs`. It supports fan-ins 2/4/8, exact tail batches and heterogeneous child programs, retains deferred points for every tree edge, and reconstructs all node statements against trusted bytecode before checking one root proof. The primary, fan-in and leaf-size benchmark matrix completed successfully on 3 November 2026 at 20:59 UTC. See [the article](../articles/leanvm-signature-aggregation.md), [the tree format and trust boundary](tree-format.md), [the experiment status](ethresearch-article-plan.md), and [the raw records](../results/article/). Records distinguish fresh full pipelines from cached-leaf merge measurements. The final suite and two-wrapper forged-bytecode control passed at 21:02 UTC. The strengthened [interleaved mixed-program case](../results/article/mixed/evidence.json) also passed fresh public-only verification; it is one correctness demonstration, not a performance curve. Merge code specializes to a complete global plan, so reusable online mempool subtrees, deferred-claim folding, dependency unions and discards remain future work. The remainder retains the original investigation and subsequent folding/self-recursion proposals; statements that custom recursion was absent describe its starting point.

At the start of this investigation, the project produced direct-batch leanVM proofs for ETHFALCON, the expanded-key ETHDILITHIUM variant, and the research FORS variant without recursively combining them. Upstream leanSPHINCS recursion remains a separate reference workload; the custom fixed-arity and bounded-tree experiments are measured independently.

Generic custom recursion is feasible with the pinned backend. Its in-VM proof verifier already takes the inner program's Fiat-Shamir seed as an argument. The public aggregation API specializes its claim representation, host witness generation and deferred bytecode evaluation to one self-recursive leanEthereum guest. Reusing that API unchanged cannot turn these custom leaf proofs into valid `EthereumProof` objects.

## Why large direct batches stop

At leanVM revision `575df819d9c857f38068cecf7b1640e0ce4bfb29`, `leanvm_core::pcs::MAX_MU` is 28. `cpu::prove` rejects a witness whose stacked commitment requires a larger log size. The actual trial logs in this project record:

| Direct batch | Result |
|---|---|
| ETHFALCON, 4 signatures | Proof generated and verified |
| ETHFALCON, 8 signatures | `WitnessOutOfRange { log_committed: 29 }` |
| ETHDILITHIUM, 1 signature | Proof generated and verified |
| ETHDILITHIUM, 2 signatures | `WitnessOutOfRange { log_committed: 29 }` |
| Research FORS, 256 signatures | Proof generated and verified |

The failing logs are `results/2026-11-03-falcon/ethfalcon-8.log` and `results/2026-11-03-dilithium/ethdilithium-2.log`. These failures are measured limits of the original implementation, not timing measurements for the failed proofs. Raising the constant requires checking PCS configurations, soundness bounds, buffers and memory cost. The subsequent tree runner instead divides work into bounded leaf proofs and proves their verification.

## Reusable source and API boundary

All references below refer to the pinned source under `vendor/leanVM`. Keep that checkout unchanged. Place an attributed adapter in a new local crate or module, with tests against the pinned implementation. Preserve the upstream license notices and make any extraction fail clearly when the source revision changes. Extract named functions and their dependency closures rather than relying on unchecked line-number slices.

| Source | Reuse and required adaptation |
|---|---|
| `crates/rec_aggregation/guests/lean_ethereum.py`, through `verify_sub` | The proof verifier, transcript helpers, field packing, layout certification, Keccak verification and WHIR opening. Replace its signature/DA-specific `main`. `verify_sub(pi_0, pi_1, seed_0, seed_1, g_logs_pow2, g_squares, defer_out)` is already parameterized by the child program seed and public input. |
| `crates/rec_aggregation/src/aggregation.rs`, `gen_verify` | Private host witness preparation from a `Program`, public input, scalar proof stream and `verifier::Summary`. Its layout handling is mostly generic. Replace the hardcoded evaluation of `stacked_bytecode()` with the actual child program's `cpu::layout::bytecode_table(&program.prog)`. |
| Same file, `placeholder_map`, `whir_shape`, `merkle_cap_depth`, descriptor types and coordinate helpers | Private compilation constants and hint-layout generation. `placeholder_map(kbc)` depends on child bytecode log size and backend structure, not the child's signature scheme. Extract its helper dependency closure. Scheme-only placeholder entries can initially remain populated rather than being selectively removed. |
| Same file, `aggregate_deferred_claims`, bytecode sumcheck helpers, `DeferredClaim` | Reuse in the second stage, parameterized by an explicit trusted bytecode table instead of the cached self-guest. The in-VM counterpart is `aggregate_claims`, near the end of the guest file. |
| `crates/verifier`, `Bytecode::new`, `Bytecode::evaluate`, `verify_execution`, `replay_unchecked` and `Summary` | Public low-level native operations already expose what an adapter needs. `replay_unchecked` prepares hints; it is explicitly not verification. Only the recursive guest and final checked verification establish validity. |
| `leanvm_core::cpu`, `layout`, `fs_seed`, `scalar_proof`, `public_input_bytes`, `prove`, `verify` | Public low-level program, proof transport and verification infrastructure. |

The most important extraction is approximately the generic verifier portion of the upstream guest plus the host placeholder/hint machinery. This is a substantial proof-system integration, not a small wrapper around the public `aggregate` function. A useful upstream change would expose a supported generic recursive-verifier API and move these helpers out of signature-specific aggregation.

Verification comparisons must separate preparation from steady-state checking. `cpu::verify` rebuilds and preprocesses the stacked bytecode table on every call. Upstream `EthereumProof::verify` caches `verifier::Bytecode` for its fixed program. A fair repeated-verification benchmark prepares `Bytecode::new` once, records that setup separately, then times `verifier::verify_execution` with the prepared object. Retain cold verification as another useful metric. Include proof conversion consistently in either timing boundary and state that choice; cold custom verification and cached upstream verification are different workloads.

The existing recursive opening dispatch supports commitment sizes `MU_MIN=22` through `MAX_MU=28`. An existing custom FORS proof with one signature has log size 19 and does not fit that dispatch. Reprove such a leaf with `Program::min_log_committed=22`, use a sufficiently large FORS leaf batch, or deliberately extend and validate the dispatch configurations. The measured FORS batch of 16 already has log size 22. Ordinary Falcon and Dilithium leaf proofs already fit its size window. The transport also has a fixed `STREAM_CAP=8192`; check each candidate child against that cap.

## Stage 1: two proofs of the same custom leaf program

Start with two leaf proofs of exactly the same guest, parameter set and count, with different keys/messages. Pin their expected program digest. The native test harness must first verify both leaves normally, then prepare the same verifier summaries and hints the recursive guest will consume. This reduces the first prototype to one child bytecode layout and one trusted bytecode polynomial.

Build a wrapper guest from the existing generic verifier functions. Its `main` calls `exponent_tables` once, reads two child public inputs, calls `verify_sub` for each using the pinned child seed, and publishes a domain-separated digest of the ordered child claims and the deferred bytecode evaluation data. A leaf public input represents an exact ordered signature batch; publish enough claim-manifest data for a receiver to recompute those digests from its expected messages and keys.

The `defer_out` result cannot be ignored. The upstream recursive verifier deliberately leaves one evaluation of the child's stacked bytecode polynomial unchecked in-circuit: a point and its claimed value. A proof that only calls `verify_sub` and then discards that result does not prove execution of the expected child program.

For the smallest sound first prototype, export both deferred point/value pairs in the wrapper statement. The outer receiver recomputes their values using the pinned leaf program and `Bytecode::evaluate`, reconstructs the exact wrapper public input, and verifies the wrapper proof. The wrapper's own program is checked by ordinary `cpu::verify`. No child proof verification is required at the receiver after this wrapper proof is accepted. The receiver still does two native bytecode polynomial evaluations; this first implementation is a correctness milestone and its verification cost must be measured as such.

Bind every deferred point and recomputed value into the wrapper public input, together with the child program identity and child public inputs. Do not merely perform a host check while proving an unrelated digest. When adding a sumcheck to reduce the two fresh bytecode claims to one, reuse the upstream transcript binding and terminal identity. Synthetic zero-point carried claims can be fixed explicitly for bare leaves that have no carried claim; they must not be accepted as unbound witness values.

This first stage is an actual proof of two custom proofs. It need not yet implement unbounded recursion, arbitrary scheme dispatch, set union or discards. Those features should have separate acceptance criteria.

## Stage 2: bounded fan-in and multiple levels

A multi-level aggregator must preserve two different things: the fresh bytecode claim raised while verifying each child proof, and every deferred claim that the child's statement already carries. They can concern different programs. An ETHFALCON leaf and an aggregation wrapper have different bytecode polynomials, even if their compiled bytecode happens to have the same padded length.

Two practical architectures are available:

1. **Programs specialized per level.** Fix the leaf program, compile a wrapper for it, then compile the next wrapper for that wrapper. This avoids a self-size fixed point initially. Carry one evaluation obligation per authorized program family/level, aggregate obligations against the same polynomial with the reused sumcheck, and discharge all remaining obligations natively at the root. The root verifier must pin the whole program chain. This gives a bounded-depth prototype with transparent growth in verification obligations.
2. **One self-recursive wrapper with a leaf branch.** Use an authorized program registry or fixed digest set for leaves and a fixed wrapper program identity. Verify leaf proofs and wrapper proofs through the appropriate structural verifier specializations. Carry and batch deferred claims separately for each bytecode polynomial. Reuse upstream `unified_guest`'s compile-to-size fixed point for the wrapper branch, while keeping its digest in the statement and pinning it at the outer verifier. This is the more reusable design, with a larger statement and soundness review surface.

Do not substitute a leaf program seed into the existing self-recursive `EthereumProof` statement without adapting the bytecode polynomial and carried-claim logic. The statement's program identity, Fiat-Shamir initialization, layout constants and final bytecode evaluation must agree throughout the tree.

Begin with a domain-separated ordered binary tree over child claims. Count equal public inputs as repeated verification work until a canonical dependency-set representation is implemented. EIP-8288-style union, deduplication, subset selection and discards require additional in-circuit coverage checks. They are not implied by proving that two child proofs are valid. The existing upstream signature-specific coverage construction is a reference for that later step.

## Implementation and validation estimate

Plan three implementation milestones: extract and differentially test generic hint/placeholder generation; implement and independently verify the two-child wrapper with all deferred evaluations discharged; then extend to repeated levels and canonical dependency semantics. The first milestone reuses several thousand lines of existing verifier DSL and substantial host machinery. Expect several engineer-days for a reviewed two-child prototype and further work for a reusable multi-level implementation; this is an engineering estimate, not a measured implementation or performance result.

Before reporting custom recursive timings, require all of the following:

- Valid proofs of two independent instances of the same leaf guest, with the final root verified in a fresh process that has no leaf signature witnesses.
- Native checked-verifier and in-VM verifier agreement on valid leaves, corrupted scalar streams, Merkle openings, public inputs and announced shapes.
- Rejection after changing a child program seed, claimed child public input, deferred point, deferred value, or sumcheck message. Test deferred data independently so an unrelated outer digest mismatch does not conceal a missing evaluation check.
- Correct behavior at opening-size limits, proof-stream capacity, configured fan-in and supported rates. Reproving padded small leaves must be included in the leaf cost.
- A three-level tree with distinct leaves, plus malformed carried obligations. The root must discharge every remaining program-family obligation.
- Explicit claim semantics and tests for duplicate children, order changes and dropped claims. Set union or discard functionality needs its own coverage tests before being advertised.

Measure leaf proving, wrapper witness preparation, recursive proving, final root verification, native deferred-evaluation work, statement bytes, proof bytes and process peak memory separately. Include failed capacity trials in the raw record. Until these milestones pass, large-count projections must retain an explicit assumed merge cost and must not be presented as measured aggregation throughput.
