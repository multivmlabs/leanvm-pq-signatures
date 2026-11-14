# Plan: signature choice behind leanVM aggregation

Status: implementation, benchmark collection and scoped validation complete, 3 November 2026. All primary, fan-in and leaf-size benchmark configurations finished successfully at 20:59 UTC. At 21:02 UTC the final suite passed (80 Python tests, zero skips; two plus six ordinary Rust checks), and the separately executed forged-bytecode control through two wrapper levels passed. The strengthened interleaved mixed-scheme proof and fresh public-only verification also passed; this is a single correctness demonstration, not a performance curve. Standard Dilithium baseline selected by the user: ML-DSA-44, FIPS 204. See [the article](../articles/leanvm-signature-aggregation.md), [methodology](../articles/leanvm-signature-aggregation-methodology.md), [review evidence](tree-encoding-review.md), [mixed-case evidence](../results/article/mixed/evidence.json), and [raw experiment records](../results/article/).

## Target

A short ethresearch article, about 1,200 to 1,500 words, with three figures, one architecture diagram and a small results table. Plain language, short paragraphs, no em dashes. Detailed parameters, test results and raw measurements go in a reproducibility appendix rather than the main text.

Question: can wallets choose the signature that suits their signing hardware or MPC protocol, while an off-chain service batches verification and the network receives a common hash-based proof?

Distinguish three operations throughout: native signature verification outside the VM; proving a direct batch inside leanVM; recursively proving verification of batch proofs. None alone supplies the EIP's canonical transaction-dependency integration.

## Scheme scope and existing evidence

| Article label | Completed implementation and measurements | Final validation |
|---|---|---|
| ethFalcon-512 | Native C/Python checks; corrected direct proofs; fixed six-to-one aggregate; primary trees, fan-in and leaf-size studies | Final suite and shared mixed-program/composition controls passed |
| Falcon-512, SHAKE | Standard C/Python fixtures, SHAKE guest, direct capacity measurements, primary trees and fan-in study | Final compatibility/constraint suite and mixed-program control passed; PR #490 remains a separate RISC-V reference |
| ethDilithium | Native C/Python checks; expanded-key guest, direct capacity measurements, primary trees and fan-in study | Final public-claim/constraint suite and mixed-program control passed |
| ML-DSA-44, SHAKE | FIPS 204 C/Python fixtures, SHAKE guest, direct capacity measurements, primary trees and fan-in study | Final FIPS/constraint suite and mixed-program control passed |
| Research FORS | Direct proofs at requested totals; padded multilevel trees, fan-in and leaf-size studies | Public-only mutation/final suite and mixed-program control passed; padding and bandwidth costs retained |

ML-DSA-44 is not round-3 Dilithium2. Both ETH and standard Dilithium-family guests use the same documented registered expanded-key model for a controlled comparison. This is not a claim that compact-key expansion is proved in the VM. Report the registration assumption and expanded-key bytes. A compact-key registration proof is a separate extension, with its own cost.

Falcon uses canonical expanded signature witnesses; compact signature decoding is performed by the host. Keep that boundary visible. PR #490's RISC-V guest has different parsing and execution boundaries, so its published numbers belong in related work, not a local speedup comparison.

FORS remains a standalone few-time research component, not SLH-DSA, leanSPHINCS or a security-equivalent substitute. Retain full upstream leanSPHINCS as a separately labelled reference. The current proofs are not zero knowledge.

## Implementation sequence

1. Freeze the existing data and source hashes. Preserve historical Falcon timings under their original stricter guest identity. Reuse corrected size observations and the existing 30-signature run with their actual sampling limitations.
2. Add standard SHAKE fixtures and guests on the same pinned custom ISA. Build C references with explicit `ETHFALCON=0` and `ETHDILITHIUM=0`; the latter defaults to one. Reuse arithmetic checks, but implement the correct SHAKE absorb/squeeze, domain separation, message framing and rejection sampling. Test block boundaries and independent vectors before proving.
3. Replace the fixed `aggregate-falcon` workflow with a deterministic tree plan supporting schemes, leaf capacity, fan-in, exact tail batches and trusted child programs. Do not pad a claim list by duplicating signatures. Support different child bytecode sizes through statically selected, namespaced verifier specializations. Keep vendor sources unchanged.
4. First implement a correct explicit-obligation tree: retain deferred evaluation points for every tree edge. At receipt, reconstruct expected leaf claims and every node statement bottom-up using trusted programs, evaluate all edge obligations and verify the root proof. Child proofs and signature witnesses remain unnecessary at receipt. Envelope bytes and native deferred work grow with tree edges, and the figures must show that cost.
5. Treat folding deferred claims as a later optimization. Folding must group claims by the exact trusted bytecode polynomial and bind inherited claims. Reusing a self-recursive helper under the wrong program identity is not acceptable. Do not present the explicit-obligation baseline as constant-cost arbitrary-depth recursion.

Gate before the large runs: all five schemes have a valid proved leaf within supported capacity, and a three-level tree passes independent statement and deferred-obligation checks. If a configuration exceeds capacity, record the failure; do not silently change the backend or draw an estimated successful curve.

## Benchmark matrix

Use the same M4 Pro, pinned build, rate=1, 32-byte messages, distinct keys/claims and deterministic public benchmark seeds where available. Run one prover process at a time on this 24 GiB machine. No parallel wall-time claim is inferred from sequential samples.

| Study | Configurations | Sampling |
|---|---|---|
| Native baseline | Sign/verify for the four lattice variants; FORS reference labelled separately | Calibrated repeated native checks, at least 1,000 verifications; sign/keygen measured separately; Python and C timings never conflated |
| Direct batch proofs | Five schemes; N=1 through 30 until the first measured capacity failure; FORS also N=70 and 100 | Reuse compatible existing proofs for sizes; one warmup and three timed proofs for new timing points |
| Main recursive curves | Five schemes x N={10,30,70,100}, fan-in four | 20 end-to-end cases; three complete timed runs after setup/warmup, unless a recorded capacity failure prevents proving |
| Fan-in sensitivity | The same five schemes and four totals, fan-ins two and eight | 40 additional layouts; reuse independently verified leaf proofs and time all merge work three times |
| Leaf-size sensitivity | ETHFALCON at N=100, leaf sizes {1,2,4,5}; FORS leaf size 16 versus primary size five | Fan-in four; report partial tails and padded witness cost |

Initial leaf capacities: ethFalcon five; ethDilithium one; FORS five with `min_log_committed=22`, charging padding. This gives actual recursive FORS trees even at N=10. Establish standard Falcon and ML-DSA capacities by measurement before fixing their plans. A FORS size-16 sensitivity can have no merge at N=10; label that explicitly. Direct FORS at these totals may be better than recursion.

Reuse the same signature records across layouts. Proof-cache reuse is appropriate for merge-only measurements, but never report it as a fresh end-to-end proof run. Keep the existing flat six-child, 30-signature result as a reference rather than relabelling it as a four-ary tree result.

Capture per run and per node: signature/leaf/merge counts, depth, program hashes, padded bytecode sizes, witness sizes, VM cycles, proof rate, preparation time, proof time, serialization time, complete process wall time, peak RSS, root core bytes, complete envelope bytes, manifest/key/message bytes and raw signature bytes. Verification reports include program preparation, deferred work, proof checking and cold/cached totals separately.

## Correctness checks

Compare valid signatures and canonical codecs with pinned native implementations. Reject changed messages, keys, norms, samplers, hints and arithmetic advice, including cross-variant signatures with recomputed public inputs. Exercise SHAKE block boundaries and multi-block output.

For trees, test mixed child programs, different bytecode sizes, incomplete groups, exact ordering/counts, duplicate and missing claims, wrong program pins, full 192-bit field encoding, changed child proof advice, and inherited deferred points at lower levels. Extend the existing forged-bytecode boundary control through multiple levels. Final verification must work in a fresh process with only intended public claims, trusted code/plan and the root envelope.

## Figures and wallet study

1. Direct batches: proof bytes and proving time against signature count, with measured capacity failures marked. Show unsupported ranges as gaps. No fitted curve across missing data.
2. Recursive trees: total proving work, complete root-envelope bytes and final verification time at N=10,30,70,100. Separate core and auxiliary bytes and show raw-signature/direct-batch baselines. Plot measured points with sample variation.
3. Efficiency: fan-in and leaf-size tradeoffs in merge work, peak memory and amortized prover work/bytes per signature. Keep secondary configurations in the appendix if the main figure becomes crowded.

Export PNG and SVG plus the underlying CSV/JSON. Use ordinary scientific plotting tools and inspect the rendered figures. Keep all old/new guest identities and hardware differences explicit.

Architecture: wallet or MPC participants sign the canonical transaction digest; the wallet sends transaction data, signature and authenticated key identity to an off-chain aggregator; the aggregator checks and batches witnesses; builders merge proofs; receivers derive the required dependency claims from transactions/account policy and verify the aggregate. Secret signing keys never leave the signers.

The browser/phone study compares signing-only responsibility with local proving responsibility using measured host time, memory and upload bytes, plus cited constrained-device and threshold-signing research. Do not describe desktop results as phone benchmarks or invent battery measurements. Standard-signature support can preserve compatibility with existing threshold or hardware implementations; the ETH hash variants do not inherit that support automatically.

Separate shared prover cost from protocol gas. Report prover work per signature and possible service-fee allocation as a model. Under the current draft, fixed dependency tariffs do not automatically decrease because signatures share a proof. A pooled or computation-weighted tariff is a proposal, not an experimental gas result. Include availability/censorship, witness visibility and fallback considerations briefly.

## Article order and conclusion

Use the user's requested order: motivation and references; a few sentences on the signature choices and implementation; tree design and parameters; wallet/aggregator architecture; figures and measured results; limits and EIP changes. Aim for two short introductory paragraphs and a compact discussion rather than a broad survey.

Connect directly to zsfelfoldi's 1 November forum reply #14. It proposes same-verifier batches that prove several individual dependencies, rather than requiring one proof per signature or enshrining each signature scheme. Our existing ordered batch digest is not that interface yet: the proposed integration must authenticate the complete per-item dependency list, the verifier identity, transaction-derived messages and account-authorized keys. Discuss batch statement encoding, verifier-code availability, invalid-witness admission costs, resource limits and fee allocation.

The supplied URL points to #13, which discusses hiding ECDSA/EdDSA behind STARKs. Link it accurately if relevant, but do not adopt the claim that wrapping a classical signature automatically gives post-quantum unforgeability. Current EIP-8288 already requires mode-1 transaction/dependency equality; do not present the older missing-equality objection as still unaddressed. Generic scheme 0x11 and protocol constants remain unfinished. Current EIP-8141 ARBITRARY signature bytes are introspectable, so that route alone does not supply future witness elision.

Deliver the article, figure sources and exports, reproducible benchmark commands, machine-readable results and a short correctness appendix. No forum post or external publication without an explicit request.

## Initial primary references

- [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) and [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288): draft integration and current accounting rules.
- [Generic batching proposal, reply #14](https://ethereum-magicians.org/t/eip-8288-frame-type-for-pq-sig-and-stark-aggregation/28723/14); [requested reply #13](https://ethereum-magicians.org/t/eip-8288-frame-type-for-pq-sig-and-stark-aggregation/28723/13).
- [Recursive mempool proposal](https://ethresear.ch/t/recursive-stark-based-bandwidth-efficient-mempool/23838) and [signature merging](https://ethresear.ch/t/signature-merging-for-large-scale-consensus/17386).
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): ML-DSA specification and exact naming.
- [Efficient Threshold ML-DSA](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_celi.pdf) and [Thresholdizing Standardized FALCON Signatures](https://eprint.iacr.org/2026/1300): feasibility of signing compatible with standard verifiers, not evidence of audited wallet deployments.
- [ZKNOX-HW-FALCON](https://github.com/ZKNoxHQ/ZKNOX-HW-FALCON) and [ZKN-PRIVACYHW](https://github.com/ZKNoxHQ/ZKN-PRIVACYHW): concrete hardware prototypes with their stated development/security limitations; do not present host timing tables as device measurements.
- [leanVM PR #490](https://github.com/leanEthereum/leanVM/pull/490): related standard-Falcon implementation on a different VM branch.
