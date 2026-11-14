# Methods and reproducibility

The main article is [Signature choice behind leanVM aggregation](leanvm-signature-aggregation.md). The implementation plan is [docs/ethresearch-article-plan.md](../docs/ethresearch-article-plan.md). These experiments use actual leanVM execution proofs, not host verification receipts or summed proof bundles.

## Machine and source identity

Measurements run sequentially on Apple M4 Pro, 24 GiB RAM and 12 logical CPUs, macOS 26.3, Rust 1.99.0. The release configuration uses `target-cpu=native`, upstream jemalloc and the default thread pool. Only one prover process runs at a time. Thermal state and background activity are not controlled. Report observed medians/ranges, not confidence intervals or cross-platform claims.

Pins are in [upstream.lock.json](../upstream.lock.json): leanVM `575df819d9c857f38068cecf7b1640e0ce4bfb29`, ETHFALCON `43ac863e30281bb7821748178d39967367d54bc2`, ETHDILITHIUM `f9f4fe1d84e68304b425e054c273c276fe44ba11`. Vendor checkouts remain unchanged. This is the custom leanISA pin, separate from PR #490's RISC-V branch. Proof inverse-rate logarithm is one. The proofs are not zero knowledge.

The [initial environment snapshot](../results/article/environment.json) is preserved. The [final provenance snapshot](../results/article/environment-final.json) links its SHA-256 to final source and validation-artifact hashes, rather than overwriting the original record.

The pinned [WHIR configuration](https://github.com/leanEthereum/leanVM/blob/575df819d9c857f38068cecf7b1640e0ce4bfb29/crates/pcs/src/whir_config.rs) targets `SECURITY_BITS=128` round-by-round soundness over F192, with rate 1/2 (`log_inv_rate=1`), `QUERY_GRINDING_BITS=17`, and folding-variable counts six initially and four subsequently. No settings were weakened for these experiments. These are source configuration targets, not a claim of 128-bit post-quantum security or a formal soundness proof for the full backend and application.

The trusted public frontend regenerates source and derives leaf statements from actual public keys and 32-byte messages. Saved advisory claim hashes, public-input fields or sources supplied with a proof are not trusted. The tree plan binds order, signature counts, exact tails, leaf program identities, commitment floors and topology. The receiver verifies under the resulting trusted plan hash.

Merge wrapper code bakes in the complete global plan hash, including expected leaf statements. These are static bounded experiments. Leaf proofs can be reused under matching leaf identities/claims; previously produced merge subtrees are not reusable across a changing mempool or a different global plan. An online union/discard interface requires another design and benchmark.

## Relations and expanded-key assumptions

| Label | Relation | Guest witness / key model | Native baseline |
|---|---|---|---|
| ethFalcon-512 | Keccak counter hash-to-point; n=512, q=12289, squared norm bound 34034726 | Expanded s2; canonical LE16(h) commitment | Pinned C, `ETHFALCON=1` |
| Falcon-512 | Round-3 SHAKE256 hash-to-point; same arithmetic | Same expanded witness and commitment model | Same pinned C, explicit `ETHFALCON=0` |
| ethDilithium | ML-DSA-44-derived Keccak stream variant | Expanded matrix/vector/tr commitment, 81,984-byte encoding | Pinned C, `DILITHIUM_MODE=2`, `ETHDILITHIUM=1` |
| ML-DSA-44 | FIPS 204 SHAKE variant, pure signing with empty context | Same expanded-key relation | Same pinned C, explicit `ETHDILITHIUM=0` |
| Research FORS | Keccak few-time component, n=32, k=16, a=8 | 64-byte public key, 4,608-byte signature | Python reference with PyCryptodome; not native C |

`ETHDILITHIUM` defaults to one in the vendored source. Omitting the macro does not select standard SHAKE. The standard and ETH native libraries use separate fingerprints. Source namespaces retain Dilithium2, but tr=64 bytes, secret key=2560 bytes and context framing are ML-DSA-era behavior. Round-3 Dilithium2 is a different target and is not measured here.

For Falcon, compact key/signature decoding is done by the host. The guest checks canonical coefficient ranges, standard or ETH hash-to-point, the full ring product and both complete squared norms. It establishes existence of an expanded valid signature, not a commitment to one particular compressed byte string. The standard hash-to-point stream is capped at 1,280 bytes and rejects exhaustion. ETH uses 40 counter blocks of 32 bytes. A cap can reject an exceptionally unlikely valid signature; it cannot justify accepting an invalid relation.

The Dilithium-family guest verifies an expanded-key relation. The receiver must derive that identity from its independently authorized compact key or trust an appropriately validated registration. The public-only frontend implements the first option: it derives the matrix, scaled transformed public vector and tr outside the VM before constructing the expected public input. Its native expansion cost is recorded separately in public-claim derivation timing. Registration is optional, and caching derived identities is another receiver optimization. Compact-key expansion remains unproved inside the guest; a wholly in-VM verifier would additionally prove rho-to-matrix expansion, scaled public-vector transformation and tr derivation. Fixed 32-byte messages and empty ML-DSA context define the measured interface; HashML-DSA and other contexts are separate relations.

The 81,984-byte expanded encoding is internal witness material, not a mandatory wallet upload. The aggregator can derive it from a 1,312-byte compact key; a wallet can send that compact key, a 2,420-byte signature and its 32-byte message, plus transaction/framing overhead. Key caching or validated registration can reduce repeated key transport. The main article's Falcon signature/proof upload ratio likewise counts only the signature or proof payload; shared keys, messages and transactions are additional in both cases.

Standalone FORS is not a full unlimited-use signature scheme, leanSPHINCS or FIPS 205 SLH-DSA. Its deterministic 128-bit index mapping admits a generic chosen-message birthday strategy around 2^64 hashes. Do not interpret its speed as a security-equivalent wallet replacement. The earlier full leanSPHINCS measurements remain separately labelled in [results/COMPARISON.md](../results/COMPARISON.md).

## Timing scopes

Direct proof reports contain one warmup and three timed proofs. Rust `prove_s` includes VM execution, the backend's STARK-witness construction and proving. Python fixture preparation is performed and cached before these runs: compact decoding, key expansion and Recorder arithmetic-advice generation are excluded. Compilation, serialization, native proof verification and key generation are also excluded. Thus these are prover-pipeline timings from prepared witness streams, not wallet-submission-to-proof latency. Existing `metadata.fixture_generation_s` values are preparation references, not fresh preparation measurements repeated with each proof. Size is the actual serialized payload, with no fitted growth model. The first measured capacity failure stops larger lattice direct batches; only that attempted count is recorded as a measured failure.

The [preparation reference archive](../results/article/preparation-reference.json) extracts those historical setup timings, deduplicates the actual tree leaf fixtures used across layouts, and retains separately recorded per-pass merge-advice preparation. It runs no new timers or provers and copies no witness streams. Original Python setup may predate later host optimizations; do not add it to each timed proof sample as if repeated afresh.

Main fan-in-four trees use three separate fresh leaf-and-merge proving runs after setup/warmup, starting from prepared inputs. Every measured run creates new leaf proofs and all merge proofs. The plot's prover-work value sums each leaf's `prove_s` and every node's `prove_s` in that run. These are measured elapsed proving intervals, not CPU core-seconds. `pipeline_elapsed_s` and `experiment_process_elapsed_s` remain separate fields. The latter additionally captures process startup and Rust host orchestration, but excludes earlier Python `make_manifest`/`build` and fixture/advice preparation. “Fresh pipeline” therefore denotes fresh proof generation from prepared streams, not a full wallet-to-proof latency. Neither metric equals distributed elapsed time.

The draft's `AGGREGATION_INTERVAL=1000 ms` specifies broadcast cadence, rather than an experimentally demonstrated proof-completion deadline. Sequential prepared-input prover work does not measure a distributed pipeline's latency or wallet-submission-to-proof latency. These experiments demonstrate no one-second wallet-to-proof service; they also do not establish that a pipelined distributed service would take the full sequential work sum as elapsed latency.

Fan-in-two/eight sensitivity repeats all merge work three times after warmup with independently checked reusable leaves. A cached leaf's original measured work is retained in CSV, but is not called freshly performed end-to-end work. Fan-in-four merge-only controls provide the matched memory comparison when present. Leaf-size sensitivity uses exact groups; commitment padding is charged, including the minimum log-commitment floor of 22 for recursive children. A singleton carried to the next tree level creates no unnecessary merge proof.

The complete aggregated proof includes the root STARK, deferred points for every edge and serialization metadata. No receiver needs child proof files or signature witnesses. The native receiver evaluates all edge obligations using trusted bytecode and reconstructs the root statement. Auxiliary bytes and evaluation work are O(E). Shared program source, intended public claims, transactions, registration and transport framing are additional. A bare core proof under a prover-selected statement is insufficient.

Verification plots use fresh-process reports when available. Cold operation time is `compile_plan_s + deferred_bytecode_prepare_s + median(deferred_evaluation_s) + median(root_core_verify_cold_s)`. Cached operation time is the median edge evaluation plus median cached root-core verification. It applies only to rechecking the identical static plan. New claims or totals change wrapper code and its bytecode tables, requiring cold preparation; cached latency is not new-block verification latency. The cold core already includes root bytecode preparation; do not add `root_bytecode_prepare_s` a second time. The timer excludes Python public-claim derivation, preliminary frontend compilation, CLI loading and deserialization. `public_claim_derivation_s` is recorded separately. `public_receiver_process_s` includes frontend inspect and timing repetitions; neither it nor `verification_operation_total_s` is a single-request latency.

Figure 2D pairs `public_claim_derivation_s` with the preparation-inclusive proof-verification time from the same fresh verification report, for Falcon-512, ML-DSA-44 and research FORS at 10, 30, 70 and 100 signatures with fan-in four. All 12 bars use three measured paired runs each. For each run, the two measured phases sum to the combined time. The total bar height is the median of those paired sums, and its two segments come from the corresponding run; for an even-sized incomplete sample, average the two middle runs component by component. Whiskers show the minimum and maximum paired totals. This avoids adding component medians from different runs and presenting the sum as an observed median total. The [phase CSV](../results/article/figures/verification-phases.csv) retains all 36 paired samples and their source reports. These times are measurements, not extrapolations; “expected” in the verifier interface describes the intended public statement, not a predicted runtime.

The first timer includes public-record loading, authorized leaf-source/manifest preparation and expected key/message commitment derivation, including Dilithium compact-key expansion in the Python frontend. It is not an isolated hash benchmark. The second includes Rust plan compilation, deferred-bytecode table preparation, all-edge evaluation and one root-STARK verification operation. Their combined total excludes additional frontend `inspect` work, subprocess startup, proof loading/deserialization and other orchestration outside those two timers. It is not a separately measured end-to-end node-validation latency.

A separate [ML-DSA commitment diagnostic](../results/article/mldsa-commitment-diagnostic.json) profiles `key_identity` for ten distinct saved public keys in an isolated process, with its key-identity and coefficient caches initially cleared. About 90% of profiled key-identity time is spent converting the 5,120 coefficients per key into the guest's binary-field encoding; compact-key expansion accounts for about 6%. This profile excludes source regeneration and other manifest work in the full derivation timer. The frontend regenerates the same one-signature source for each ML-DSA leaf, adding overhead to that broader timer. Profiler instrumentation changes runtime, so this diagnostic does not replace the original figure timings. The plotted measurements and phase CSV remain unchanged.

RSS is whole-process peak resident memory. It includes warmups and any fresh leaves generated in that process. It is not per-node memory and cannot be multiplied by thread count to infer concurrency requirements.

Native verification uses three groups of 1,000 calls on one saved key/message/signature per scheme. This is an input-conditioned baseline, not a many-key timing distribution. C timings include the ctypes call and compact decoding. Falcon output buffers are preallocated. FORS remains a separately labelled Python/PyCryptodome reference. Keygen and signing timing fields use 30 fresh samples per lattice variant and are separate from verification and proving. Desktop signing timings do not characterize secure-element latency, MPC round complexity or phone energy use.

| Signature scheme | Median native C verification, µs |
|---|---:|
| ethFalcon-512 | 13.65 |
| Falcon-512, SHAKE | 9.56 |
| ethDilithium | 99.06 |
| ML-DSA-44 | 37.02 |

These timings measure ordinary signature verification on the CPU, separately from STARK verification. They do not predict Ethereum gas costs or STARK proving times.

## Correctness evidence

The [encoding review](../docs/encoding-review.md) and [recursive aggregation review](../docs/recursive-envelope-review.md) document prior checks and their limits. Standard Falcon additionally checks upstream standard KATs against pinned C and an independent schoolbook equation; reciprocal ETH/standard rejection; deterministic fixture replay; SHAKE128/256 empty, absorption, padding and squeezing boundaries; byte ranges; samplers; modular advice; changed messages with recomputed public commitments; and a fully recomputed false zero-signature witness rejected by the norm constraint. An isolated terminal-coordinate test constructs otherwise valid pairs with only s1[511] nonzero, accepting 5832 and rejecting 5833 after recomputing every witness and public commitment. The false pair supplies the malicious complement that would satisfy a sum omitting that last coordinate, so the test specifically detects terminal omission.

The standard SHAKE helpers constrain all absorbed bytes and all extracted words. Explicit SHAKE padding uses 0x1f and the final 0x80 bit, with rates 136 and 168 bytes. Tests cover the VM's packed-state gap after byte 135, so SHAKE128 cannot accidentally treat a capacity lane as output. No new Keccak opcode or vendor constraint was introduced.

The ML-DSA suite adds 12 tests, including 15 pinned FIPS 204 ACVP internal sigVer vectors checked with C and Python, the external pure-signature empty-context guest, the bounded 136-byte challenge stream with 128 candidate bytes, and reciprocal ETH/standard adversarial guest checks. The [multi-level tree encoding review](../docs/tree-encoding-review.md) covers the newer tree construction in addition to the earlier fixed-arity aggregation format.

The tree tests cover trusted plan/program identity, full field encoding, exact counts and order, lower-level inherited obligations and verification with public claims only. A scoped passing test suite is not a formal proof of the entire compiler, memory bus, Keccak GKR, Fiat-Shamir transform or polynomial commitment scheme.

Final validation passed 80 Python tests with receipt controls enabled and eight ordinary Rust tests. The separately run forged-bytecode control through two recursive wrappers also passed. Formatting and release Clippy with warnings denied passed. See the [validation log](../results/article/validation.log), [two-wrapper control log](../results/article/validation/forged-two-level.log) and [Clippy log](../results/article/validation/clippy.log).

The [validation summary](../results/article/validation/summary.json) records these checks. The [matrix integrity report](../results/article/matrix-integrity.json) confirms 45 successful direct configurations, four measured direct capacity failures, 60 primary fresh pipelines, 21 sensitivity fresh pipelines and 180 cached-leaf merge passes, with public-only fresh verification for every report.

A separate [mixed-family correctness case](../results/article/mixed/evidence.json) proves two claims from each of the five families, using ten one-signature leaves, four merges and 13 edges. Interleaving forces the first two parents to handle child bytecode logarithms 13 and 18, and the root to handle logarithms 18 and 19. Fresh verification succeeds with all leaf witness paths absent, using independently authorized source pins and public key/message claims. This is one correctness case, not a performance curve, topology optimum or gas measurement. Its aggregated proof is 357,300 bytes, including a 350,416-byte core; 39 source/report/artifact hashes are checked in the evidence.

## EIP integration boundary

The checked EIP-8288 draft sets `MAX_LEANSTARK_DEPS_PER_WRAPPER=1` and `MAX_LEANSIG_DEPS_PER_WRAPPER=16`; generic scheme 0x11 also remains reserved. A same-verifier batch that produces many individual proven dependencies therefore needs revised wrapper/admission limits and specified generic semantics. Its public statement must preserve the per-item claims and verifier identity required by the transactions. Counting 30 unrelated transaction claims as one opaque dependency would change the authorization/accounting interface rather than implement the proposed per-item batch interface.

A possible extension would define a stable canonical batch statement, verifier-code availability and admission budgets measured in verified items, witness bytes and VM cycles. Resource limits and invalid-witness admission costs would need specification and measurement. Allocating one aggregator's shared proving cost among participating claims is a service-fee model, separate from the draft's fixed per-dependency protocol tariffs. The experiment neither measures EVM gas from desktop CPU timings nor proposes treating all items in a batch as one tariff unit.

For scale, the draft's dependency-verification tariff constants are 3,000 gas for leanSPHINCS and 30,000 for leanSTARK. If generic per-item dependencies were enabled while retaining the latter tariff, 30 items would nominally contribute `30 * 30000 = 900000` gas to that component alone. The draft also has a separate recursive-header intrinsic component; frame and transaction charges are additional. This is a hypothetical tariff calculation, not measured gas, and current scheme 0x11 dependencies remain invalid until their semantics are defined. Shared proving does not by itself replace 30 individual authorizations with one tariff unit.

## Commands and files

```sh
make setup
make build
PYTHONPATH=python .venv/bin/python scripts/article_bench.py native
PYTHONPATH=python .venv/bin/python scripts/article_bench.py direct
PYTHONPATH=python .venv/bin/python scripts/article_bench.py trees
PYTHONPATH=python .venv/bin/python scripts/article_bench.py sensitivity
make article-figures
make test
```

Use the benchmark script's `--schemes`, `--counts`, `--fan-ins`, `--repeat` and `--warmup` arguments for a subset. Saved reports make the script resumable. Existing success files are checked for verification status; use a new results/artifact location or explicitly remove the intended generated subset for an independent rerun. Do not delete the old studies when producing a new one.

Actual measurements live under `results/article/direct`, `results/article/trees` and `results/article/native.json`. Figures and underlying CSV/JSON are written to `results/article/figures`. `measurements.json` records every loaded report's SHA-256. `--allow-incomplete` produces a partial preview and explicit missing-data warnings. Strict final rendering requires the full direct, native, primary tree, matched fan-in and leaf-size sensitivity matrix, including three fresh prepared-input proof runs and three all-leaves-reused merge passes where applicable. An actual recorded configuration failure, including a failed warmup, is retained as a documented gap rather than replaced by an estimate.

Exact public benchmark inputs, including compact signatures, are archived under [results/article/inputs](../results/article/inputs), with SHA-256 checksums. The generator can replay these archives when the ignored artifact cache is absent, including the originally randomized Dilithium datasets. No secret keys are archived. This reproduces the original claims rather than generating a new random dataset with the same count.

Historical Falcon timing rows preceded removal of an erroneous 625-byte payload policy and retain their old guest hashes. They must not be relabelled as measurements of the corrected guest. Earlier size-growth data contain one proof per count; those observations are not repeated timing samples. The old flat six-to-one 30-signature experiment is also a different topology from a four-ary tree and remains its own reference.

## Separately published RISC-V Falcon measurements

[leanVM PR #490](https://github.com/leanEthereum/leanVM/pull/490), head `354f7ef2d4a4fee2b9fc3300f93dbc00ec23f7ab`, merged into `riscv-exploration` on 5 October 2026. Its standard round-3 Falcon-512 guest decodes compact keys and a padded compressed signature body inside a RISC-V VM. The PR publishes these measurements on AMD 9950X3D with 32 threads:

| Signatures | Proving time | Proof size | Verification | Peak RSS |
|---:|---:|---:|---:|---:|
| 7 | 0.468 s ±3.9% | 318.0 KiB | 3.36 ms | 3.1 GiB |
| 28 | 1.902 s ±0.8% | 355.5 KiB | 3.33 ms | 10.8 GiB |

The workload reports approximately 146,664 RISC-V cycles per signature. A separate four-thread, seven-signature measurement reports 0.737 seconds ±6.1%. The variation labels above are the PR's published labels; they are not confidence intervals computed by this project.

These are attributed upstream results, not locally reproduced data or points on our custom-ISA figures. The ISA, guest codecs, claim encoding, signature formatting, hardware and thread counts differ. The local six-signature standard-Falcon direct capacity and much larger tree work therefore do not establish a general limit or state-of-the-art performance for leanVM. A controlled implementation comparison would require matching those boundaries on one machine and build configuration.

The curated primary-source numbers are archived in [upstream-pr490.json](../results/article/related/upstream-pr490.json).

## Compatibility motivation versus tested interoperability

The threshold-Falcon paper's [signing interface](https://github.com/radhika1601/threshold-falcon/blob/master/our_impl/sign.h) and [reference hash-to-point](https://github.com/radhika1601/threshold-falcon/blob/master/falcon_ref/common.c) use the Falcon round-3 reference family: SHAKE256 of the 40-byte nonce followed by the message, read as big-endian 16-bit samples accepted below 61,445. That matches the point relation used by our standard Falcon guest, rather than FN-DSA's different message framing. The hardware-Falcon README likewise explicitly selects its round-3 adapter with `FNDSA_FALCON_R3=1`; its raw s2 can be compressed by the host. These checks motivate compatibility but do not constitute an interoperability test: no signatures from those MPC or device implementations were run through this project's guest. The DILITHIUM application name in the separate hardware proof of concept also does not establish the exact FIPS 204 ML-DSA-44 version used here.

## Aerie extension, 4 November 2026

The [Aerie feasibility study](aerie-under-leanvm.md) adds native Falcon-v1.2 aggregation and a constrained leanVM arithmetic probe. The original 3 November signature datasets, direct/tree reports and three figures are unchanged. The main article now also includes the Aerie table and Figure 4. The original article/manifest snapshot is preserved separately; the current deliverable manifests record the expanded documents.

Native runs use Aerie `49b6c212c209286c536196f53618823ffdf0e899`, the unchanged upstream lockfile and benchmark harness, 1/12 Rayon workers, one warmup and three proof roundtrips for each live count 1/10/30/70/100/1024/8192/32768. These are native Aerie proofs, not leanVM proofs. Native one-thread summary curves use the one-worker process; the upstream dedicated one-thread recheck in the twelve-worker process remains in the raw reports and can differ slightly. The [native guide](../docs/aerie-native-benchmarks.md) gives exact setup, parsing, stage-timer, RSS and dependency boundaries.

The separate public-verifier controls and verifier-only consumer use all shared package versions and source revisions from the upstream lock. Eight mutations reject; a fresh scalar consumer accepts without signer, prover or signature-witness dependencies. Their [dependency provenance](../results/aerie/native/dependency-provenance.json) and [harness provenance](../results/aerie/native/harness-provenance.json) retain the exact final hashes. An earlier external dependency resolution is preserved under the ignored artifact directory, separately from the final aligned controls.

The leanVM probe enforces multiplication modulo `2^64-59`, including canonical residues and both carry chains. Counts 1/8/64/256 each have one warmup and three measured proofs at rate one, with every saved proof freshly verified under independently regenerated source/public-input pins and empty witnesses. It includes one Keccak binding step per product and is not an Aerie verifier or an estimate of complete verifier capacity. See [the arithmetic review](../docs/aerie-kernel-review.md) and [measured kernels](../results/aerie/kernels/summary.json).

The final project suite passed all 90 Python tests with real receipt controls enabled, plus the ordinary Rust tests; its [new log](../results/aerie/validation.log) preserves the prior 80-test log. The complete Aerie verifier has not been ported or proved in leanVM. Its wrapped proof size and end-to-end proving/verification costs remain unmeasured.
