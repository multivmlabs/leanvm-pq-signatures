# Aerie wrapper review

This is a scoped review of the wrapper relation, its receiver, and the single-thread Rust runtime adaptation. It uses the zkVM security review skill at `/Users/manuelbsantos/.codex/skills/zkvm-security-review/SKILL.md`. It is not a new cryptanalysis of Aerie or Akita, nor an audit of the leanVM proof system.

Final execution review: 4 November 2026. Aerie is pinned to `49b6c212c209286c536196f53618823ffdf0e899`, Akita to `e023b6a46143f7b23199ccecb2684192baf7b640`, Jolt to `c7c2d08d5bb0c7c80501f29f723e595af7fcff3c`, Spongefish to `ef9741346a150039427d9e0c02d6b2d73e93ec81`, and leanVM RV64IM to `06e5c9cd6981103786f9d0a17324241b559a50d3`. The Aerie and RV64IM vendor worktrees were clean during this review. The runtime, selected-schedule adapter and Q64 cache extension live in owned overlays outside those vendor worktrees.

## Intended claim

For the exact trusted guest ELF and an intended ordered canonical statement of public keys and messages, the outer proof establishes that the unchanged Aerie verifier accepted an aggregate for that statement, count, and pinned profile. Prover-controlled advice contains only the framed statement and inner Aerie proof. It does not contain an acceptance bit, trusted setup, or precomputed verifier equations.

| Boundary | Required enforcement |
|---|---|
| Advice length and packing | Guest bounds byte length before reading, checks final word padding, and parses an exact frame. |
| Public statement | Guest performs canonical parsing and requires the canonical count to equal the frame count. |
| Aerie proof | `verify_aggregate` checks proof version/count, hashes the supplied public keys and messages with the proof's salts, reconstructs public targets, and runs all PIOP and PCS checks. |
| Inner transcript | The PIOP transcript must complete. Akita `VerifierGrinding::finish` calls the fail-closed channel's EOF check after checking its replay state. |
| Public output | Guest commits the domain/profile/count/statement digest only after successful full verification. |
| Receiver | Derives the expected SDK output from its independently supplied intended statement and count, then calls full `Program::verify`. |
| Program trust | Receiver requires an independently configured ELF SHA-256 and loads that exact ELF. leanVM additionally binds decoded code, memory image, and region sizes into its program digest. |

The caller still has to reconstruct the intended ordered statement from the transactions and account public keys it intends to authorize. The wrapper does not itself implement Ethereum transaction execution, account authorization, or replay prevention. Receivers need the public statement or enough transaction data to reconstruct it. They do not need the original signatures, salts, frame, or inner Aerie proof.

## Runtime adaptation

The runtime supplies allocation, in-memory I/O, single-hart synchronization, paths used by generic serialization code, and unavailable OS interfaces. The verifier's arithmetic, hash functions, transcript schedule, decoding predicates, and PCS equations are not replaced.

`HashMap` is provided by hashbrown. In the production Aerie/Akita verifier source subset inspected, its only application use is three memoization maps in `akita-params/src/sis/onehot_source.rs`. They use lookup and insertion, and do not feed map iteration into transcript encodings. Changing the table's hash seed or bucket order therefore does not change these computations. This conclusion does not automatically extend to newly enabled crates or features.

`Arc` uses `Rc`, and atomics use ordinary single-hart cells. Locks reject reentrant acquisition rather than returning aliased mutable references. This relies on the actual VM having one execution thread, no interrupts, and no thread-spawn syscall. These types are not suitable as a general standard library for concurrent native programs. The build wrapper injects them only into RV64IM consumer crates. `RwLock` currently has exclusive read guards, so it can reject nested read locking that standard Rust would allow; no such use was found on the inspected verifier path. This is a completeness risk if future dependencies add that pattern, not evidence of false-proof acceptance.

`Instant` produces zero elapsed time. The inspected Aerie uses are staging and total-time metrics; no signature or proof predicate depends on these values. Timings reported by the benchmark host use its real clock. `SystemTime` exists for generic standard-library compatibility and is not a source of verifier challenges. `catch_unwind` cannot recover from a guest panic; the SDK panic handler executes an illegal instruction, so a panic cannot yield a successful proof.

Floating-point compatibility methods delegate to libm. The integer-power methods use the same `core::intrinsics::powif64` and `powif32` operations as standard Rust. This matters because Akita's parameter checks use `2f64.powi(lambda_exponent)` in conservative security bounds. That source expression is unchanged. These compatibility helpers and their dependency versions belong in the build closure; actual catalog admission and guest verification still need positive interoperability controls.

The final I/O direction is a reexport of Rust's in-memory `alloc::io`, rather than custom decoding shortcuts. Canonical scalar decoding still uses `read_exact`. Aerie's final PCS length must equal the exact remaining input. Akita's verifier channel remembers any failed receipt and rejects both poisoned state and trailing transcript bytes. The wrapper and setup decoders also require exact consumption.

The custom entropy callback returns `getrandom::Error::UNSUPPORTED`. It does not supply zero bytes as successful cryptographic randomness. The ordinary Aerie verifier obtains challenges from the Fiat-Shamir transcript and does not require operating-system entropy. Any newly introduced entropy-dependent path must continue to fail closed.

The inspected local dependency diffs redirect tracing/once_cell synchronization to the single-hart types, import the floating-point compatibility trait for generic rand code, and convert unavailable raw OS errors into in-memory I/O errors. They do not turn entropy errors into success or change cryptographic verifier equations. Copied packages and their exact diffs must remain included in the source closure, rather than being represented only by upstream package revisions.

The `ffi` and `path` compatibility types preserve arbitrary Unix bytes, including invalid UTF-8 and embedded zero bytes. UTF-8 conversion remains fallible. These are generic serialization containers, not filesystem access. An isolated native test checked their byte-preserving owned, borrowed, and boxed conversions.

## Immutable public setup variant

Only native-validated public setup bytes compiled with `include_bytes!` can use `Validate::No`. They are initial program data authenticated by the trusted ELF and leanVM program digest. No advice-selected setup or setup hash is accepted.

The guest must select the fixed bank by its checked count, require exact decoding, match `max_num_vars`, `max_num_batched_polys`, matrix element count and fixed seed, require an empty prefix registry, and call public `FalconVerifierSetup::from_derived_setup`. This skips repeated expansion of a fixed public matrix. It does not skip terminal preparation, Fiat-Shamir challenges, PIOP checks, or Akita opening verification.

The supported test counts use three distinct setup blobs: counts 1/10, count 30, and counts 70/100. Count 30 and counts 70/100 have the same matrix payload but different descriptor bounds and schedule selections. Their complete serialized setups must not be silently interchanged. The compiled bank should reject other counts unless a separately checked descriptor/shape mapping is added.

All five exported setups passed native exact validated decoding and then the full unchanged verifier against existing real Aerie proofs after trusted import. See `results/aerie-wrapper/public-setup.json` and `results/aerie-wrapper/public-setup-import-checks.json`. This validates native interoperability, not compiled guest execution or an outer proof. The existing prepared terminal-cache exporter is Q128-only and rejects Aerie's FP64 field, so this port must not substitute that artifact.

## Q64 terminal-cache extension

The owned Akita overlay extends the pinned Q128 artifact interface with a distinct scalar Q64 target. The reviewed patch is `results/aerie-wrapper/akita-q64-cache.patch`, SHA-256 `ee37dd9dad5aafda9f951eea3e325f6c1f4d0429b74e7b5c20bc0f1a8df5ab73`; the upstream and modified source hashes are in `results/aerie-wrapper/akita-q64-cache-overlay.json`. It changes five files without modifying upstream vendor checkouts.

The extension uses `Q64_NUM_PRIMES` consistently for transforms, payload sizing and decoding, retains the Q128 tag and adds a separate Q64 tag, and selects the decoder from the protocol field. It recomputes exact CRT capacity from the field, ring dimension, width and coefficient bound. The exactness tail must cover the full prepared prefix when required and must be absent otherwise. Setup-seed digest, schedule digest, setup field count, ring dimension, exact geometry and total length are checked. Both i32 base residues and i16 tail residues are range checked before constructing the prepared representation.

Only the fixed public matrix transform is cached. The proof-dependent right-hand-side decomposition, matrix-vector multiplication, exactness checks, terminal comparison and transcript replay remain in the unchanged verifier path. `mat_vec_i16` still checks the actual right-hand-side basis/bound and required CRT capacity. The guest must load this cache exclusively from immutable ELF data with pinned hashes.

Native validation in `results/aerie-wrapper/q64-cache-native.json` passes direct-ring arithmetic comparisons with and without an exactness tail, Q128 compatibility, cross-target rejection, malformed metadata and residue controls, and all five original Aerie proofs through cache installation. Changed message and proof controls reject. A deliberately changed but still in-range transform payload can decode and produces a different matrix product. That is expected: identity labels and range checks do not prove that a transform was derived from its seed. Immutable, validated, program-bound provenance is mandatory, rather than optional defense in depth.

No blocking source issue was found in this extension. These native checks do not replace validation of the final compiled guest and its exact static-cache loader.

## Completed validation and remaining gaps

The host's four release tests pass. They cover advice packing, statement digest binding, trusted ELF pinning, and a real small outer proof rejecting changed outputs, program identity, corrupt proof bytes, truncation and trailing bytes. The small program is explicitly a host/backend contract test and does not claim Aerie verification. Shared frame tests and native setup interoperability provide additional checks.

The final compiled cache variant has ELF SHA-256 `f9eb00b035eba3fa3f0a42ad6f2c9e3405e8bca1c35ba146fd7ddec40b761342` and decoded leanVM program digest `ebdd6b22bea82d076055f8d067909db372fffc375907ce262f36ed20c66c1b52`. Its build target is `riscv64im-unknown-none-elf`, with Rust `1.101.0-nightly`, commit `0abfedbc7cd4e725f126913880c95800394f7c37`. The source and static-data closure is recorded in `results/aerie-wrapper/guest-build-manifest.json`. Every listed file hash and the aggregate hash were independently recomputed during review. The manifest includes the shared frame/claim format, guest runtime, SDK, owned dependency sources and immutable setup/cache artifacts; registry and external git dependencies are additionally identified by the guest lockfile. This records provenance, rather than proving compiler correctness or reproducible builds across machines.

All fifteen measured full interpretations for counts 1, 10, 30, 70 and 100 exit successfully with observed output equal to the receiver-derived expected output. An independent Python SHAKE calculation reproduces each intended statement digest. The per-table executed row counts sum exactly to the instruction count in every run. The report artifact hashes and frozen ELF/host identities were checked. These are complete executions of the compiled verifier under leanVM's reference RV64IM machine.

The final count-10 control suite contains twelve actual guest rejections: changed message, key, salt, proof body, record order, frame count, truncated inner proof, trailing inner proof, truncated frame, trailing frame, oversized statement header, and nonzero advice padding. Every rejection is classified as a guest trap. Malformed framing bypasses native prevalidation only through the test flag and reaches the unchanged guest parser. Late proof mutations run through uncapped interpretation so a commitment-capacity refusal cannot masquerade as verification rejection. A valid aggregate for a different record ordering also executes successfully and commits its different intended statement. See `results/aerie-wrapper/non-zk/n10/controls/summary.json` and the individual execution reports.

Every tested count is refused by both count-only capacity measurement and an actual outer `Prover` call. Each summary says `outer_proof_generated=false`; failed prover reports have no proof bytes or successful proving samples. The conservative packed-witness lower bound already exceeds the backend's one-commitment limit. No Aerie outer proof was generated, so fresh-process Aerie receipt verification, wrong-statement receipt rejection and outer-receipt corruption controls are explicitly unavailable. The separate synthetic host/backend proof tests cannot substitute for those missing end-to-end receipt tests.

Successful reference interpretation is separate evidence from a successful STARK. A capacity rejection is neither completed guest verification nor a proof. The default outer profile is plain and provides no zero-knowledge guarantee. The optional zero-knowledge backend needs its own successful measurements and controls before privacy or cost claims are made.

## Current assessment

No false-statement acceptance was identified in the inspected wrapper or runtime source or reproduced by the execution controls. The full verifier is encoded and runs inside leanVM; the tested complete runs do not fit an outer proof at the pinned backend limit. Consequently this is a validated execution port and a measured proving-capacity result, not a successful Aerie-to-leanSTARK demonstration. The reviewed source paths and these limits remain distinct from the cryptographic assumptions of the experimental Aerie/Akita profile, the correctness of leanVM's proof system, and the compiler/runtime translation assumptions.
