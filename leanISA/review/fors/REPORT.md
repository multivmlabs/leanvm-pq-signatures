# Independent FORS and statement binding review

Reviewed 2026-11-03 against leanVM `575df819d9c857f38068cecf7b1640e0ce4bfb29` (clean vendored tree). Guest SHA-256: `93c774d165ceb79e036bc513dad2da563e86122968bb9d77bb8d4c3262892e49`. Generator SHA-256: `3cd91fb7bc7564ccf392d6599e739d16e00239f820b91535c8896c64499b8fc3`. Runner source SHA-256: `0618c84c3992f4e6da8c65f00f45bf88c0afb4728adeb919c7641931beae3fc3`.

No omitted FORS signature relation was found in the reviewed guest. This conclusion is bounded by inspection, independent executable tests, and tracing the relevant compiler/AIR operations. It is not a complete proof-system soundness audit and does not establish a production security level for this custom signature construction.

## Verified relation and joins

- `guests/fors.py:15-20`: with `Y=f192(0,1,0)`, membership of `low` and `(word+low)/Y` in the base field forces `word=low+Y*high`. The cubic tower representation is unique (`vendor/leanVM/crates/primitives/src/field/gf2_64x3.rs:1-9`), so this excludes a third limb and uniquely pins the exposed low limb. Compiler lowering emits the `JUMP` base-field membership check (`lean_compiler/src/lower/builtins.rs:418-425`). `JumpTable` reads all three operands through `memory_k`, including on untaken branches (`leanvm_core/src/tables.rs:775-777`), which carries literal-zero upper limbs (`:147-151`). This is not merely an interpreter restriction.
- `guests/fors.py:23-34`: each bit obeys `b*(b+1)=0` in a field, and both 64-bit halves are reconstructed using the binary polynomial basis and `Y`. Thus the first 128 digest bits are uniquely determined, including unused index bits when `k*a<128`.
- `guests/fors.py:44-89`: seed, forest root and the original 32-byte message determine indices. The leaf and every ancestor bind the correct tree, height and index in disjoint little-endian address fields. The constrained direction bit selects left/right. Compression of all tree roots writes into the already witnessed public-root cells, enforcing equality through write-once memory.
- All variable FORS hash inputs use full 16-byte cells, so the compiler's unchecked partial-cell suffix caveat does not apply. Domains and addresses contain explicit zeros where specified. `keccak_cells` places Ethereum's `01 ... 80` padding; independent Keccak/byte reconstruction accepted root and batch messages across both odd and even multi-block layouts. The Keccak table fixes third limbs to zero (`leanvm_core/src/tables.rs:939`) and delegates actual permutation correctness to the upstream Keccak argument, whose full soundness was outside scope.
- `guests/fors.py:93-103`: the public digest binds ordered fixed-length seed/root/message triples. Count and `(k,a)` are specialized into bytecode; domain strings also carry `(version,n,k,a)`. Reordered and shortened claims rejected against the original commitment. Duplicates are intentionally allowed and accepted, consistent with documentation that this is a direct batch without deduplication.

## Independent evidence

Run:

```sh
.venv/bin/python review/fors/audit.py
.venv/bin/python review/fors/verify_binding.py --strict
```

`audit.py` produced 38 matched outcomes, retained in `results.json` with input fixtures. It builds full trees, secrets, paths, addresses, domain strings and commitments independently of the project's record generator. It accepted distinct byte-level fixtures at `(k,a,count)` equal to `(1,1,1)`, `(3,5,3)`, `(16,8,1)`, `(1,12,1)`, `(128,1,1)`, and `(10,12,1)`. Inputs exercise an all-zero public seed and high bytes. The controls use the published Ethereum Keccak empty-message digest and valid fixtures.

Crucially, computed `hint_f192_limbs` and `hint_decompose_bits` were replaced in the source with arbitrary witness streams. The honest replacement produced the identical bytecode/program hash `ab88c7f6ed1c7be82bdb63f879189789bd64aab82e83343958f970280a31870b`. Altered low-limb advice for headers, secrets and authentication nodes failed at `canonical` line 19. Altered low and high digest bits failed reconstruction at line 33; non-boolean or extension-field bits failed the boolean identity at line 28. This separates checking actual guest constraints from merely trusting honest computed advice.

Third limbs on each of the six header words and selected secret/path words rejected at canonical membership. Changed seed/root/message claims with freshly recomputed public commitments, changed secret/path bytes, and reordered tree openings all rejected at the forest-root equality (`verify_one` line 89), before the batch commitment could explain rejection. Public-input third limbs rejected in the runner.

`verify_binding.py` reused an existing real proof, creating no new proof. Six outcomes are in `verify-results.json`: the saved proof and unchanged statement passed; changed public input, changed source and a corrupted proof failed. The intentionally permissive metadata and serialization boundaries below passed, as expected.

## Boundaries and limitations

### Source identity and metadata

`src/main.rs:102-120` compiles the source supplied alongside the proof, derives its program identity, and echoes caller-provided `scheme`/`metadata`. `:129-147` verifies execution of that supplied program/public input. It supplies no separate allowlist or expected-claim argument. `python/pqbench/__main__.py:51-70` uses the resulting identity for the experimental dependency envelope.

A valid saved FORS proof still verified with a forged scheme label, arbitrary count/parameter metadata and an invalid witness stream, because those are not the cryptographic statement. The witness is unnecessary during verification. A changed constrained guest failed against the saved proof, confirming actual code binding; an empty guest could execute with the same public input, confirming the CLI accepts caller-selected relations. Consumers must pin the expected guest identity and independently compute the expected key/message commitment. This is already stated in `docs/fors.md:38` and `docs/architecture.md:5`; it is a documented generic-verifier boundary, not a demonstrated bypass of pinned verification.

### Noncanonical proof transport

At `src/main.rs:129`, `bincode::deserialize` accepts arbitrary trailing bytes. Appending `UNAUTHENTICATED_TRAILER` to a saved proof still verified and increased reported `proof_bytes`; changing an actual proof byte failed. This is a reproducible serialization malleability observation. It does not change the proved statement and no signature forgery or proof-system soundness consequence was demonstrated. If a canonical proof-file representation is required, use a decoder configured to reject trailing bytes while preserving this legacy fixed-integer encoding.

### Signature security level

The default uses only 128 deterministic public message-index bits (`python/pqbench/fors.py:48-50`, `guests/fors.py:47-60`). For a fixed key, two distinct messages with equal index vectors accept the exact same signature. Under the ideal-hash model, a chosen-message attacker can find such a pair by a birthday search in about `2^64` hashes, request a signature for one, and reuse it for the other. This follows exactly from the encoded relation; a `2^64` search was not executed. The general bound is about `2^(k*a/2)` chosen-message collision work, separate from `2^(k*a)` second-preimage work after a fixed signed message. `collision.json` and the `collision-*` fixtures demonstrate the exact signature-transfer relation at the supported alternate parameters `n=32,k=1,a=8`: a deterministic birthday search found two distinct messages with index 39 after 18 candidate hashes, one copied signature verified for both, and a control with another index rejected at the actual forest-root check. This reduced-parameter observation does not empirically establish default-parameter attack cost; the ideal-hash birthday calculation does. Multiple signatures reveal additional reusable openings and require a separate few-time security analysis.

Before this review, `docs/fors.md:42` noted the 128-bit preimage limit and absence of a many-signature analysis, but did not spell out the tighter chosen-message collision bound. The documentation now explicitly states that bound and separates the signature scheme from backend security. No explicit 128-bit signature security claim was found, so this is a security limitation, not an admitted missing-constraint defect. The backend's target security level does not transfer to this custom signature scheme. Fixture secrets are publicly derivable by design, and benchmark keys must never be treated as production signing keys.

## Host hardening after the baseline review

The host observations above describe the pre-hardening snapshot. Root subsequently added optional expected program-hash and public-input checks, a `statement_pinned` flag, and fixed-integer bincode decoding with exact consumption. The independent `verify_binding.py --strict` rerun recorded all six expected outcomes in `verify-results.strict.json`, including rejection of the appended trailer. Unpinned verification still intentionally permits caller-selected relations and metadata labels; pinning both expected values is now enforceable through the CLI. The baseline evidence is retained in `verify-results.json`. These changes do not alter the FORS guest hash or its proof relation.

## Coverage not claimed

No new full proofs were generated during this review to avoid disturbing concurrent benchmarks. Computed-advice adversarial executions share the original constrained bytecode but are not malicious custom AIR proof constructions. The upstream PCS, Fiat-Shamir soundness, Keccak GKR argument, portable verifier as a whole, denial-of-service handling of arbitrary guest sources, and recursive aggregation were not exhaustively audited. No guest, production host or vendored source was changed by this review.
