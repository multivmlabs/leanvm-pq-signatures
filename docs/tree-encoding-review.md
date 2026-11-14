# Recursive tree encoding and receipt review

Reviewed 3 November 2026. This is a scoped implementation review and regression
suite, not a cryptographic audit of the pinned STARK backend. The procedure
follows the local `zkvm-security-review` skill: trace the intended statement,
attacker-controlled data, complete verifier path, and positive/negative controls.
The experimental format is specified in [tree-format.md](tree-format.md).

## Scope and provenance

The reviewed path is `pqbench.article_inputs` public-claim derivation,
`aggregate-tree` plan construction and receipt verification, `tree_guest` node
statements, and their use of the extracted upstream recursive verifier. Additional
checks cover shared SHAKE byte packing and the standard Falcon norm boundary.
The repository parent HEAD is `b2c3ed5aab2b5f4f39c3659ecb318e711f0f9a7c`;
the project additions are uncommitted workspace files. Dependency instances are:

| Dependency | Revision |
| --- | --- |
| leanVM custom ISA | `575df819d9c857f38068cecf7b1640e0ce4bfb29` |
| ETHDILITHIUM C/Python reference | `f9f4fe1d84e68304b425e054c273c276fe44ba11` |
| ETHFALCON C reference | `43ac863e30281bb7821748178d39967367d54bc2` |

The observed toolchain is Rust 1.99.0 (`b940084d7`, 2026-09-28), native CPU
features from `.cargo/config.toml`, release thin LTO and one codegen unit. The
standard ML-DSA native library records Clang/version, every source/header hash,
its test-only ACVP adapter, and explicit `-DETHDILITHIUM=0` in its fingerprint.
The corresponding Falcon build uses explicit `-DETHFALCON=0`. No production
contract, deployed verification key, or EIP-approved guest identity is supplied
by this experiment. The backend proofs are not zero knowledge.

## Intended statement and trust boundary

The receiver starts with intended, ordered public key/message claims and an
authorized signature-verifier implementation. It regenerates the exact-count
leaf sources and leaf public inputs, then obtains a plan hash from that trusted
configuration. A received envelope may choose its proof and all auxiliary edge
points, but cannot choose the receiver's claims, verifier code, plan or root
public input.

The resulting claim is existence of valid signature witnesses for exactly those
ordered leaf statements, composed through all the specified tree edges. Compact
signature bytes need not be available to the receiver. The ML-DSA-family leaf
relation uses the documented expanded-key model. The public-only receiver
derives that identity from its authorized compact key through trusted host
expansion; alternatively a receiver could trust a validated registration. A
pre-registered expanded-key table is not required by this frontend. Expansion
remains outside the VM and does not establish wallet policy.
Transaction canonicalization, nonce consumption, expiry, authorization and EIP
set union/discard semantics remain separate application obligations.

| Value | Controller | Enforcement and binding |
| --- | --- | --- |
| Public keys/messages | Receiver's intended public claims | `article_inputs.expected_pi`; saved PI/hash/source metadata are ignored |
| Leaf verifier | Receiver-authorized source generator | Recompile source and compare exact `cpu::fs_seed` with the expected pin |
| Counts/order/tails/fan-in | Receiver's trusted plan | Semantic plan hash; all full leaves precede a positive exact-count tail |
| Child program identity | Trusted tree construction | Baked child seed plus native deferred evaluation against that exact child bytecode |
| Child public input | Prover witness, constrained by recursive verification | Included in the node digest; receiver reconstructs it from its children |
| Deferred point/value | Derived during child-proof verification | Every full 192-bit coordinate and value is included in the node digest |
| Deferred value at receipt | Receiver | Recomputed from trusted bytecode; no prover-supplied values are accepted |
| Root public input | Receiver | Reconstructed bottom-up, then supplied to the root proof verifier |
| Root proof and envelope | Prover | Strict version/plan/root identity, shape checks, and native root proof verification |

Accepting an accompanying manifest and its hash solely because they travel with
the proof would change this trust boundary. The Rust CLI requires an external
expected plan hash; the Python public-only frontend supplies it after deriving
claims and authorized sources. Neither interface establishes ownership of a
wallet key by itself.

## Encoding and composition checks

The plan hash commits compact JSON in its declared struct field order. Pretty
JSON returned as `semantic_plan` has a different key order and must not be hashed
verbatim. The Python regression test independently reconstructs the documented
semantic JSON and agrees with the native Keccak hash. Paths and labels are
excluded while ordered leaf program pins, public inputs, counts and commitment
floors are included.

Node preimages contain a domain, arity, plan hash and ordered child records.
Digest fields are canonical 128-bit halves. A deferred coordinate or value is
three little-endian 64-bit limbs, and the packing gadget carries all three into
the hash. Odd field counts receive an explicit zero field. Mixed bytecode sizes
select namespaced verifier functions with the matching point dimension. A
same-size program is not interchangeable: the seed and actual bytecode
polynomial both matter.

Every tree edge is retained in the envelope. Receipt verification evaluates the
lowest points against trusted leaf code, reconstructs their parent statements,
then repeats upward through the root. Thus an inherited point changes a lower
node public input and transitively the expected root input. The core root proof
alone does not discharge these obligations. The auxiliary bytes and native
bytecode evaluation work grow with tree edges.

The fixed-width bincode decoder rejects trailing bytes and has a 64 MiB limit.
Required JSON manifest fields must be present; extra JSON fields are permitted
for public metadata and have no authorization role. The final verifier reads no
signature fixture, leaf proof or intermediate proof.

## Regression evidence

The following tests do not create proofs:

```sh
PYTHONPATH=python .venv/bin/python -m unittest discover \
  -s tests -p test_tree_envelope.py -v
```

Six public-plan tests passed in 2.55 seconds. They cover independent plan hashing,
exact `5+5+1` claims, public key/message/order/tail changes, malicious saved
PI/hash/source metadata, duplicate/missing claims, malformed positive/full/tail
counts, required fields, and substitution of a different verifier with exactly
the same instruction count. The latter is rejected under the original source
pin; authorizing the substitute instead produces a different plan hash.

The suite also contains real-envelope controls that take an existing proof:

```sh
TREE_TEST_MANIFEST=/absolute/path/to/manifest.json \
TREE_TEST_PROOF=/absolute/path/to/run/aggregate.proof \
PYTHONPATH=python .venv/bin/python -m unittest discover \
  -s tests -p test_tree_envelope.py -v
```

All 12 tests passed in 13.179 seconds against the real 30-signature FORS tree:

```sh
TREE_TEST_MANIFEST=artifacts/article/fors/trees/fors-30-b4/manifest.json \
TREE_TEST_PROOF=artifacts/article/fors/trees/fors-30-b4/sample-0/aggregate.proof \
PYTHONPATH=python .venv/bin/python -m unittest discover \
  -s tests -p test_tree_envelope.py -v
```

This tree has six five-signature leaves, three merges, depth two (two wrapper
layers, three node levels including leaves) and eight edges. Its trusted plan hash is
`99924a15f813485cef6eea1a5f7aece5f3649c3dde894ebe7e95839f08dc3946`.
The root program hash is
`ad51f0ff99b10e02c82b470bad7845855efc80a76a52ba40eb9baecb7da037ce`.
The tested envelope SHA-256 is
`1d9f12dcff6252889abd4b54fc84a4ef2cb2809aca7039b184d0e916156e5a60`;
the manifest SHA-256 is
`4e24f0d62143b8fefcec3024bedb81806b534c1d47f943d12bffeeb2d1a86330`.
The controls regenerated the trusted manifest using only intended public
key/message records and verified while all leaf fixture paths were nonexistent.
Each of the three limbs of a lower inherited edge was independently mutated and
rejected. Missing/extra merges and edges, changed point dimensions, modified
plan/root/proof bytes, truncation, trailing data and a changed external pin were
also rejected. Modified key/message/order/tail/removal cases were rejected even
when their new intended plan pins were recomputed. No proof-producing job was
run by this test suite.

The tree author's separate normal Rust tests cover ordered topology for all
leaf counts 1 through 100 and fan-ins 2/4/8, mixed-size compilation, native
full-field encoding, and actual guest/native packing agreement. That packing
unit test substitutes the verifier body to isolate the encoding; it is not a
child-proof soundness test. The separately executed ignored toy test passed in
4.51 seconds with depth three, three wrapper layers and eight edges. It verifies
the honest composition, rejects lower inherited-point and transport mutations,
and verifies again after child inputs/proofs are removed. See the
[archived toy log](../results/article/validation/toy-three-level.log).

The final `make test` run completed at 21:02 UTC with the FORS30-b4 manifest and
sample-0 envelope above supplied through `TREE_TEST_MANIFEST`/`TREE_TEST_PROOF`.
All 80 Python tests passed in 46.909 seconds with zero skips, including all 12
tree plan/receipt tests. The ordinary Rust checks passed separately: two in
`aggregate-falcon` and six in `aggregate-tree`. Proof-producing ignored tests
are scheduled separately. See the [full validation log](../results/article/validation.log).
Release Clippy over all targets with warnings denied and the formatter check
also passed; see [Clippy](../results/article/validation/clippy.log) and
[formatting](../results/article/validation/format.log).

## Additional checks

The shared SHAKE implementation explicitly XORs the `0x1f` domain suffix and
final `0x80` bit, including the shared final byte case and an extra padding block
for an exact-rate message. It preserves the VM state-layout gap after byte 135,
and exposes only rate bytes between squeezes. Checked input bytes and checked
128-bit word decompositions make the cell-to-byte mapping exact. The owner's
18 boundary cases compare against Python `hashlib` for SHAKE128/256 around both
rates and across multiple squeeze blocks. Invalid bytes and false outputs are
rejected by guest execution. The ML-DSA guest consumes the shared primitive for
98-to-64-byte message hashing, 32-to-136-byte challenge expansion and
832-to-32-byte challenge hashing.

The [exact field-order certificate](../results/article/field-encoding-check.json)
checks the host encoding with polynomial `x^64+x^4+x^3+x+1` and generator `g=2`.
It verifies `g^(2^64-1)=1` and `g^((2^64-1)/p)!=1` for every prime factor
`p` in `3,5,17,257,641,65537,6700417`; trial division and their product check
the factorization. Thus the encoding generator has order `2^64-1`. The bounded
ML-DSA products, including `8380417^2`, and the maximum Falcon norm plus allowed
complement lie below that order. Under the enforced operand ranges, these
integer equalities cannot alias by exponent wraparound. This is an exact
host-field arithmetic check, not a formal proof of the compiler or backend.
The generator-order unit test and the windowed-power comparison against
independent binary exponentiation both passed in the final suite.

The Falcon norm terminal reads `sums[GEN ** N]`, after all 512 coefficient pairs.
Each squared magnitude is nonnegative and bounded; even their largest possible
sum plus the bounded complement is far below the `GF(2^64)` generator order.
The equality to `g^34034726` therefore enforces the integer norm bound without
exponent wraparound. The standard and ETH guests reuse this terminal. The
standard test constructs complete advice for a zero signature that violates the
norm and observes guest rejection. The stronger isolated last-coordinate control
also passed: `s2[0]=128`, with `s1[511]=5832` for the positive case and
`5833` for the false case, and a public key satisfying the full ring equation in
both. The false witness supplies the complement that would succeed if the last
coordinate were omitted, with a legal high limb of `519`. This avoids an earlier
range-check rejection masking the terminal-boundary test. Both inputs satisfy
the full ring equation. The native C verifier and guest accept the positive
case and reject the false case in the executed final suite.

The ML-DSA suite passed 12 tests, including all 15 pinned FIPS204 ML-DSA-44 ACVP
internal verification cases in both C and independent Python, a valid pure
empty-context guest execution, changed messages with recomputed public input,
challenge/rejection/hint/arithmetic mutations, sampler exhaustion bounds and
reciprocal standard/ETH cross-variant guest controls with fully recomputed
arithmetic advice. The ACVP native adapter removes only the external message
prefix because those vectors target the internal algorithm; production records
use the unchanged public C entry point. The guest has a completeness cap of 128
candidate bytes after eight sign bytes and rejects exhaustion.

The stronger inherited-bytecode control passed separately at 21:02 UTC in
3.76 seconds:

```sh
cargo test --release --offline --bin aggregate-tree \
  forged_bytecode_is_rejected_through_two_wrapper_levels -- --ignored --nocapture
```

Its honest depth-two tree verifies. A normally assembled tiny program B accepts
a public input that expected program A excludes. A test-only malicious prover
then keeps A's cached transcript seed while executing B; native verification
against A rejects. Unchecked advice preparation, compiled only for this test,
allows the partial child verifier to export B's incorrect deferred value. The
test generates two genuine wrapper proofs carrying that value. Native checking
of those wrapper proofs accepts their advertised statements, and every root-
immediate bytecode evaluation is correct. Reconstructing all edge evaluations
against the expected code changes the required root statement and the unchanged
production final verifier rejects. This isolates the inherited obligation rather
than merely mutating a point after proving. No production verification check is
disabled, and this is not a backend soundness attack. See the
[control evidence](../results/article/validation/deferred-boundary-two-level.json),
[test log](../results/article/validation/forged-two-level.log), and
[artifact inventory](../results/article/validation/forged-two-level-artifacts.json).

A single interleaved mixed-program correctness demonstration also passed a real
proof pipeline and fresh public-only verification. It contains exactly two claims
from each of the five families: ten one-signature leaves, four merges, thirteen
edges and depth two. The first two parents each verify children with bytecode
logs 13 and 18; the root verifies children with logs 18 and 19. Thus different
sizes share an actual parent at both wrapper levels, exercising the static
specializations. Authorized sources and program pins agree with the independent
direct reports, leaf public inputs are independently derived from actual keys
and messages, and all ten receiver leaf-input paths are absent. No child proof
or signature witness is used by the final verifier. The archived
[mixed-case evidence](../results/article/mixed/evidence.json) includes source,
report and artifact hashes. This is one correctness demonstration, not a mixed-
scheme performance curve or evidence of an optimal topology.

## Conclusion and remaining evidence

No discrepancy was found in the reviewed claim binding, full-field encoding,
all-edge reconstruction, SHAKE packing or Falcon terminal bound. The real
depth-two FORS tree passed its public-only positive control and every targeted
receipt mutation above was rejected. The separate depth-three toy and the
two-wrapper forged-bytecode control also passed, as did the interleaved mixed-
program case with heterogeneous child sizes at both levels. This conclusion remains limited by the
lack of an independent audit of the inherited recursive verifier/backend/compiler,
trusted native key expansion or validated registration, and the absence of
deployed EIP integration. The review does not establish wallet policy correctness, production signing-device
security, post-quantum security parameters of the research FORS component, or
zero knowledge.
