# Experimental recursive tree format

`aggregate-tree` produces bounded-depth recursive proof trees over independently
trusted leaf statements. It uses the pinned leanVM backend and retains **every**
deferred bytecode evaluation. It does not implement EIP dependency unions,
discards, self-recursion, or bounded-size deferred-claim folding. The backend
proofs are not zero knowledge.

## Trusted inputs and CLI

The receiver must obtain an expected manifest and plan hash from its intended
claims and authorized verifier implementations. Neither may be selected by the
received proof envelope. In this project the Python public-claim builder derives
leaf public inputs from intended public keys/messages and regenerates authorized
leaf sources. The Rust runner treats those expected public inputs as trusted
statements; it does not independently interpret signature-scheme key formats.
Passing a prover's manifest and its accompanying hash provides no application
authorization.

```json
{
  "schema_version": 1,
  "scheme": "ethfalcon-512-keccak",
  "signatures": 10,
  "leaf_capacity": 5,
  "fan_in": 4,
  "programs": [{
    "id": "full",
    "source_file": "leaf-program.py",
    "expected_guest_hash": "<64 hex characters>",
    "min_log_committed": 22
  }],
  "leaves": [{
    "program_id": "full",
    "signatures": 5,
    "public_input_hex": "<independently derived 64 hex characters>",
    "input_file": "leaves/leaf-0.json"
  }]
}
```

The example abbreviates the leaves array: ten signatures require two five-item
leaves. Paths are relative to the manifest. `input_file` has the existing fixture
fields `source`, `public_input`, and `witness` and is read only when a new leaf
proof is needed. Verification requires source files but never reads input files,
signature witnesses, leaf caches, or intermediate proofs. Extra manifest fields,
such as public records retained by the independent claim builder, are ignored by
the Rust schema.

Compile each authorized source and require its cached Fiat–Shamir seed to equal
`expected_guest_hash`. All leaves except the final leaf must have
`leaf_capacity` signatures; the final leaf must have a positive count no larger
than the capacity. Counts must sum exactly to `signatures`. Partial leaves use
separately authorized exact-count programs; no duplicated padding claims are
introduced. The default commitment floor is 22 and supported floors are 22–28.
This floor is a prover policy, not a new signature relation.

```sh
target/release/aggregate-tree inspect --manifest expected.json
target/release/aggregate-tree prove --manifest expected.json \
  --expect-plan-hash TRUSTED_HASH --leaf-cache-dir cache --out-dir run \
  --rate 1 --repeat 3 --warmup 1
target/release/aggregate-tree verify --manifest expected.json \
  --expect-plan-hash TRUSTED_HASH --proof run/aggregate.proof \
  --repeat 3 --warmup 1 --report verify.json
```

`inspect` is an unpinned diagnostic that compiles programs without proving. Its
output contains the semantic plan, program table, complete topology and root
program hash. A trusted claim builder may use it to compute a pin for its own
configuration. Both `prove` and `verify` require that independently trusted pin.

## Plan identity and topology

The plan hash is Keccak-256 of `b"pqbench/tree-plan/v1\0"` followed by compact
UTF-8 JSON serialized in the following field order:

1. `format`: `"pqbench/tree-v1/all-edges/level-chunks"`;
2. `schema_version`, `scheme`, `signatures`, `leaf_capacity`, `fan_in`;
3. ordered `leaves`, each with `signatures`, lowercase `guest_hash`, lowercase
   `public_input_hex`, and `min_log_committed`, in that field order.

JSON has no extra whitespace. Program IDs, paths, redundant records and unused
program specifications do not affect the semantic plan. The runner nevertheless
checks every supplied program specification against its source pin.

Leaves have node IDs `0..leaf_count`. At each level, partition the current
ordered node list into consecutive chunks of at most `fan_in`. Merge chunks of
two or more; carry a singleton to the next level unchanged. Append merge nodes
in creation order. Supported fan-ins are 2, 4 and 8. This explicit scheduling
policy is not a claim of minimum merge count. A single-leaf plan has no merge
and transports that leaf proof as its root.

The node programs are specialized by the global plan hash and the exact ordered
child program seeds. Each distinct child bytecode logarithm gets a namespaced
copy of the parsed generic verifier AST. Function calls and constant-array
references are renamed; builtin operations and witness stream names are
preserved. No vendor code or compiler semantics change. Program construction
occurs through the normal compiler, which computes a consistent halt sentinel
and Fiat–Shamir seed.

Because the global plan hash commits the complete intended claim list and is
baked into merge code, an intermediate merge proof belongs to that complete
plan. It cannot be reused as an online mempool subtree after the intended plan
changes. Leaf proofs remain reusable across plans with the same leaf program and
public input. A reusable incremental merger needs a separate statement/coverage
protocol; the measurements here concern bounded, predetermined trees.

## Node statement and complete deferred checks

A merge verifies every child proof in the guest, using that child's expected
program seed and hinted public input. Each verification yields a fresh deferred
point and value for that child's bytecode polynomial. The merge's public input
is Keccak-256 of this exact preimage:

```text
domain16 || arity_LE128 || plan_hash32 || child_record[0] || ...
child_record = child_program_seed32 || child_public_input32
             || canonical_packed(point_coordinates..., claimed_value)
domain16 = b"pqbench/tree/v1\0"
```

Seeds, public inputs and the plan hash each use two canonical 128-bit cells.
Every coordinate and evaluation value is an arbitrary 192-bit field element,
encoded as three little-endian 64-bit limbs. Two such elements occupy three
128-bit hash cells. If the number of elements is odd, append a complete zero
192-bit element. A child's point has `child_kbc + N_BYTECODE_SELECTORS`
coordinates; the pinned backend has four selectors. The guest's packing gadget
constrains all limbs, including the top limb. No 192-bit element is truncated.

The final envelope contains points for **all tree edges**, including those below
the root's immediate children. In canonical merge order, the native receiver:

1. starts with the independently expected leaf public inputs;
2. evaluates each edge point against the exact trusted child program, caching
   `verifier::Bytecode` once per program seed;
3. reconstructs that merge's public input from those recomputed values and the
   already reconstructed child public inputs;
4. verifies the single root proof against the resulting root public input and
   expected root program.

The child public-input hashes transitively bind inherited obligations. Dropping
lower-level points, evaluating a point against a different program with the same
bytecode size, or accepting prover-supplied values breaks this interface.
Auxiliary point data and native evaluation work grow with the number of edges.
Only checking the root core proof against an accompanying, prover-selected public
input is insufficient.

## Transport and measurement boundaries

The fixed-width bincode envelope is:

```text
version: u32 (=1)
plan_hash: [u8;32]
root_guest_hash: [u8;32]
deferred_points_by_merge: Vec<Vec<Vec<F192>>>
proof: leanvm_core::cpu::Proof
```

`F192` is three 64-bit limbs. Nested vector lengths use bincode's fixed u64
lengths. Decoding rejects trailing bytes and has a 64 MiB limit. Code, signatures,
child proofs, and claimed deferred values are absent. `aggregate.core.proof`
contains only the root proof; `aggregate.proof` is the complete verification
transport. Trusted public claims/sources are separate and their size must be
reported separately when relevant.

Leaves are cached by program seed, expected public input, requested rate, and
commitment floor. Every reused proof is natively checked, including its actual
PCS rate. `--fresh-leaves` forces leaf proving. `--repeat` and `--warmup` repeat
all merge nodes while preparing leaves once; they do not silently count leaf
cache reuse as a new full pipeline. Cold complete-pipeline samples require
separate processes and fresh leaf caches.

Reports retain each node's hint preparation, proving and self-verification times,
cycles, witness sizes, proof-stream length, program identity, topology and proof
bytes. Compilation is separate. Hint preparation includes checked child
verification. Proving includes VM execution. Pipeline wall time includes cache
I/O, validation and serialization. Process peak RSS is the high-water mark for
the complete process, not an isolated per-node peak. Verification reports code
preparation, all-edge reconstruction, cold root-core checks and cached portable
root-core checks separately; its total includes all requested verification passes
and excludes plan loading/compilation and envelope deserialization.

Normal Rust tests cover ordered tree coverage, heterogeneous compilation,
full-field encoding and actual guest/native packing agreement. The explicitly
scheduled proof-producing test is:

```sh
cargo test --release --offline --bin aggregate-tree \
  toy_three_level_tree_preserves_all_inherited_obligations -- --ignored --nocapture
```

It exercises a small three-level tree and mixed child sizes, then rejects a
mutation to the lowest inherited obligation, missing points, wrong program
identity and trailing bytes. Its leaf relation binds two public cells and has no
signature-security interpretation. Real signature trees require their separate
fixture, verifier and fresh-process checks.

The stronger deferred-bytecode control below passed separately after the
benchmark matrix (one test, 3.76 seconds). Reproduce it without concurrent proving:

```sh
cargo test --release --offline --bin aggregate-tree \
  forged_bytecode_is_rejected_through_two_wrapper_levels -- --ignored --nocapture
```

It first checks an honest tree and a normally verified tiny program B that accepts
an input excluded by expected program A. A test-only malicious prover then keeps
A's cached transcript seed while supplying B's execution. Two genuine wrapper
proofs carry the false lower-level deferred value. The test requires the unchanged
final verifier to reject after evaluating every edge against the expected code,
even though the root's immediate bytecode claims are correct. The unchecked advice
helper is compiled only for tests; no production verification check is disabled.
This is a composition-boundary control, not a demonstrated backend soundness attack.
The test prints a temporary result directory containing its JSON evidence.
The executed result is archived as
[deferred-boundary-two-level.json](../results/article/validation/deferred-boundary-two-level.json),
with the [captured test log](../results/article/validation/forged-two-level.log)
and [artifact inventory](../results/article/validation/forged-two-level-artifacts.json).
