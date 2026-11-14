# Complete Aerie verifier input and public claim

The wrapper input contract lives in
[aerie-wrapper-format](../experiments/aerie-wrapper-format/src/lib.rs).
Its purpose is to let a guest verify an existing Aerie proof while binding
that execution to the receiver's intended ordered keys and messages.
No native acceptance bit, precomputed hash-to-point table, or original Falcon
signature is part of the guest input.

## Input bytes

All integer header fields are unsigned little-endian:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 8 | `AERLVM01` |
| 8 | 8 | Live record count |
| 16 | 8 | Canonical public statement length |
| 24 | 8 | Inner Aerie proof length |
| 32 | statement length | Aerie's canonical public statement |
| following | proof length | Complete Aerie wire proof, including salts |

The frame decoder requires exact consumption, 1 to 65,536 records, at most
64 MiB of statement and 4 MiB of proof. It requires Aerie's per-record-salt
magic `aerie/falcon/v1p`; common-salt signing is outside this wrapper profile.
The guest additionally parses the canonical statement, checks its parsed count
equals the frame count, constructs the trusted deterministic Aerie setup and
runs the full `verify_aggregate` implementation. Only after acceptance does
it commit the claim digest below through the leanVM SDK.

The runtime's advice transport may pack frame bytes into little-endian words.
That transport must retain the exact byte length and check any word padding.
Padding is not part of the frame or its public statement.

## Public claim

`claim_digest(N, statement)` is the first 32 SHAKE256 output bytes of:

```text
DOMAIN
LE32(length(PROFILE)) || PROFILE
LE64(N)
LE64(length(statement)) || statement
```

The exact domain and profile bytes are fixed in the shared crate. The profile
names Falcon-512's key-prefixed `fn-dsa` 0.3.0 raw/empty-context relation,
per-record salts, wire version one, and the complete pinned Aerie, Akita,
Jolt and Spongefish revisions with Akita's dev-protocol/BLAKE2b profile.
The original signature byte strings and the particular inner proof bytes are
not in this claim: the intended statement is existence of valid signatures
for the ordered public records.

The receiver regenerates this digest from its intended canonical statement
and pins the guest ELF/program identity. It must compare the SDK's committed
public-value digest with that expected commitment. A prover-selected public
statement or receipt digest is insufficient authorization.

## Native producer

[aerie-wrapper-inputs](../experiments/aerie-wrapper-inputs/src/main.rs) consumes
one of the exact saved native benchmark fixtures. It parses its canonical
statement and signatures, generates genuine Aerie proofs, natively verifies
them and writes one frame for every timed sample:

```sh
export CARGO_HOME="$PWD/.cache/aerie-cargo"
export CARGO_TARGET_DIR="$PWD/.cache/aerie-target"
cargo +stable build --release --offline \
  --manifest-path experiments/aerie-wrapper-inputs/Cargo.toml
.cache/aerie-target/release/aerie-wrapper-inputs \
  artifacts/aerie/honest-fixtures/SELECTED-FIXTURE.bin \
  artifacts/aerie-wrapper/inputs/n100 --repeat 3 --warmup 1
```

The producer records fixture parsing, canonical encoding, reusable setup,
native Aerie proving and native checking separately. Its `sample-i/input.frame`
and `sample-i/aggregate.aerie` are actual generated artifacts. `statement.bin`
and `claim-digest.bin` are receiver inputs. Native generation alone does not
establish any leanVM execution or proof result.

## Controls

The producer also writes changed-message, changed-key, changed-salt,
changed-proof, truncated-Aerie and trailing-Aerie frames. Those mutations are
first checked against unchanged native Aerie verification. It adds malformed
outer lengths/tails and a count mismatch for the actual guest parser.

For counts above one it generates a second **valid** Aerie proof for swapped
ordered records, swapping the matching signature witnesses as well. The guest
can accept that alternate statement. Its outer proof must nevertheless reject
when checked under the original intended claim digest. This control tests the
public binding rather than merely the inner verification algorithm.

Every control remains labelled as native-prechecked until the actual guest
and outer proof consumer execute it. These files contain public benchmark
statements, signatures and proofs, with no signing secret keys. Omitting the
inner proof from a final receipt is not by itself a zero-knowledge claim.

## Benchmark driver

[aerie_wrapper_bench.py](../scripts/aerie_wrapper_bench.py) coordinates native
production, count-only complete guest execution, measured outer proofs and
fresh receipt verification. Pass the trusted built ELF and native host:

```sh
.venv/bin/python scripts/aerie_wrapper_bench.py prove \
  --host /absolute/path/to/aerie-leanvm-host \
  --elf /absolute/path/to/aerie-verifier.elf \
  --counts 1 10 30 70 100 --repeat 3 --warmup 1
```

Each measured outer proof consumes the corresponding freshly generated native
Aerie sample. Native setup, fixture parsing, Aerie proving, complete guest
execution, outer proving, serialization and receipt verification remain separate.
The reported sum of inner and outer proving intervals is stage work, not a
distributed latency. `--zk` selects a separate outer-proof cohort; both modes
can reuse the same immutable native input cohort.

`controls --controls-at 10 --counts 10` runs the actual guest and receipt
controls once an honest outer proof exists. Capacity rejection does not count
as an invalid-input control passing. Malformed frame controls use the host's
execute-only raw-negative-input path to reach the unchanged guest parser.
For a measured proof-capacity failure the driver can run the exact interpreter
separately, with public output checked, while clearly recording that no outer
proof was generated.

## Immutable public setup exports

The producer has a native, proof-free export command:

```sh
.cache/aerie-target/release/aerie-wrapper-inputs --export-setup 100 \
  artifacts/aerie-wrapper/public-setup/n100
```

For 1/10 records the exact public setup contains 131,072 Fp64 elements and is
1,048,682 serialized bytes. For 30/70/100 it contains 229,376 elements and is
1,835,114 bytes. Every export was deserialized with full native validation,
including rederivation from the fixed seed, and compared to its original object.
N=1/10 have byte-identical setup; N=70/100 are identical. N=30 has a distinct
descriptor and catalog row despite sharing the larger matrix length.

The pinned `build_riscv64_terminal_ntt_cache` supports Q128 only and rejects
Aerie's Q64 field. The metadata records that limitation rather than supplying
an incompatible cache. Matrix seed expansion can still be removed from guest
execution by making its exact validated result immutable program data.

The import compatibility command takes only public setup, statement and Aerie
proof. All five cases passed unchanged full native `verify_aggregate` after
`deserialize_exact_with_mode(Compress::Yes, Validate::No)` and
`FalconVerifierSetup::from_derived_setup`. Skipping validation here is safe only
because these exact bytes were previously validated and are intended to be
bound as immutable ELF data, not supplied as unchecked prover advice.

See [public exports](../results/aerie-wrapper/public-setup.json) and
[checked native imports](../results/aerie-wrapper/public-setup-import-checks.json)
for exact hashes, shape metadata and scope. These import checks generate no
STARK proofs and establish no outer proving-time claim.

## Experimental Q64 transform cache

The isolated [Akita overlay](../experiments/aerie-port/akita) adds a scalar Q64
variant of the existing trusted transform artifact. Its distinct target tag is
2. Payload coefficients use the existing three Q64 CRT primes, with an i16
exactness tail when required. Import selects the decoder from the protocol
field and checks the exact schedule, setup identity, dimensions, coefficient
bounds, residue ranges and end of file.

For all five tested counts the selected terminal matrix has ring dimension
128, 384 rings, width 128 and an exactness tail for all 384 rings. Each artifact
is 688,248 bytes. There are three distinct complete artifacts because setup
and schedule identities differ. Their transform payloads are identical.

The [native checker](../experiments/aerie-q64-cache-check/src/main.rs) confirms
that these imports preserve unchanged full Aerie verification for all five
existing proofs. Dense ring products agree with direct arithmetic both with
and without tails. Invalid identity, target, length, geometry and residue
controls reject; the original Q128 path still round-trips correctly. An
in-range transform mutation is deliberately accepted by the parser and changes
the arithmetic. Parsing cannot authenticate derived matrix contents, so the
cache must be immutable trusted ELF data.

See the [patch](../results/aerie-wrapper/akita-q64-cache.patch),
[source hashes](../results/aerie-wrapper/akita-q64-cache-overlay.json) and
[native checks](../results/aerie-wrapper/q64-cache-native.json). These results
establish native interoperability. Actual guest capacity and outer proving
cost must still be measured.
