# Thirty-signature recursive envelope: independent integration review

The experiment now has one recursive root proof of six five-signature ETHFALCON leaf proofs. This review found no demonstrated statement-binding or deferred-evaluation omission in the exercised implementation. It is a fixed-arity, one-level prototype, not a reusable self-recursive or EIP-8288 dependency-union implementation.

## Checked trust chain

1. `aggregate-falcon::expected_inputs` requires schema 1, the ETHFALCON scheme label, five signatures per leaf and exactly 30 records. It independently decodes each 897-byte canonical compact public key, rejects out-of-range coefficients, computes the same LE16 polynomial-key commitment as the leaf, hashes the actual 32-byte message and recomputes each ordered five-record leaf digest. Supplied `claim_hash`, `key_hash` and `leaves[].public_input_hex` metadata do not drive verification. Duplicate key/message claims are rejected.
2. The final `verify` command requires an expected leaf program hash and compares it with the locally compiled leaf source. `verify_aggregate` checks the envelope's program identity, version, leaf size and six deferred points. It compiles the wrapper from the fixed local wrapper implementation, the trusted child program seed and the required child count. No root guest source is accepted from the proof envelope.
3. `guests/aggregate_falcon.py::main` calls the extracted `verify_sub` six times with the pinned child program seed. Each hinted child public input is included in the root statement together with every fresh deferred bytecode point and value. These are the actual proof-verifier outputs, not host verification receipts.
4. The child proof verifier intentionally leaves its bytecode polynomial evaluation deferred. The outer receiver evaluates the expected leaf bytecode at all six transmitted points, reconstructs each expected value and hashes the complete statement before checking the root proof. Those obligations are not ignored or accepted from a prover-supplied scalar value.
5. Field serialization retains all three 64-bit limbs of every 192-bit point coordinate and evaluation value. The wrapper uses the upstream constrained `pack_pair` representation; the native statement preimage uses the same order, including the odd-field zero padding. The header binds the domain, arity and child program seed. Native/guest packing tests cover nonzero top limbs.
6. The final native verdict uses the public manifest, trusted leaf source, one root proof and the six deferred points. It does not deserialize child proofs or use signature witnesses. Fixed-integer bincode decoding rejects trailing bytes.

## Independent saved-root tests

`tests/test_recursive_envelope.py` passed six test methods in 3.06 seconds. It generated no proof and ran each final check in a fresh subprocess. The accepting public-only test copied only a stripped manifest containing `(public_key_hex,message_hex)` records, the trusted leaf program and the root envelope into a temporary directory. No compact signatures, decoded signatures, witness inputs or child proof files were available there.

Predetermined accepting controls:

- The public-only manifest and root verify as 30 signatures and six child proofs.
- Replacing every advisory leaf PI, key hash, claim hash and source SHA metadata value does not change the verdict. The verifier derives the actual claims from the canonical keys/messages and derives the program hash itself.

Predetermined rejecting controls:

- Changing an actual 32-byte message rejects after expected-PI recomputation, at root proof verification.
- Substituting another valid canonical public key or reversing the first leaf's claim order rejects.
- Duplicating a key/message claim or supplying only 29 records rejects.
- Flipping the third limb of the first deferred point coordinate rejects at root proof verification. This reaches the native polynomial evaluation and reconstructed public input, rather than being rejected as malformed transport.
- A wrong trusted leaf pin, a changed compiled leaf norm constant, or a changed envelope leaf identity rejects.
- Corrupting the root proof or appending unparsed bytes rejects.

The prover's own negative executions additionally alter a child proof scalar, a Merkle leaf-row word and a child public input after host child verification, thereby reaching the in-VM verifier. All reject. The first trial altered Merkle cap node zero, which is unused transport padding and may legitimately change; that was an ineffective test control, not a demonstrated verifier bypass. The final test mutates an actual opened leaf row.

A separately run, ignored-by-default Rust test probes the deferred-evaluation boundary more directly. It uses test-only unchecked advice preparation for a proof of a different tiny program under a cached expected seed. The partial recursive verifier and a root bound to the prover's value accept; native evaluation of the expected leaf bytecode produces a different value and the final root check rejects. This is an intentional malicious-prover control, not a backend soundness attack. It demonstrates that the required outer check is consequential, rather than only testing an unrelated hash mismatch. See [the recorded control](../results/recursive-30/deferred-boundary.json).

## Boundaries

The envelope is 369,348 bytes in this run: a 366,080-byte core proof plus 3,268 bytes of version/program/count/deferred-point transport. The public claim manifest and trusted program distribution are separate costs. Six native bytecode evaluations are still required at final verification and their cost belongs in the reported verification time. Ignoring them and checking only `aggregate.core.proof` would establish a weaker claim than this experiment advertises.

This review does not establish the soundness of the entire copied upstream verifier, compiler, memory bus, Keccak argument, Fiat-Shamir transform or polynomial commitment system. It does not cover arbitrary multi-level carried claims, mixed guest programs, canonical dependency-set unions or discards. The prototype uses the current custom-leanISA ETHFALCON relation, not PR #490's RISC-V SHAKE-Falcon guest. Benchmark keys and signing randomness are publicly reproducible test material and must not be used for funds. Proofs are not zero knowledge.

Reproduce the saved-root integration checks after creating the experiment:

```sh
PYTHONPATH=python .venv/bin/python -m unittest discover -s tests -p test_recursive_envelope.py -v
```
