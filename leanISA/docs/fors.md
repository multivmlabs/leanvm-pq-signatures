# Research Keccak FORS relation

This benchmark implements a complete standalone FORS verification relation in leanVM. It is an unreviewed few-time research variant, not FIPS 205 SLH-DSA, SPHINCS+, or leanSPHINCS. FIPS 205 uses FORS inside a larger signature construction that authenticates many FORS keys through a hypertree; that layer is intentionally absent here. These measurements therefore describe the component and cannot be substituted for the cost of an unlimited-use wallet signature. See [FIPS 205, sections 3 and 8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).

The default parameters are `n=32` bytes, `k=16` trees and tree height `a=8`. Every benchmark record uses a distinct, deterministically generated test key. Test seeds are public and are unsuitable for real signing. Fixture generation constructs all trees outside the measured prover interval. The proof itself checks the disclosed signature paths; it receives no host verification receipt.

## Exact byte encoding

`H` is Ethereum Keccak-256 with its `0x01` padding, not SHA3-256. Every domain is 16 bytes: ASCII `FORS:` followed by the operation name (`LEAF`, `NODE`, `ROOT`, `MSG`, or `BATCH`), padded with zeros to 12 bytes, then the four bytes `(version=1, n, k, a)`. Each address is `LE32(tree) || LE32(height) || LE64(index)`.

For public seed `P` and secret leaf value `S`, both 32 bytes, the leaf at index `i` in tree `t` is:

```text
leaf(t,i) = H(D_LEAF || P || address(t,0,i) || S)
```

An internal node at height `h` and index `i` is:

```text
node(t,h,i) = H(D_NODE || P || address(t,h,i) || left || right)
root = H(D_ROOT || P || tree_root[0] || ... || tree_root[k-1])
```

The public key is `P || root`, totaling 64 bytes. Messages in this harness are exactly 32 bytes. The message digest is `H(D_MSG || P || root || message)`. Interpret its first `k*a` bits little endian and split them into `k` groups of `a` bits. Each group selects the leaf for one tree. A signature contains the selected 32-byte secret value and `a` 32-byte authentication nodes for each tree; its size is `n*k*(a+1)` bytes, or 4,608 bytes at the defaults.

## What the guest constrains

The guest hashes the seed, public root and original message to derive the leaf choices. It constrains every decomposed bit to be boolean and reconstructs the complete first 128-bit digest cell, which contains all index bits for supported parameters `k*a <= 128`. It derives every ancestor index from those bits, selects left and right path nodes using the constrained direction bit, computes each tree root and compresses all roots to the claimed public root.

Every hinted message, public-key, secret and path cell is constrained to its canonical 128-bit encoding. This prevents extra field limbs from being silently discarded by byte hashing. Signatures remain witness data and never appear as constants in compiled guest source. The source depends only on the count and parameter set.

The public input is the full 256-bit digest:

```text
H(D_BATCH || (P || root || message)[0] || ... || (P || root || message)[N-1])
```

It binds the ordered batch of public keys and messages. The count and parameters are also fixed by the compiled guest. A receiver must compare this digest against its expected claims and pin the expected guest/program hash; merely accepting whichever source and public input accompany a proof does not authenticate a wallet request. This direct-batch guest implements no deduplication, recursive proof merge, or discard operation.

## Interpretation and regression checks

Increasing the count measures verification of more independent signatures in one proof. It does not measure a recursive aggregation node. FORS has a limited signing budget per key: these parameters have no supplied many-signature security analysis, and proof aggregation does not improve signature security.

This standalone variant derives its `k*a` message-index bits deterministically from public values and includes no signer-controlled randomizer in that hash. For a fixed public key, two different messages with the same index vector accept exactly the same signature. In the ideal-hash model, a chosen-message attacker can find such a pair with a birthday search in about `2^(k*a/2)` hashes, obtain a signature for one message, and reuse it for the other. At the defaults this is about `2^64` hashes and one signing query, even though finding a second message for a fixed, already signed index vector takes about `2^128` generic trials. Thus neither the 256-bit hash output nor the backend's target security establishes 128-bit classical chosen-message security for the complete signature variant. This is a known structural limitation of this research construction, separate from whether its verification paths are correctly constrained; no practical `2^64` forgery was executed.

The independent review in `review/fors/audit.py` demonstrates signature transfer using the supported alternate parameters `n=32, k=1, a=8`: two distinct messages with equal index vectors accept one copied signature, while a different-index control rejects it at the forest-root equality. This small-parameter experiment confirms the encoded relation; the default-parameter complexity above follows from the exact birthday bound, not from extrapolating its runtime.

`tests/test_fors.py` exercises valid one- and three-record batches, two independent witnesses under identical guest source, altered path nodes, secrets, messages, public keys, noncanonical witness cells and public input. It generates a real proof, verifies the exported statement without witnesses, and rejects a corrupted proof and a changed public input. All integration subprocesses use four leanVM worker threads. The pinned leanVM backend currently produces proofs without zero knowledge.
