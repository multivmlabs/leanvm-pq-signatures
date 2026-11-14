# Raccoon-G HD-wallet profile: source audit and implementation specification

Status: **provisional**. This document records the authors' executable profile precisely. It is not yet a completed paper-to-code conformance review. Do not start benchmark experiments from this draft. The user requested approval before experiments.

## 1. Source identity

The supplied URL, [ePrint 2026/1628](https://eprint.iacr.org/2026/1628), resolves to *Lattice-based Signature Schemes for Bitcoin* by Zakharov, Kudinov, Balatska and Chopa. It reviews Dilithium, Falcon and Hawk. It is not the Raccoon-G HD-wallet construction.

The matching primary construction is [*Lattice HD Wallets: Post-Quantum BIP32 Hierarchical Deterministic Wallets from Lattice Assumptions*, ePrint 2026/380](https://eprint.iacr.org/2026/380), by Deegan, Fitzwater, Gür and Nugent. The [authors' announcement](https://www.projecteleven.com/blog/lattice-hd-wallets-post-quantum-bip32-hierarchical-deterministic-wallets-from-lattice-assumptions) links this paper and the [authors' accompanying implementation](https://github.com/p-11/lattice-hd-wallets).

Reference checkout: `sources/lattice-hd-wallets`, commit `461a5ed9b6d57e3bf8c381be3bb79325ab21d906`. Relevant executable files are:

- `src/raccoon/thrc-py/raccoon_primitives.py`: unrounded keys, serialization, single-party signing and verification.
- `src/raccoon/thrc-py/thrc_core.py`: challenge, matrix expansion, transcript hash and norm bound.
- `src/raccoon/thrc-py/polyr.py`: ring arithmetic and exact NTT convention.
- `src/raccoon/thrc-py/thrc_gauss.py`: deterministic rounded Gaussian sampler.
- `src/raccoon/mod.rs`: wallet derivation.
- `scripts/sigparams.sage`: parameter-selection analysis, with discrepancies noted below.

The user confirmed 2026/380 and its authors' code as the intended sources on 2026-11-09, and subsequently approved downloading the PDF. The IACR landing pages were read, but native HTTP returned 403 and approved browser downloads timed out. Therefore the complete PDF, section numbers, theorem conditions and paper algorithms have **not** yet been verified. The specification below is explicitly based on pinned executable source, not inferred missing paper text. Access to the PDF remains necessary for claiming paper conformance.

This is a separate scheme from original NIST Raccoon-128-1. Its larger ring modulus, Gaussian secrets, ring dimension, module dimensions and wallet public-key encoding must not be substituted into the standard-Raccoon baseline.

## 2. Selected executable profile

Use the name `Raccoon-G HD, authors' PoC profile` until the paper review is complete. The repository calls this a proof of concept and does not claim it is audited.

| Parameter | Value |
| --- | ---: |
| Security target in reference | 128 bits |
| Polynomial degree `N` | 256 |
| Ring | `Z_q[X]/(X^256 + 1)` |
| `q` | 562949953438721 |
| `q` bit length | 50 |
| Public vector length `k` | 9 |
| Secret vector length `ell` | 9 |
| Challenge weight `tau` | 23 |
| Key Gaussian standard deviation `sigma_t` | `2^7` |
| Signing Gaussian standard deviation `sigma_w` | `2^40` |
| Public-key rounding parameter `nu_t` used during verification | 35 |
| Commitment rounding parameter `nu_w` | 38 |
| `q_t = floor(q / 2^35)` | 16384 |
| `q_w = floor(q / 2^38)` | 2048 |
| Claimed maximum derivation depth in Python profile | 1000 |
| Matrix seed bytes | 16 |
| Key-generation master randomness bytes | 32 |
| Challenge, `tr` and `mu` bytes | 32 each |

The parameter labels are source facts, not an independent security estimate. In particular, the Sage script uses `n = 2^60` for a maximum derivation quantity, whereas Python uses depth 1000. This must be resolved before attributing a security level or derivation guarantee to a port.

## 3. Canonical encoding

All polynomial arrays are polynomial-major, coefficient-major, in increasing index order. Integers use little-endian encoding. A seven-byte residue must satisfy `0 <= x < q`; a two-byte hint residue must satisfy `0 <= x < q_w`. Reject noncanonical residues rather than reducing malformed input modulo the relevant modulus.

- Public key: `A_seed[16] || t[9][256]`, each `t` coefficient seven bytes. Total **16144 bytes**. This stores full, unrounded `t`.
- Signing key for host fixture generation: serialized public key followed by `s[9][256]` in seven-byte residues. Total **32272 bytes**. The error vector is implicit and not stored.
- Signature: `c_hash[32] || z[9][256] || h[9][256]`. `z` uses seven-byte residues and `h` uses two-byte residues. Total **20768 bytes**.

This signing-key size is the actual serialized `(vk,s)` size in `raccoon_primitives.py`. The README table's 16128-byte private-key entry counts only the secret vector. Do not mix these definitions.

For a modulus `m`, define `center_m(x)` by first taking its canonical residue, then subtracting `m` if the residue is strictly greater than `floor(m/2)`. Thus even `q_w = 2048` uses representatives `[-1023,1024]`, as the source decoder does. This tie convention must be tested.

The upstream decoders check lengths but do not reject all out-of-range coefficients. A strict port intentionally restricts acceptance to the canonical serializer's image. Differential tests must distinguish this parser hardening from an arithmetic mismatch.

## 4. Arithmetic and hashes

For canonical coefficients define `Round_u,m(x) = ((x + 2^(u-1)) >> u) mod m`. Apply it coefficientwise. Perform ring arithmetic modulo `q` before rounding. This is the executable `poly_rshift` rule, including its tie convention.

Use the exact NTT in `polyr.py`. Forward butterflies use the 256-entry `RACC_W` table in its existing bit-reversed schedule. The inverse reverses that schedule, multiplies `(y - x)` by the table entry, then multiplies all coefficients by `RACC_NI = 560750930183101`. An alternative Montgomery implementation must be differential-tested against this representation and against independent negacyclic multiplication.

`hdr8(ds,b1,...,b7)` is exactly eight bytes `[ord(ds),b1,...,b7]`, absent arguments zero. `hdr24(ds,i,j,k)` is exactly `ord(ds) || k:u8 || i:LE24 || j:LE24`. These headers are not interchangeable with string concatenation or length-free hashes.

Matrix expansion produces **NTT-coordinate entries directly**, as the pinned reference does. For each row `i = 0..8`, column `j = 0..8`, initialize `SHAKE128(hdr8('A',i,j) || A_seed)`. Read seven-byte chunks, mask to 50 bits, reject candidates `>= q`, and accept 256 residues for `A_hat[i][j]`. Do not NTT these sampled coordinates again.

`HashVec(data,v)` flattens `v` in the encoding order and returns 32 bytes of:

```text
SHAKE256(hdr24('H', len(data), 7*len(v), 0)
         || data || every LE56(v_i mod q))
```

Even a vector modulo `q_w` uses **seven-byte** coefficients for this hash. Its two-byte signature encoding is a different format.

`Challenge(c_hash)` initializes `SHAKE256(hdr8('c',23) || c_hash)`. Repeatedly read two-byte little-endian `x`, set `index = (x >> 1) & 255` and `sign = 2*(x & 1)-1`. Set that coefficient if currently zero; otherwise discard that pair. Stop after 23 distinct positions. Return a ternary polynomial of exact weight 23. High unused bits are discarded; replacing this with Fisher-Yates sampling changes signatures.

Bind the full unrounded public key using:

```text
tr = SHAKE256(serialized_public_key)[0:32]
mu = SHAKE256(tr || original_message)[0:32]
```

The guest must compute this itself from the supplied canonical public key and original message. Accepting an unchecked host-supplied `mu`, expanded matrix or transformed key is not equivalent verification.

## 5. Verification relation

Input: exact public-key bytes, arbitrary message bytes under a bounded transport length, exact signature bytes. No secret key or wallet seed enters the verifier.

1. Enforce the lengths and canonical residue ranges above. Decode `t`, `z` and centered hint `h`.
2. Compute `tr`, `mu`, challenge `c`, and `A_hat` exactly as above.
3. Compute `t_hat = Round_35,q_t(t)` and `t_scaled = 2^35 * t_hat mod q`, coefficientwise.
4. Compute in the ring:

   `v = A*z - c*t_scaled mod q`.

5. Compute `w = (Round_38,q_w(v) + h) mod q_w`.
6. Require `HashVec(mu,w) == c_hash`.
7. Require the Euclidean norm bound on `(center_q(z), 2^38*center_q_w(h))`.
8. Accept only if every check succeeds.

Step 3 reflects actual executable code in both `_sign_with_unrounded_public_key` and `_verify_with_unrounded_public_key`. Their docstrings say no `t` scaling, but their bodies **round full `t` and scale the rounded vector**. The full `t` remains in the public key to enable exact wallet key addition. Do not implement the docstrings' direct `A*z-c*t` formula and call it source-compatible.

The Python source computes a floating-point radius:

```text
B = exp(1/4) * (sqrt(1000)*23*2^7 + 2^40) * sqrt(256*(9+9))
    + (23*2^35 + 2^39) * sqrt(256*9)
```

and accepts `sqrt(sum(z_i^2) + 2^76*sum(h_i^2)) <= B`. A deterministic integer-only RISC-V verifier needs an explicitly pinned squared threshold, derived with interval/high-precision arithmetic and checked against the intended paper bound. Do not silently round this to binary64 in a consensus-facing verifier. The accumulations need at least 128-bit checked arithmetic; each decoded centered coefficient can otherwise make a 64-bit sum overflow. Reject out-of-bound values early when useful, without allowing wraparound or saturating acceptance.

The implemented deterministic profile uses **`25650475979193785709999263840`** as the exact squared threshold. Both [rational Taylor/square-root intervals](review/norm_bound_check.py) and the independent fixture helper's directed 512-bit interval calculation give this same floor. This certifies evaluation of the displayed expression, not its security provenance.

The source's binary64 square-root comparison accepts some slightly larger integer norms. This port deliberately implements the exact integer predicate instead of emulating that rounding. Independent, challenge-consistent controls at the threshold and threshold plus one document the difference, including both coefficient signs. The public domain and executable identity identify this strict profile. Until the paper is available, this remains a **reference-profile threshold**, not a paper-certified bound.

## 6. Host key generation and signing

These operations generate correctness fixtures off chain. The leanVM statement proves signature verification, not honest key generation or derivation history.

For a 32-byte entropy value, the PoC first derives 48 DRBG seed bytes using HKDF-SHA256 with empty salt and empty context, then instantiates `NIST_KAT_DRBG`, then requests 32 key bytes `K`.

Generate `A_seed = SHAKE256(hdr8('A') || K)[0:16]`. Sample each secret polynomial using `RoundedGaussian(2^14, hdr8('s',i)||K)` and each error polynomial with `RoundedGaussian(2^14, hdr8('e',i,1)||K)`. Compute full `t = A*s + e mod q`. Return `vk = (A_seed,t)` and `sk = (vk,s)`.

The reference rounded Gaussian is deterministic Marsaglia polar sampling at 256-bit `mpmath` precision. It consumes signed 64-bit uniform values from SHAKE256 of its seed and scales them into `[-1,1-2^-63]`. For a pair `(x0,x1)`, accept `0 < S = x0^2+x1^2 < 1`, compute `F = sqrt((1/6 - 2*sigma^2)*log(S)/S)`, and output `floor(F*x0+1/2)`, `floor(F*x1+1/2)`. Do not replace this with a host-language standard normal RNG if claiming deterministic compatibility.

Signing takes a fresh random 32-byte `K`. Sample `r[9]` using variance `2^80`, domain `hdr8('r',i)||K`, and `e'[9]` using domain `hdr8('e',i,2)||K`. Compute `w = Round_38,q_w(A*r+e')`, `c_hash = HashVec(mu,w)`, `c = Challenge(c_hash)`, `z = c*s+r mod q`, `y = Round_38,q_w(A*z-c*t_scaled)`, and `h = w-y mod q_w`. Serialize `(c_hash,z,h)`.

The public `sign_message` wrapper in the pinned PoC does not perform rejection/retry after the norm test. Fixture generation must verify its output and report any retry or failure. Do not hide a verification failure or treat changing the verifier bound as an optimization. The complete paper may prescribe a specific rejection strategy that still needs confirmation.

## 7. HD derivation and scope

The construction's useful property is exact public-key addition under a **shared matrix seed**. For parent `(A_seed,t)` and tweak `(A_seed,delta_t)`, child public key is `(A_seed,t+delta_t mod q)`. The child secret is `s+delta_s mod q`; the implicit error adds. Reject mismatched matrix seeds.

The pinned wallet implementation uses `HMAC-SHA512` with a 32-byte chain code as key. A non-hardened child at `u32` index `i` derives:

```text
I = HMAC-SHA512(chain_code, serialized_full_public_key || BE32(i))
tweak_entropy = I[0:32]
child_chain_code = I[32:64]
```

Generate the tweak using the same entropy-to-DRBG-to-Gaussian process, but force its `A_seed` to the parent's seed. Add the keys. Public-only and private derivation must produce byte-identical child public keys. The tweak seed alone cannot regenerate the child signing key.

The reference master-node convenience API uses `HMAC-SHA512("Raccoon-HD-wallet", master_seed)`, splitting the result into key-generation entropy and chain code. Its independent-seed-and-chain-code API is separate.

The actual hardened derivation body uses `0x00 || serialized_s_vector || derivation_seed || BE32(i)` as HMAC data. This differs from comments describing only `0x00||private_key||BE32(i)` and must be checked against the paper before becoming a project wallet API. The reference also exposes `u32` indices separately from the textual hardened marker; do not invent a BIP32 high-bit rule and silently change its deterministic outputs.

The RISC-V signature-verification benchmark should receive the final public key and original message. It must **not** claim to prove the child belongs to a given root/xpub. Proving an HD path is a separate relation with a public root, chain code, path, depth policy and per-step derivation checks. It must be labelled and measured separately if later added.

## 8. Required correctness and security checks

Before any benchmark approval request, prepare these checks and record source/ELF hashes:

1. Independent NTT round-trip and negacyclic-product checks, including `0`, `q-1` and sparse basis polynomials. Cross-check matrix expansion, `mu`, challenge and reconstructed `w` against the pinned Python oracle.
2. Deterministic host vectors with fixed entropy and explicitly fixed signing randomness. Record full public key, message, signature, intermediate transcript hashes, norm and profile ID. Include independently generated keys and at least one public/private derived-child match. These are correctness vectors, not performance samples.
3. Accept honest canonical signatures in native code and the actual RISC-V guest interpreter. Reject changed message, changed key, swapped key/message pairs and changes in every signature component. Verify actual guest output commits to **all ordered public-key/message pairs**, count and scheme/profile.
4. Reject short/long inputs, trailing bytes, residue `q`, residue `q_w`, high unused bits, wrong parameter/profile IDs and arithmetic overflow. Include norm boundary checks for both signs and the even-modulus midpoint convention.
5. Fix the program identity in the consumer. Independently recompute the public statement from the intended original pairs. An accepted STARK of some other executable, message digest or claimed profile is not this statement.
6. Keep production verification independent of signature witnesses, child proof files or host-supplied verification booleans. Full tree verification must settle the backend's terminal polynomial claims in addition to checking the root transcript.

Do not report complete security proof, 128-bit estimate, paper conformance, maximum derivation depth, maximum direct batch or proving/verification timing until the corresponding evidence exists. **No benchmark experiment was run while preparing this specification.**

## 9. Open decisions

- The user confirmed the corrected paper, 2026/380, and its authors' code.
- Obtain and read its full PDF, especially the exact Raccoon-G construction, HD key-generation changes, distribution assumptions, bounds and parameter tables.
- Resolve executable rounded verification versus misleading unrounded-verification comments against the paper.
- Resolve Python depth 1000 versus Sage derivation quantity `2^60` against the paper. The implemented exact integer threshold is documented above, without claiming paper conformance.
- The implemented proof statement is signature verification. Host fixture tooling additionally checks master, hardened, non-hardened and watch-only derivation. It does not prove a wallet derivation path inside the STARK.
- Record upstream license provenance before redistributing source. The checkout has source comments referring to licenses but no root license file in the tracked file list; do not invent a license.
