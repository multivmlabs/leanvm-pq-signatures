# Original Raccoon-128-1 verification profile

The requested source of truth is the [NIST Raccoon specification](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/raccoon-spec-web.pdf), downloaded as `sources/raccoon-spec-web.pdf`, SHA-256 `7dae8c58264599fc65d0c31421166732d6253fe3cb5665034316c25c79998926`. This profile uses original Raccoon, not Raccoon-G and not a threshold protocol. The `-1` selects one unmasked signing share. Verification is independent of the signing share count.

The reference code is [masksign/raccoon](https://github.com/masksign/raccoon), pinned to `e789b4b72a2b7e8a2205df49c487736985fc8417`. Vendor sources are unchanged. The repository's current `doc/raccoon.pdf` has a different file hash from the NIST document. Parameters match the requested NIST profile, but independent review found conflicting byte-level pseudocode. On 2026-11-09 the user explicitly selected official C/Python and known-answer interoperability, with the PDF discrepancies documented. That is this profile's approved policy. No literal-PDF variant is substituted.

## NIST PDF and reference discrepancies

The [independent review](review/SECURITY-REVIEW.md), finding R1, records three discrepancies that prevent a claim of literal PDF conformance:

- PDF Algorithm 9 hashes `hdr_h || serialized_w || mu`; both official implementations and this guest hash `hdr_h || mu || serialized_w`.
- PDF Algorithm 10's loop condition uses `<= omega`, contradicting its stated weight. The reference stops at exactly 19 nonzero coefficients.
- Its printed sign convention `(-1)^b0` is the opposite of the reference's `2*b0-1`.

Independent native and actual-ELF controls distinguish the two hash orders. Known-answer interoperability applies to the reference policy, not a hypothetical literal-PDF variant. The decoding corrections below address separate canonicalization and completeness issues; they do not resolve these transcript discrepancies.

## Parameters

| Quantity | Value |
|---|---:|
| Ring | `Z_q[X]/(X^512+1)` |
| `q` | 549824583172097 |
| `k`, `ell` | 5, 4 |
| `kappa`, signing shares `d` | 128, 1 |
| `nu_t`, `nu_w`, challenge weight `omega` | 42, 44, 19 |
| `rep`, `u_t`, `u_w` | 8, 6, 41 |
| Scaled squared bound `2^-64 B_2^2` | 14656575897 |
| Infinity bound `B_inf` | 41954689765971 |
| Public key, signature, secret key bytes | 2256, 11524, 14800 |
| Public message bytes in this guest | 32 |

These are Table 2. All XOFs and hashes internal to Raccoon are SHAKE256 with the specification's original domain headers. The SDK's BLAKE2s is used only for the VM's public output commitment.

## Signature relation

The witness is a signature in the fixed-length NIST encoding. The public statement is an ordered, nonempty list of compact public-key/message pairs, together with the approved executable identity. For each pair, the guest performs all of the following:

1. Decode the 16-byte public matrix seed and the `5*512` little-endian 7-bit coefficients of `t`. Each coefficient must be below `q_t=floor(q/2^42)=125`.
2. Decode the 32-byte challenge hash, signed unary-coded hint vector `h`, and response vector `z` using the low-40-bit plus unary-high-part format. Require the fixed 11524-byte length and canonical zero padding. The four extra bytes used by word transport must also be zero.
3. Compute `tr=SHAKE256(pk,32)` and `mu=SHAKE256(tr||message,32)` inside the guest. Neither hash is advice.
4. Check the hint and response infinity bounds and the specified scaled squared Euclidean bound. This is the original `CheckBounds`, including flooring each absolute response coefficient before squaring.
5. Derive the weight-19 challenge polynomial from the challenge hash with the original `'c'` header, the reference's stopping rule and sign convention. Expand every matrix entry from the public seed with the original `'A'` header using rejection sampling and SHAKE256. No expanded matrix or challenge is trusted.
6. Compute `y=A*z-2^42*c*t` in the specified ring. Round its canonical coefficients to the `q_w=floor(q/2^44)=31` domain, add the signed hint modulo `q_w`, and hash `hdr_h || mu || serialized_w` using the reference transcript order.
7. Accept that record only if the recomputed challenge hash matches the signature challenge hash.

The reference implements steps 3 through 7 in `xof_sample.c`, `racc_core.c`, `polyr.c` and `ntt64.c`. Public-key hashing and byte deserialization are in `racc_serial.c`. The local `c/adapter.c` enforces the compact boundary and canonical encodings before invoking those functions. Integer operations execute as ordinary constrained RV64IM instructions. The reference's intended wrapping Montgomery arithmetic is compiled with `-fwrapv`; it does not depend on a host arithmetic hint.

## Reference corrections at the byte boundary

NIST specification Section 2.5 requires rejecting invalid or alternative encodings. The pinned C decoder accepts all 7-bit public coefficients, including 125 through 127, and its signature decoder only checks the remaining zero padding when the entropy-coded payload ends partway through a byte. The adapter rejects coefficients outside `Z_125` and uses a bounded bit reader for the same prefix-free signature encoding. It checks every padding bit and only fetches a new byte when another bit is required. This also accepts valid payloads that consume exactly the last bit of the fixed-size signature, which the reference decoder incorrectly rejects because it fetches one byte early. This follows the PDF's encoding rules while preserving the reference transcript policy above. It does not change key generation, signing distributions or parameter values.

The native C signer remains unchanged. `review/crosscheck.py` checks exact public-key and signature agreement with the separate official `ref-py` implementation and reproduces the first prescribed NIST known-answer record, including its full public key, secret key and signed message.

## Public output and trust boundary

Advice contains a count, followed by each compact key, 32 message bytes and signature, transported as little-endian 64-bit words. `MAX_BATCH=64` is a transport bound: `1+64*1727` words fit inside the fixed 131072-word advice region. It is not a measured prover capacity.

The guest checks every signature, then commits the following word sequence through the SDK public-values interface:

```
32-byte domain: "pqbench/racc1281/compact/v1" followed by five zero bytes
count as LE64
for every ordered record: public key bytes (2256), message bytes (32)
```

The receiver must pin the approved guest ELF and independently compute this output from the intended records. No signature bytes, secret keys, native acceptance bits or host-generated hash/matrix claims enter that computation. Count and order are committed. Duplicate-key policy, transaction binding and account authorization belong to the receiver. The experiments use the pinned backend's plain proof mode; this profile does not itself claim zero knowledge.

## Implementation controls

Native and actual RISC-V interpreter tests cover one- and two-signature positive cases, distinct deterministic keys/messages, altered key/message/challenge rejection, malformed unary coding, noncanonical key coefficients, signature and word-transport padding, valid payloads that fill the last byte exactly, out-of-range counts and output count/order/key/message binding. Two separate algebraic zero-public-key inputs isolate the byte-aligned padding and exact final-bit boundaries. They are parser controls and are excluded from the benchmark fixture generator.

The SDK software Keccak permutation is compared with the unchanged C permutation on 130 complete 25-lane states, including all-zero and all-one states. The replacement affects only the permutation. Absorption, padding, squeezing, domain headers and rejection sampling remain in the reference C implementation. This is a software kernel in the VM, not the leanISA specialised circuit.

No STARK, proving-time, verification-time, witness-capacity or aggregation experiment has been run for this scheme. Those measurements require the user's requested approval first.
