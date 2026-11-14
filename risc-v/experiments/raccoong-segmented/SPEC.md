# Segmented Raccoon-G verification

This is a new proof decomposition for the unchanged strict Raccoon-G signature
profile. It is not a new signature scheme, an unchecked matrix hint, or an
increase of leanVM's witness cap. The original whole-signature guest remains
preserved, including its measured inability to produce a one-signature proof.

## Original relation and source identity

Use the exact relation in `risc-v/raccoon-g/SPEC.md`, approved authors' source
`461a5ed9b6d57e3bf8c381be3bb79325ab21d906`, and unchanged RISC-V backend
`06e5c9cd6981103786f9d0a17324241b559a50d3`.

The ring is `Z_q[X]/(X^256+1)`, `q=562949953438721`, `k=ell=9`, challenge
weight 23, `nu_t=35`, `nu_w=38`, and exact squared norm threshold
`25650475979193785709999263840`. Keys contain 16144 canonical bytes; signatures
contain 20768 canonical bytes; benchmark messages contain 32 bytes. The strict
integer norm intentionally differs from the authors' binary64 boundary behavior.
Full paper conformance and parameter security remain unverified pending PDF access.

## Per-part guest

The current two-row guest uses five canonical parts: `(0,1)`, `(2,3)`,
`(4,5)`, `(6,7)`, and `(8,8)`. The final repeated computation is charged and is
neither an additional original row nor another signature. The earlier single-row
candidate, its executable and measurements are preserved separately in
`one-row.elf`, `one-row-source.zip` and `one-row-manifest.json`.

Each leaf execution takes one part index `p` in `0..5`, the full public key and
message, the full signature `(c_hash,z,h)`, and the entire reconstructed commitment
vector `w[9][256]`. It checks:

1. Every original public-key and signature coefficient is canonical, and the
   complete signature satisfies the original strict norm predicate.
2. Every supplied `w` coefficient is canonical modulo 2048.
3. The original full-key binding `tr=SHAKE256(pk)[0:32]` and
   `mu=SHAKE256(tr||message)[0:32]` are computed inside the VM.
4. The original `HashVec(mu,whole_w)` equals `c_hash`. HashVec retains its original
   eight-byte header and seven-byte encoding of every coefficient.
5. All nine response polynomials and the challenge are transformed inside the VM.
   For both selected rows, all nine matrix polynomials are expanded by the
   original SHAKE128 sampler. The full published key is rounded and scaled using
   the original executable equation. The guest computes
   `v_r = (A*z-c*t_scaled)_r` and requires
   `w_r = Round_38(v_r)+h_r mod 2048`, coefficient by coefficient, for both rows.
   The full global checks, transformed response and common witness binding are
   shared within this execution. Row eight is actually recomputed for part four.
6. The guest computes the common witness binding below and commits the row's
   public statement. No host verification result, pre-expanded matrix or `mu`
   is trusted.

All five canonical parts, covering all nine distinct rows, are needed. One
accepted part alone is a partial
verification claim and must never be reported as an accepted full signature.

### Fixed trace normalization

The native recursive tree requires identical padded instruction-table heights.
The complete unchanged 100-signature corpus contained one part whose store count
crossed the `2^19` boundary. The selected uniform guest therefore executes a fixed
32768 volatile `u64` stores to one naturally aligned, disjoint local scratch cell,
after all checks and public commits and before returning. The scratch is never
read, no witness controls the count or address, and every store executes inside
the proved VM. All padding is included in prover work and witness counts.

This changes no signature equation, decoding rule, norm, witness-binding digest
or public output. It preserves all corpus records rather than selecting a
favourable subset. Its original unnormalized two-row executable and source are
archived separately. The original 500-part store-count range, 506140 through
525147, becomes 538908 through 557915 under this fixed addition, within one
padded `2^20` store table. Final-executable measurements must confirm the complete
shape before aggregation. No proof-system limit is raised.

## Canonical witness binding

The fixed witness codec is:

```text
signature[20768] || w[9][256] as canonical LE16 coefficients
```

Thus the encoded `w` length is 4608 bytes. Row-major and coefficient-major order
match the original signature arithmetic. Typed arrays and canonical checks fix
every byte and prevent alternate residue encodings. The row index is deliberately
absent from this binding so all rows can share it.

For `b` equal to zero and one, compute:

```text
D_b = BLAKE2s-256(domain_b[32] || LE64(20768) || LE64(4608)
                 || signature || encoded_w)
domain_0 = "pqbench/rcg-wit/strictv1/hash0v1"
domain_1 = "pqbench/rcg-wit/strictv1/hash1v1"
D = D_0 || D_1
```

Each domain is exactly 32 bytes. The SDK's existing proved BLAKE2s instruction
implements these hashes. No new accelerator is introduced. Two separated hashes
avoid adding a single 256-bit witness-binding digest as an additional bottleneck;
this does not upgrade the underlying backend's own hash or proof security.

The part's public-output preimage is:

```text
domain_part[32] || LE64(part_index) || LE64(first_row) || LE64(second_row)
    || pk[16144] || message[32] || D[64]
domain_part = "pqbench/rcg-two/strictv1/d512/v1"
```

It is committed through the ordinary SDK public-values interface. Every word is
little endian. The signature and `w` are witnesses; `D` is auxiliary proof data.

## Complete receiver and composition argument

The caller authorizes only its ordered public-key/message list and pins the
segmented guest identity, backend, tree shape and decomposition policy. It does
not authorize or independently trust sender-supplied `D` values.

The receipt carries one 64-byte `D` per original signature. For each authorized
pair at index `i`, the receiver constructs expected outputs for parts zero through
four and their fixed row pairs, always using that pair and the same `D_i`. It
requires that exact part order and complete coverage. It applies only the explicitly specified native-tree
padding, then invokes complete native `Tree::verify`, including all terminal
program, image, fixed-polynomial and matrix obligations.

Under the zkVM argument's witness-knowledge/extraction assumptions and collision
resistance of the witness binding, the accepted parts with the same `D_i` yield
one common canonical `(signature,w)` witness. Every part checks the same full
norm and challenge relation, and the receiver requires coverage of all nine
distinct matrix rows. Their conjunction therefore implies the original full
signature relation for the authorized public key and message. Different extracted
witnesses with one common binding give a collision. Plain existential soundness
alone is not being presented as a witness-extraction theorem for this composition.
Different keys, messages, part/row indices or binding
values are not accepted under the receiver's independently reconstructed outputs.

Missing, duplicated or reordered rows do not satisfy the expected output list.
Padding may repeat complete final leaf claims only after all intended rows are
present; it never counts as a new signature or as missing-row coverage.

The receipt's binding values are existential auxiliary proof data. Supplying them
does not change which original keys/messages the application authorizes. Signature
witnesses and child proof files are unnecessary at the final receiver.

## Accounting and controls

Report original signature count `N`, partial-leaf count `5*N`, distinct matrix-row
obligations `9*N`, actual matrix-row computations `10*N`, padding slots, every
fresh leaf and merge, root bytes, the extra
`64*N` binding bytes, and complete receipt verification. Do not compare a root
without its auxiliary bindings to a complete receipt. Original direct-batch
failures remain failures and are not replaced by partial-proof measurements.
Fresh reconstruction of complete `w`, common `D` calculation and advice packing
are prover preparation, not signature fixture generation. Every fresh pipeline
must charge that work once per original signature, plus all part and merge proofs.
It may exclude only key generation and signing as in the earlier signature study.

Before proof production, independently review the codec, collision/coverage
argument, full public binding and actual guest predicates. Correctness controls
must include all nine honest rows, invalid row indices, changes to each witness
component, out-of-range `w`, full-key low-bit binding, norm-bound controls,
different witnesses/bindings, and consumer missing/duplicate/wrong-row attempts.
