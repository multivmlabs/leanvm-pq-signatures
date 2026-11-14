# Raccoon-G HD-wallet verification under RISC-V leanVM

This port implements the **authors' HD-wallet proof-of-concept profile**, with
strict canonical encodings and an explicit integer norm threshold. It is separate
from original NIST Raccoon-128-1 in `../raccoon`. The implementation specification
is [SPEC.md](SPEC.md). Full comparison with the corrected paper,
[ePrint 2026/380](https://eprint.iacr.org/2026/380), remains pending PDF access.
No security level or paper-conformance claim follows from these correctness tests.

The authors' code is pinned at
`461a5ed9b6d57e3bf8c381be3bb79325ab21d906` in
`sources/lattice-hd-wallets`. The experimental RISC-V backend is pinned at
`06e5c9cd6981103786f9d0a17324241b559a50d3`. Both checkouts remain unchanged.
The new verifier is Rust `no_std`; host fixtures use the pinned Python code.

## Verified relation

The guest reads a **16,144-byte full public key**, a **32-byte original message**
and a **20,768-byte signature**. Its profile uses `N=256`,
`q=562949953438721`, `k=ell=9`, challenge weight 23, `nu_t=35` and `nu_w=38`.
It checks every seven-byte coefficient is below `q` and every hint below 2048.
The full public key enters `tr=SHAKE256(pk)[0:32]`, then
`mu=SHAKE256(tr||message)[0:32]`. Matrix expansion, challenge sampling, all SHAKE
operations, NTTs, the reconstructed commitment hash and the norm execute inside
the VM. The host supplies no unchecked digest, matrix, acceptance bit or arithmetic
advice. SHAKE uses the official SDK's **software** Keccak permutation; there is
no RISC-V Keccak precompile.

Ring multiplication uses canonical Montgomery64 arithmetic. A product is below
`2^100`, and the Montgomery correction below `2^114`, so its `u128` addition
cannot overflow. The hot path uses multiply-high operations and shifts, without
division by the 50-bit modulus. Matrices are expanded one polynomial at a time.
Only nine transformed `z` polynomials and a few scratch polynomials are retained.

The executable authors' code rounds the full `t` and rescales it by `2^35` during
verification. Its comments saying that `t` is used directly are inconsistent
with its body. This port follows the executable equation. Publishing full `t`
still preserves exact addition for host-side public child derivation.

The norm check is exact integer arithmetic on centered `z` and scaled hints:

```
sum(center_q(z)^2) + 2^76 * sum(center_2048(h)^2)
    <= 25650475979193785709999263840
```

This threshold is `floor(B^2)` for the source's ideal real-valued depth-1000 bound
expression. [An exact rational certificate](review/norm-bound-certificate.json)
encloses its exponential and square roots tightly enough to establish that floor.
The port intentionally does not reproduce Python binary64 square-root rounding.
Challenge-consistent controls at the exact threshold pass; controls one integer
unit above it fail, while the source's float predicate accepts them. This is an
explicit profile difference. It must be retained in the report until the paper's
intended bound is checked. Centering at the even-modulus hint midpoint follows
the source convention. Norm accumulation rejects early and cannot overflow `u128`.

## Public binding and wallet scope

The output is the SDK BLAKE2s commitment to these little-endian words:

```
32-byte domain "pqbench/raccoong/hd-poc/strictv1"
count as LE64
for each ordered record: full public-key bytes || original message bytes
```

Every key and message is included. Receivers must derive this digest from their
intended records and pin the approved ELF. Signatures are witnesses. `MAX_BATCH=64`
and the 4 MiB advice region are transport bounds, **not measured proving limits**.
Unused advice beyond the declared count is outside this relation. Plain backend
proofs do not add zero knowledge automatically.

The host generator also exercises master-key generation, hardened and non-hardened
derivation, watch-only derivation and signing at derived keys. It uses the authors'
Gaussian sampler, KDF, deterministic test entropy and explicit signing coins.
Public and private non-hardened derivation agree byte-for-byte in the controls.
These are public test keys, never wallet keys. The RISC-V proof verifies the final
signature; **it does not prove a derivation path or root/xpub membership**. That
would require a separate authenticated statement.

## Build and correctness checks

From the project root:

```sh
python3 risc-v/raccoon-g/build_guest.py
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/raccoong-correctness-target" \
 cargo +stable test --release --locked --offline \
 --manifest-path risc-v/raccoon-g/host/Cargo.toml
```

The build checks both repository revisions and cleanliness, then records compiler,
source, executable, oracle-fixture and norm-certificate hashes. `guest/Cargo.lock`
and `host/Cargo.lock` are pinned. The host API mirrors the ML-DSA port:
`ELF`, `record`, `records`, `batch`, `batch_range`, `run_from_records` and
`expected_output`. `record(index)` loads a deterministic fixture or invokes the
Python generator outside any proving timer, then independently verifies it natively.
The generator requires pinned `pycryptodome` and `mpmath`; its details are in the
[fixture record](review/oracle-fixtures.md).

The release correctness suite checks Montgomery multiplication against independent
integer modular arithmetic, NTT products against schoolbook negacyclic convolution,
SHAKE known answers and streaming boundaries, and source-oracle `mu`, challenge
and matrix values. It executes honest signatures, derived-key signatures, modified
claims and malformed encodings in the actual RISC-V interpreter. Exact norm-bound
controls isolate the norm from the challenge equation. Detailed outcomes are in
[IMPLEMENTATION-CHECKS.md](review/IMPLEMENTATION-CHECKS.md).

No STARK production, witness-capacity search or performance benchmark has run for
this port. Those experiments require the user's explicit approval.
