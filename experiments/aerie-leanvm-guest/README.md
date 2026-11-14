# Complete Aerie verifier guest

This guest runs the original public Aerie Falcon-512 aggregate verifier inside
leanVM RV64IM. It parses the canonical ordered statement, verifies every inner
Aerie relation and commits a digest of the exact statement. It receives no
Falcon signature witnesses or host acceptance flag.

The public output is `leanvm_guest::commit` applied to the four little-endian
words of `aerie_wrapper_format::claim_digest(records, statement)`. The outer
receipt verifier must independently reconstruct that digest from the intended
public keys and messages, and check the trusted guest program identity.

## Build

```sh
rustup toolchain install nightly-2026-10-03 --component rust-src
python3 experiments/aerie-leanvm-guest/build_guest.py
```

The build uses its committed Cargo.lock, RV64IM core and alloc, the local
single-thread std subset, and the pinned leanVM SDK. The linker launcher keeps
the pinned Rust linker and makes its bundled LLVM library visible on macOS.
Logs are written to `artifacts/aerie-wrapper/guest-{std,full}-build.log`.

Public setup exports must first exist at the paths listed in
`trusted-setup-sha256.json`. Their expected SHA-256 values are checked before
compilation. Recreate them with the native input producer:

```sh
for n in 1 10 30 70 100; do
  .cache/aerie-target/release/aerie-wrapper-inputs --export-setup "$n" "artifacts/aerie-wrapper/public-setup/n$n"
done
CARGO_HOME="$PWD/.cache/aerie-cargo" CARGO_TARGET_DIR="$PWD/.cache/aerie-target" cargo +stable run --offline --release --manifest-path experiments/aerie-q64-cache-check/Cargo.toml -- "$PWD"
```

The default features embed those immutable public matrix banks and three exact
Q64 terminal NTT cache blobs in the ELF. The cache checker validates the derived
matrices against direct ring arithmetic and original aggregate proofs before
export. Cache SHA-256 values are pinned in `trusted-cache-sha256.json`, checked
both by the build helper and Cargo build script. Cache bytes are trusted public
verification-key data and are never read from advice. `--no-terminal-cache`
recreates terminal transforms inside the guest. Supported record counts are 1, 10, 30, 70 and 100. The original
`FalconVerifierSetup::new` baseline remains in the source and can be selected
with `python3 experiments/aerie-leanvm-guest/build_guest.py --derive-setup`.
Native export validates a canonical round trip against the fixed seeded setup;
the guest checks the pinned seed, dimensions, matrix length and prefix registry.

## Runtime and input

Advice is an unsigned 64-bit byte length followed by the complete
`aerie-wrapper-format` frame, packed in little-endian 64-bit words with zero
padding. The guest checks the byte limit, padding, frame lengths, proof profile,
canonical statement and record count before verification. The current image
reserves 1 MiB advice, 16 MiB RAM and a 1 MiB stack gap. Its reclaiming allocator
returns transient verification allocations to the heap.

The std subset is specifically for one uninterrupted execution thread. It has
no operating-system calls, clock, entropy source or thread creation. Arc uses
Rc and atomic operations use single-hart cells. Unsupported entropy fails.
Standard in-memory codecs come from the pinned Rust `alloc::io`; float methods
use real libm operations and the original Rust integer-power intrinsic.

Aerie uses an owned overlay that prepares only its deterministic PCS schedule,
through the original Akita `for_selection` API. `--all-schedules` restores the
original preparation. The diff and source hashes are in
`../aerie-port/aerie-overlay.{json,patch}`. The Akita overlay adds Q64 public cache import/export and field-based cache
selection; its reviewed patch and hashes are in
`../../results/aerie-wrapper/akita-q64-cache-overlay.json` and `../../results/aerie-wrapper/akita-q64-cache.patch`.
Field arithmetic, transcript, hash, sumcheck and proof verification checks remain
unchanged. Platform-only copied registry adapters are listed with source
hashes and a compact diff in `../aerie-port/platform-patches.json` and
`../aerie-port/platform.patch`.
