# FORS capacity re-audit

Rechecked 6 November 2026. This report preserves the earlier measurements and
does not change the FORS relation, its hash, the guest, the backend, the
commitment cap, or any verifier checks.

## Findings

1. **The old 100-signature result is real.** A fresh 100-signature proof was
   produced and fully verified again. The independently recomputed public claim
   agrees with the saved statement. A separate process then verified the new
   proof using its witness-free statement and pinned guest/public-input values.
2. **The current RISC-V eight-signature refusal is also real.** The unchanged
   eight-signature guest completes on the reference interpreter and returns the
   correct public output, so this is not an invalid signature, advice bound or
   RAM trap. Its packed circuit witnesses alone already exceed the supported
   commitment size. This diagnostic is not a STARK proof.
3. **The main change is losing a Keccak-specific VM instruction.** The old
   backend proves each Keccak permutation with a specialized Keccak argument.
   The RISC-V backend's special hash instruction is BLAKE2s; FORS's Keccak is
   implemented by ordinary RV64IM instructions. The unchanged RISC-V guest
   spends approximately **94.1% of its executed instructions inside Keccak-f**.
4. **Seven is a property of this guest/kernel/input schedule, not a fundamental
   FORS limit or an inherent RISC-V limit.** A faster equivalent software
   permutation may improve it. A Keccak precompile would be a backend change.

The previous recommendation that RISC-V is useful for reusing integer-based
lattice verification code should not be interpreted as a prediction that every
signature workload improves. FORS is a counterexample to that prediction.

## Pinned programs and proof evidence

- Old backend: `575df819d9c857f38068cecf7b1640e0ce4bfb29`.
- RISC-V backend: `06e5c9cd6981103786f9d0a17324241b559a50d3`.
- RISC-V guest ELF SHA-256:
  `64480a3bf424f97578f6477a7a4045c2452853a0801f45fc191648eb253e36da`.
- Same FORS verification relation: `n=32`, `k=16`, `a=8`, Ethereum Keccak-256,
  the fixed message/leaf/node/root domains and tree/height/index addresses.
- Public batch-output hashing differs between the SDKs: the old guest hashes
  the ordered claim list with Keccak; the new guest commits profile, count and
  ordered public headers through SDK BLAKE2s. This difference does not remove
  or replace any of FORS's 150 Keccak permutations per signature.

| Case | Executed instructions | Committed witness words | Proof bytes | Proof status |
|---|---:|---:|---:|---|
| Archived guest, 1 signature | 7,534 | 470,016 | 239,992 | Earlier saved proof verified |
| Archived guest, 100 signatures | 751,127 | 19,439,616 | 305,176 | Fresh proof and separate verification passed |
| RISC-V guest, 1 signature | 916,420 | 42,128,704 | 333,978 | Existing saved proof verified |
| RISC-V guest, 7 signatures | 6,413,707 | 212,148,312 | 390,222 | Existing saved proof verified |
| RISC-V guest, 8 signatures | 7,329,902 | **At least 277,138,688** | No proof | Prover refuses `TooLong` |

Instructions from two different ISAs are not equivalent units of work, so their
ratio is not a normalized proving-speed comparison. The commitment limit is
`2^28 = 268,435,456` words in both pinned backends.

The old 100-signature batch used only about **7.24%** of that cap. It was a
successful tested count, not a demonstrated maximum. The new eight-signature
lower bound includes only packed class and clock witnesses and omits shared
columns, other committed table columns and any additional fill-plan rows.

Fresh archived proof evidence:

- [`old100-claim-recomputed.json`](fors-capacity-probe/old100-claim-recomputed.json):
  independent byte-level public-claim reconstruction without signature values.
- [`old100-fresh-prove.json`](fors-capacity-probe/old100-fresh-prove.json):
  fresh proof, 0.327266291 s proving, 305,176 bytes, native self-verification.
- [`old100-fresh-proof-consumer.json`](fors-capacity-probe/old100-fresh-proof-consumer.json):
  fresh process, witness-free input, full verification passed.
- [`old100-fresh.proof`](fors-capacity-probe/old100-fresh.proof) and its
  [`statement`](fors-capacity-probe/old100-fresh.proof.statement.json).

The one fresh timing above is a reproduction control, not a replacement for the
original three-sample benchmark or a new cross-machine performance comparison.

## Exactly how much Keccak is performed

One signature verifies:

| Hash operation | Input bytes | Calls | Keccak-f permutations |
|---|---:|---:|---:|
| Message-derived leaf indices | 112 | 1 | 1 |
| Opened forest leaves | 96 | 16 | 16 |
| Authentication-path parents | 128 | 16 x 8 | 128 |
| Compress the 16 forest roots | 560 | 1 | 5 |
| **Total signature verification** | | | **150** |

The Keccak-256 rate is 136 bytes. The 560-byte forest-root input requires four
full blocks and one final padded block. It is therefore incorrect to count only
one permutation for that hash.

The old trace's Keccak opcode counts confirm the calculation:

- `N=1`: `150 + 1 = 151` Keccak instructions.
- `N=100`: `15,000 + 71 = 15,071` Keccak instructions, including its batch hash.

For the RISC-V guest, an independent instruction-address probe counts entry to
the exact ELF's Keccak function at `0x10001164`, size 2,448 bytes. It checks the
ELF hash before running and asserts `150*N` function entries. The function takes
5,749 executed instructions per permutation in this compiled guest.

| Signatures | Keccak function entries | Instructions inside Keccak | All instructions | Keccak share |
|---|---:|---:|---:|---:|
| 1 | 150 | 862,350 | 916,420 | 94.10% |
| 7 | 1,050 | 6,036,450 | 6,413,707 | 94.12% |
| 8 | 1,200 | 6,898,800 | 7,329,902 | 94.12% |

The RISC-V trace's `HASH` rows are the BLAKE2s public-output commitments, not
accelerated FORS hashes. The SDK explicitly documents that it has no Keccak
instruction in [`sdk/src/keccak.rs`](../../vendor/leanVM-riscv/sdk/src/keccak.rs).
The old ISA explicitly documents its Keccak instruction and specialized proof
argument in [`cpu/isa.rs`](../../vendor/leanVM/crates/leanvm_core/src/cpu/isa.rs).

## Why precisely the eighth signature crosses the current budget

The ALU table has 3,781,408 real rows at seven signatures, which pads to
`2^22 = 4,194,304`. At eight signatures it has 4,321,584 real rows, forcing that
table to `2^23 = 8,388,608` rows.

Each ALU row occupies 16 packed words for its class circuit and eight for its
clock circuit. Their combined padded contribution therefore doubles from
100,663,296 to 201,326,592 words. Including the other independently rounded
packed circuits gives:

```
seven signatures: 176,475,392 packed witness words
eight signatures: 277,138,688 packed witness words
supported cap:   268,435,456 words
```

That lower bound alone rules out eight in the unchanged backend. The real layout
adds more columns; we do not present the lower bound as its exact total.

The guest permits up to 445 records in 262,144 advice words. Eight records use
only 4,705 advice words. It runs in the unchanged one-MiB RAM map and successfully
finishes with the expected output on the raw interpreter. Its 7.33 million
instructions are also far below the clock's cycle limit. No artificial count,
advice or RAM ceiling explains this failure.

## Reproduction and optimization boundary

Run the independent interpreter diagnostic, not a modified prover:

```sh
CARGO_HOME="$PWD/.cache/riscv-cargo" \
 CARGO_TARGET_DIR="$PWD/.cache/riscv-host-target" \
 cargo +stable run --release --offline \
 --manifest-path risc-v/reviews/fors-capacity-probe/Cargo.toml
```

[`results.json`](fors-capacity-probe/results.json) retains full rows, minimum
padded heights, per-circuit packed-word bounds and checked outputs for counts
1, 7, 8, 9 and 16. The probe deliberately runs the reference interpreter past
the prover's capacity guard to diagnose why the unchanged prover refuses it.
It never disables verification or generates a proof outside the cap.

No duplicate signature verification or duplicate authentication path was found.
Fixed buffers and borrowed advice prevent copying the whole signature per call.
The dominant optimization target is the software permutation's loads, stores
and register use. A separately pinned equivalent Keccak kernel, with full-state
differential tests and new capacity/proof measurements, would be legitimate.
Silently changing FORS to BLAKE2s, trusting host-computed roots, lowering the
security parameters or increasing the commitment cap would change the measured
relation or backend and cannot be called a retry of this experiment.
