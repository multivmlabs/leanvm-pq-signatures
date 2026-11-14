# Aerie verifier target under leanVM

The wrapper uses the real RV64IM interpreter and proof system in leanEthereum/leanVM's `riscv-exploration` branch, pinned to `06e5c9cd6981103786f9d0a17324241b559a50d3`. It is separate from the custom ISA checkout used by the earlier signature experiments. Aerie is pinned to `49b6c212c209286c536196f53618823ffdf0e899`, Akita to `e023b6a46143f7b23199ccecb2684192baf7b640`, and Jolt to `c7c2d08d5bb0c7c80501f29f723e595af7fcff3c`.

The guest must execute the complete `verify_aggregate` relation. A native acceptance bit, an arithmetic kernel, and a transcript hash alone do not establish this relation. The public claim binds the canonical ordered public keys and messages, record count, and exact verification profile. The guest commits its claim digest only after full verification succeeds.

The host crate is `experiments/aerie-leanvm-host`. It uses `Program::from_elf`, `Program::measure`, `Prover::prove`, `Proof::{to_bytes,from_bytes}` and `Program::verify`. The last method checks the full proof, including deferred claims. A separate interpreter-only command uses the public reference `Machine` API. The host never treats `verify_core` as completed verification.

## Guest ABI

The SDK's target is `riscv64im-unknown-none-elf`. A successful exit is `ecall` with register `a7 = 93`; the public output is the four words in `a0..a3`. Other syscalls, privileged CSR instructions, misaligned accesses, and invalid instructions trap.

Advice is memory supplied before execution. It is not a public input and must be checked by guest code. The host packs a frame as one little endian `u64` byte length followed by `ceil(length/8)` little endian words. Only the last word can have zero padding. The guest checks the padding, bounds and frame format, parses the canonical statement, checks its count and verifies the entire Aerie proof.

The shared frame and claim rules live in `experiments/aerie-wrapper-format`. The frame header is `AERLVM01`, record count, statement byte length and proof byte length, each length/count encoded as a little endian `u64`, followed by the statement and proof. The parser requires exact consumption.

SDK `commit` hashes its word stream with BLAKE2s. Both sides convert the shared 32-byte claim digest into four little endian `u64`s. The guest calls `commit(&words)`. The receiver derives `Output::new(PublicValues::new().commit(&words).digest())` using the SDK's equivalent ownership sequence. The expected output is derived from the receiver's intended statement, never selected from a prover report.

The SDK linker script maps text at `0x10000000`, advice at `0x20000000` and RAM at `0x40000000`. `__stack_top` declares RAM size; `__advice_top` declares advice size. Both are part of the decoded program identity. Advice and RAM sizes must be powers of two in words. Larger memory regions can consume commitment capacity even if most memory is unused, so the guest chooses explicit region sizes.

## Rust runtime constraints

Jolt's existing `guest-std` path cannot be used unchanged. Its ZeroOS startup installs a CSR trap handler, and its standard library uses Linux syscalls. leanVM has neither interface. Using the existing Jolt guest source is useful for its full verifier call, but compiling the unchanged Jolt runtime would not produce a runnable leanVM guest.

The stock Rust `riscv64im-unknown-none-elf` target also advertises atomic loads/stores but no atomic compare-and-swap, whereas Aerie's dependencies use `Arc`. A standard library/runtime adaptation must preserve verifier semantics and supply only deterministic allocation, single-thread synchronization and non-semantic timing interfaces. No cryptographic check may be replaced by a host result.

## Host commands

Every command requires an independently configured trusted ELF SHA-256. The command must not learn this trust anchor from an untrusted receipt. `--threads` sets the exact pool size, including its dispatcher. `--rate` is the base-two logarithm of the inverse commitment rate. The default profile produces plain STARKs; `--zk` requests the backend's separate zero knowledge protocol with fresh operating-system randomness.

```text
aerie-leanvm-host execute --elf GUEST --expect-elf-sha256 HASH --input input.frame --report execution.json --repeat 3 --warmup 1 --threads 12
aerie-leanvm-host inspect --elf GUEST --expect-elf-sha256 HASH --report static-floor.json --threads 12
aerie-leanvm-host interpret --elf GUEST --expect-elf-sha256 HASH --input input.frame --report interpreter.json --max-cycles 1000000000 --repeat 1 --warmup 0 --threads 12
aerie-leanvm-host prove --elf GUEST --expect-elf-sha256 HASH --input input.frame --proof outer.proof --report proving.json --repeat 3 --warmup 1 --threads 12 --rate 1
aerie-leanvm-host verify --elf GUEST --expect-elf-sha256 HASH --statement statement.bin --records 30 --proof outer.proof --report verification.json --repeat 3 --warmup 1 --threads 12
```

`execute` calls the count-only interpreter. It runs all guest code but does not inspect the discarded exit words, which its report states explicitly. `prove` checks exit words, serializes, decodes and fully self-verifies each proof. `verify` runs in a fresh process with the trusted program, intended public statement, record count and outer proof. The receiver needs no frame, Aerie proof, salts, or original Falcon signature witnesses.

`interpret` runs the same reference RV64IM machine with an explicit instruction limit, checks its exit words, and counts executed instructions. It can finish a verifier that exceeds one proof's capacity, since it does not record a trace or apply a commitment capacity check. These execution numbers are separate from proving benchmarks; successful interpretation does not establish that an outer proof fits.

Interpretation also reports exact executed rows per instruction class. Its conservative witness lower bound includes class and clock packed witnesses at independently rounded heights, omitting shared columns and additional fill rows. This is a capacity diagnostic, not proof size. The interpret-only `--profile-counts` option records every nonzero program-counter count in address order as `instruction_profile`, for exact grouping against that ELF's symbols. Profiled timings include counter collection and must be kept separate from ordinary interpretation; JSON formatting is excluded.

`inspect` appends a two-instruction synthetic exit to the original text, retains its complete image and memory regions, and checks that the decoded bytecode height is unchanged. It measures that synthetic exit to distinguish a static code/memory capacity floor from the cost of executing the real verifier. It does not execute Aerie or generate a proof. The host configures the exact worker pool before ELF decoding, which can itself initialize parallel hashing.

The execute/interpret-only `--raw-negative-input` test flag packs malformed frames directly so rejection controls reach the unchanged guest parser. It cannot be used to produce or verify proofs. Raw interpretation has no expected output claim; if malformed input unexpectedly exits, it reports the observed output and `public_output_checked=false` so the test driver can flag the unexpected acceptance. Normal execution/proving also rejects malformed frames on the host before execution.

The execute/interpret-only `--nonzero-advice-padding` flag changes the first padding byte in the packed advice to one, preserving the declared length and all live frame bytes. The guest must reject it. Frames whose byte length is divisible by eight have no padding and are refused by this test option. This flag is unavailable in inspection, proving and receipt verification. Interpretation can reach late rejection checks without the proof-capacity limit; it does not generate a proof.

The proof file is exactly `Proof::to_bytes()`, including the leanVM protocol envelope, with zero additional framing bytes. Intended transaction/public statement data and the trusted program are separate verification inputs. Reports separate execution, proving, serialization and full verification timings, raw repeated samples, per-table row counts, committed words, allocator peak and process peak RSS.

This leanVM revision has no continuations. `TooLong` means the whole run does not fit one commitment. It is a measured capacity failure, not a proof, a completed guest verification, or a zero-cost benchmark. Error reports retain the elapsed attempt, native error and memory peak. No claim about proof size or proving time can be inferred from a rejected run.

Source references: [leanVM RV64IM branch](https://github.com/leanEthereum/leanVM/tree/06e5c9cd6981103786f9d0a17324241b559a50d3), [Aerie verifier](https://github.com/a16z/aerie/tree/49b6c212c209286c536196f53618823ffdf0e899), and [Jolt runtime](https://github.com/a16z/jolt/tree/c7c2d08d5bb0c7c80501f29f723e595af7fcff3c/jolt-sdk/src/runtime).
