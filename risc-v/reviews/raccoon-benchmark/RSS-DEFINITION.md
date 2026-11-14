# Native memory measurement definition

Source-only review, 2026-11-10. No benchmark, VM, browser or allocation experiment
was run, and no frozen source was changed.

`peak_rss_bytes` in the pinned backend calls
`getrusage(RUSAGE_SELF, &usage)` and reads `usage.ru_maxrss`. It returns the value
unchanged on macOS, where the unit is bytes, and multiplies by 1024 on Linux.
The local macOS `getrusage(2)` manual agrees: maximum resident set size in bytes.
The direct runner records this process-lifetime high-water mark after warmup and
all timed proof calls; the tree runners record it after the complete pipeline.
It is not a per-proof heap counter, nor a sum of memory across separate processes.
Worker threads belong to the measured native process. `RUSAGE_SELF` does not
add the separate Python fixture or receiver processes.

Apple's published kernel implementation assigns `ru_maxrss` from
`MACH_TASK_BASIC_INFO.resident_size_max`. That field uses the lifetime maximum
of the task's `phys_mem` ledger. It is distinct from the `phys_footprint` ledger.
Calling these measurements peak process RSS is therefore appropriate; calling
them physical-footprint measurements is not. See Apple's
[getrusage implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c#L1694)
and [task-information implementation](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/task.c#L5167).
These published sources were checked on the review date, alongside the local OS
manual; this review does not assert a source-level identity for the installed
kernel binary.

The external guard requests `ps -o rss= -p PID`. macOS reports that field in
1024-byte units, so both study launchers correctly multiply it by 1024 before
comparison with `limit_gib * 1024**3`. Apple's
[ps output implementation](https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/print.c)
prints `resident_size/1024`, consistent with the local `ps(1)` manual. This is a
sample of current RSS; it is not the process-lifetime maximum. Each loop sleeps
0.25 seconds after polling, with additional scheduling/command overhead. The
monitor can miss short peaks, including peaks just before process exit. It is
an operational stop policy, not a hard memory allocation cap.

For the article, the main standard direct N=1 value is the high-water mark of
one process containing one warmup and three timed calls. The earlier cold pilot
is a different process and allocator cohort. Neither value measures Wasm linear
memory or a browser's JavaScript heap. Native RSS includes the process's resident
code, data, stacks, allocator pages and runtime/prover buffers. It provides
evidence of a demanding native workload, but translating it into a browser heap
requirement would require an actual port and browser measurements.

Relevant local sources:

- `vendor/leanVM-riscv/crates/bench/src/heap.rs:242`.
- `risc-v/raccoon-optimized-study/direct/src/main.rs:441`.
- `risc-v/raccoon-optimized-study/tree/src/main.rs:640`.
- `risc-v/experiments/raccoong-segmented/runner/src/main.rs:514`.
- `risc-v/raccoon-optimized-study/study.py`, `Study.run`.
- `risc-v/experiments/raccoong-segmented/matrix.py`, `Matrix.run`.
