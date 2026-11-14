# Independent review of the ML-DSA twiddle-width trial

Scope: `../mldsa-poly64/c-ref/ntt.c`, compared with the unchanged pinned C
reference at `vendor/ETHDILITHIUM`, commit
`f9f4fe1d84e68304b425e054c273c276fe44ba11`. This is an independent source and
native differential check, not proof production or a full C implementation audit.

The candidate changes the storage of the 256 fixed NTT twiddles and each
function's local `zeta` from `int32_t` to `int64_t`. Coefficient arrays, the local
`t`, function signatures and every reduction function remain unchanged. An exact
source comparison confirmed that `ntt.c` is the only changed `.c`/`.h` reference
file and that its differences are exactly those three declaration changes.

The width change preserves the arithmetic:

1. Every listed twiddle fits in signed 32 bits, so loading its 64-bit
   representation gives the same signed integer as the original load and sign
   extension.
2. In the forward transform, the original product already explicitly casts
   `zeta` to `int64_t`. Widening `zeta` earlier therefore leaves that product
   unchanged.
3. In the inverse transform, negation of each twiddle is safe in both widths:
   none is `INT32_MIN`. Its subsequent product also already uses an explicit
   64-bit cast.
4. The deliberate low-32-bit truncation inside Montgomery reduction is
   unchanged. The patch does not widen the polynomial coefficients or the
   reduction variable, nor remove any hint, norm or encoding check.

For the bounded input vectors tested, forward butterfly products reduce into
`(-q,q)` and eight addition layers remain far below signed 32-bit overflow.
Inverse inputs bounded by `q-1` have a conservative eight-layer sum bound
`256*(q-1) = 2,145,386,496`, below `INT32_MAX`. Products are computed in 64 bits,
as before. These checks establish that the selected test domain does not rely on
new signed overflow behavior; they are not a proof of every caller's precondition.

`twiddle64_differential.py` compiled both transforms under independent names,
sharing only the unchanged reference Montgomery reduction. It compared 192
arrays, including zero, ones, positive/negative boundary coefficients, sparse
vectors and deterministic random arrays. Forward NTT, inverse after coefficient
normalization, and standalone inverse produced **576 exact full-array matches**.
The executable ran with AddressSanitizer and UndefinedBehaviorSanitizer, recovery
disabled, with no sanitizer report. Raw commands, source hashes and results are
in `twiddle64-independent-results.json`.

This is a legitimate representation optimization for RV64's 64-bit loads. Its
benefit must still be measured and the resulting guest must actually prove and
verify the seven-signature batch before that proof capacity is claimed. The
separate PR #605 assembly trial in this directory is not used by this candidate.
