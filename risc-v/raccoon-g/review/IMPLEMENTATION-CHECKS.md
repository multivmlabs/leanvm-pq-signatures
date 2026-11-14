# Raccoon-G implementation correctness evidence

Scope: `raccoong-hd-authors-poc-strict-v1`, from authors' commit
`461a5ed9b6d57e3bf8c381be3bb79325ab21d906`, with leanVM RISC-V commit
`06e5c9cd6981103786f9d0a17324241b559a50d3`. This is implementation evidence,
not an independent audit or a completed paper-conformance review.

The current release suite has nine passing tests and 20 actual RISC-V interpreter
executions: eight accepted runs and 12 rejected runs. These do not produce STARKs.
The log is [correctness.log](correctness.log).

- Two honest guest runs cover one and two independent key/message/signature
  records. Every original pair contributes to the expected public output.
- Three guest runs accept a master key, a non-hardened child and a hardened child,
  with signatures produced by the authors' Python implementation.
- Three changes to key, message and challenge reject in the actual guest. Zero
  count, excessive count, a public residue `q`, a response residue `q` and a hint
  residue 2048 also reject.
- Seven algebraic controls have correct challenge equations but isolate the norm:
  zero, exact squared bound and both coefficient signs accept where intended;
  bound plus one, a larger single response and hint midpoint reject. Both signs
  of the exact-bound pair are covered. The source float verifier accepts bound
  plus one, so its disagreement with this strict integer profile is documented.
- Native checks compare 2,048 Montgomery products with independent `u128` modulo
  arithmetic and four NTT products with schoolbook negacyclic multiplication.
  Tests include basis, `q-1` and dense polynomials.
- SHAKE128 and SHAKE256 empty-message answers agree with FIPS 202 vectors.
  Streaming tests cross absorption and squeezing block boundaries.
- Three independent Python vectors agree on full-key hashing, `mu`, all 256
  challenge coefficients and all 256 entries of the first expanded matrix
  polynomial. Public-output checks bind count, order, the last key byte and the
  last message byte.

The independent fixture helper's [oracle-norm.json](oracle-norm.json),
[oracle-arithmetic.json](oracle-arithmetic.json) and
[oracle-fixtures.md](oracle-fixtures.md) retain the source-side controls.
`norm_bound_check.py` supplies an additional exact-rational certificate for the
chosen integer threshold. The canonical decoder deliberately rejects residue
aliases admitted by the authors' permissive decoder.

Remaining checks: read the full paper, resolve profile/theorem and derivation
quantity correspondence, complete an independent security review, then obtain
user approval before STARK production and benchmark experiments. Proof-system
soundness, key-distribution security and HD-path membership are not established
by this suite.
