# FORS with specialised Keccak

The article's FORS workload uses the [Python guest](guests/fors.py) and leanVM
`575df819d9c857f38068cecf7b1640e0ce4bfb29`. Its profile is `n=32, k=16, a=8`,
with 32-byte messages. This is a few-time FORS component, not full SLH-DSA.

- [Exact relation and constraints](docs/fors.md)
- [Direct proof runner](src/main.rs)
- [Direct measurements](results/article/direct)
- [Publicly reproducible input corpus](results/article/inputs/fors-records.json)
- [Recursive reduction implementation](reduction/README.md)
- [Reproduction commands](../docs/reproduce.md)

Shared `pqbench` fixture helpers, recursion support and the `aggregate_falcon.py`
wrapper template are dependencies of the FORS path. The historical template name
does not add a Falcon benchmark to this backend. Earlier standalone lattice experiments and wrappers are omitted.
The backend checkout is supplied by the root bootstrap script; `vendor/leanVM`
and generated-output symlinks resolve relative to this repository.
