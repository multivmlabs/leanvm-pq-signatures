#!/usr/bin/env python3
"""Independent integer oracles for the unchanged C NTT; no performance work."""
from ctypes import CDLL, POINTER, c_int64
from hashlib import shake_256, sha256
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
Q, N, G = 549824583172097, 512, 358453792785495
lib = CDLL(str(HERE / "ntt-control.dylib"))
array = c_int64 * N
forward = lib.pqbench_raccoon_ref_polyr_fntt
inverse = lib.pqbench_raccoon_ref_polyr_intt
multiply = lib.pqbench_raccoon_ref_polyr_ntt_cmul
scale = lib.pqbench_raccoon_ref_polyr_ntt_smul
for fn in [forward, inverse]:
    fn.argtypes = [POINTER(c_int64)]
multiply.argtypes = [POINTER(c_int64)] * 3
scale.argtypes = [POINTER(c_int64), POINTER(c_int64), c_int64]

def random_poly(label):
    b = shake_256(label).digest(8*N)
    return [int.from_bytes(b[i:i+8], "little") % Q for i in range(0, len(b), 8)]

def unit(at):
    a = [0]*N
    a[at] = 1
    return a

def direct_product(a,b):
    out = [0]*N
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            k = i+j
            if k < N: out[k] += x*y
            else: out[k-N] -= x*y
    return [v % Q for v in out]

cases = [
    ("zero", [0]*N, random_poly(b"ntt-review-zero")),
    ("unit", unit(0), random_poly(b"ntt-review-unit")),
    ("negacyclic-boundary", unit(N-1), unit(1)),
    ("largest-residues", [Q-1]*N, [Q-1]*N),
    ("dense", random_poly(b"ntt-review-dense-a"), random_poly(b"ntt-review-dense-b")),
]
results=[]
assert pow(G,N,Q)==Q-1
for name,a,b in cases:
    an,bn=array(*a),array(*b)
    forward(an); forward(bn)
    # Direct polynomial evaluation at the specified bit-reversed roots.
    for i in range(N):
        rev=int(f"{i:09b}"[::-1],2)
        root=pow(G,2*rev+1,Q)
        expect=0
        for x in reversed(a): expect=(expect*root+x)%Q
        assert an[i]%Q==expect,(name,i,"forward evaluation")
    roundtrip=array(*an)
    inverse(roundtrip)
    scale(roundtrip,roundtrip,1)  # inverse(forward(a)) is Montgomery-scaled.
    assert list(roundtrip)==a,(name,"round trip")
    product=array()
    multiply(product,an,bn); inverse(product)
    assert list(product)==direct_product(a,b),(name,"negacyclic product")
    results.append({"name":name,"forward_evaluations_checked":N,
                    "roundtrip_coefficients_checked":N,"product_coefficients_checked":N})

out={"schema":1,"status":"passed","cases":results,
     "library_sha256":sha256((HERE/"ntt-control.dylib").read_bytes()).hexdigest(),
     "oracle":"Python arbitrary-precision Horner evaluation and schoolbook negacyclic multiplication",
     "benchmarks_run":False}
(HERE/"independent-ntt.json").write_text(json.dumps(out,indent=2)+"\n")
print(json.dumps(out,indent=2))
