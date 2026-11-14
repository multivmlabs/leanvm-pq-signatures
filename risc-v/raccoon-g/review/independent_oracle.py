#!/usr/bin/env python3
"""Review-only independent hashlib, integer arithmetic and source-profile checks."""
from pathlib import Path
from hashlib import shake_128,shake_256,sha256
from decimal import Decimal, localcontext
import json

HERE=Path(__file__).resolve().parent
Q,N=562949953438721,256

class Stream:
    def __init__(self,x): self.x,self.position=x,0
    def read(self,n):
        out=self.x.digest(self.position+n)[self.position:]
        self.position+=n
        return out

def matrix(seed,row,col):
    x=Stream(shake_128(bytes([65,row,col,0,0,0,0,0])+seed))
    out=[]
    while len(out)<N:
        v=int.from_bytes(x.read(7),'little')&((1<<50)-1)
        if v<Q: out.append(v)
    return out

def challenge(h):
    x=Stream(shake_256(bytes([99,23,0,0,0,0,0,0])+h))
    out=[0]*N
    while sum(v!=0 for v in out)<23:
        v=int.from_bytes(x.read(2),'little');at=(v>>1)&255
        if out[at]==0: out[at]=1 if v&1 else Q-1
    return out

def product(a,b):
    out=[0]*N
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            if i+j<N: out[i+j]+=x*y
            else: out[i+j-N]-=x*y
    return [x%Q for x in out]

def main():
    path=HERE/'independent-arithmetic-dump.json'
    data=json.loads(path.read_text())
    mont=data['montgomery']
    assert mont['Q']==Q
    assert mont['ONE']==2**64%Q
    assert mont['R2']==2**128%Q
    assert mont['NI']==pow(N,-1,Q)*(2**64%Q)%Q
    assert (Q*mont['QINV'])%(2**64)==2**64-1
    for row in data['shakes']:
        oracle=shake_128 if row['rate']==168 else shake_256
        assert oracle(bytes.fromhex(row['input'])).digest(401).hex()==row['output']
    seed=bytes.fromhex(data['seed'])
    for row in range(9):
        for col in range(9): assert data['matrix'][9*row+col]==matrix(seed,row,col),(row,col)
    assert data['challenge']==challenge(bytes.fromhex(data['challenge_hash']))
    for base in [2,3,5,7,11]:
        psi=pow(base,(Q-1)//(2*N),Q)
        if pow(psi,N,Q)==Q-1: break
    else: raise AssertionError('primitive root not found')
    for case in data['polynomials']:
        a,b=case['a'],case['b']
        assert case['roundtrip']==a
        assert case['product']==product(a,b),case['name']
        for i in range(N):
            rev=int(f'{i:08b}'[::-1],2)
            at=pow(psi,2*rev+1,Q)
            v=0
            for x in reversed(a): v=(v*at+x)%Q
            assert v==case['forward'][i],(case['name'],i)
    with localcontext() as ctx:
        ctx.prec=150
        radius=(Decimal(1)/4).exp()*(Decimal(1000).sqrt()*23*2**7+2**40)*Decimal(256*18).sqrt()+Decimal((23*2**35+2**39)*48)
        threshold=int(radius**2)
        assert threshold==25650475979193785709999263840
    out={'schema':1,'status':'passed','scope':'Independent correctness oracles, not a parameter security estimate',
         'hashlib_streaming_shake_cases':len(data['shakes']),'all_matrix_polynomials_checked':81,
         'all_matrix_residues_checked':81*N,'full_challenge_coefficients_checked':N,
         'ntt_cases':len(data['polynomials']),'forward_coordinates_checked':N*len(data['polynomials']),
         'schoolbook_product_coefficients_checked':N*len(data['polynomials']),
         'integer_threshold':str(threshold),'dump_sha256':sha256(path.read_bytes()).hexdigest(),
         'benchmarks_run':False,'prover_invoked':False}
    (HERE/'independent-arithmetic-validation.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out,indent=2))

if __name__=='__main__': main()
