#!/usr/bin/env python3
"""Compare original and twiddle64 native verifiers under isolated symbols."""
from pathlib import Path
import ctypes
import hashlib
import json
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=ROOT/'risc-v/mldsa'
REFERENCE=ROOT/'vendor/ETHDILITHIUM/c-ref'
sys.path.insert(0,str(ROOT/'leanISA/python'))
from pqbench.mldsa import verify_python

FILES=('sign','packing','polyvec','poly','ntt','reduce','rounding','fips202','symmetric-shake')

def build(ref,label):
    text=(ref/'sign.c').read_text()
    start=text.index('int crypto_sign_verify(')
    body=text[start:text.index('/*************************************************',start)]
    body=body.replace('int crypto_sign_verify(', '__attribute__((visibility("default"))) int trial_verify_internal(',1)
    body=body.replace('  shake256_absorb(&state, mu, 2);','').replace('  shake256_absorb(&state, ctx, ctxlen);','')
    source=HERE/f'{label}-test-adapter.c'
    source.write_text(text[:text.index('/*************************************************')]+body+'''
__attribute__((visibility("default")))
int trial_verify_pure(const uint8_t *sig,size_t slen,const uint8_t *msg,size_t mlen,const uint8_t *ctx,size_t clen,const uint8_t *pk) {
 return crypto_sign_verify(sig,slen,msg,mlen,ctx,clen,pk);
}
int pqbench_mldsa_fixture(uint64_t,uint8_t*,uint8_t*,uint8_t*);
__attribute__((visibility("default")))
int trial_fixture(uint64_t n,uint8_t *pk,uint8_t *sig,uint8_t *msg) {return pqbench_mldsa_fixture(n,pk,sig,msg);}
''')
    lib=HERE/f'{label}.dylib'
    command=['clang','-shared','-fPIC','-O3','-fno-strict-aliasing','-fvisibility=hidden','-ffunction-sections','-fdata-sections','-Wl,-dead_strip','-DETHDILITHIUM=0','-DDILITHIUM_MODE=2',
             '-I',str(BASE/'c/include'),'-I',str(ref),str(BASE/'c/adapter.c'),str(source)]
    command += [str(ref/(name+'.c')) for name in FILES]
    command += ['-o',str(lib)]
    subprocess.run(command,check=True)
    loaded=ctypes.CDLL(str(lib),mode=ctypes.RTLD_LOCAL)
    for name in ['trial_verify_pure','trial_verify_internal']:
        fn=getattr(loaded,name);fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p];fn.restype=ctypes.c_int
    loaded.trial_fixture.argtypes=[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
    loaded.trial_fixture.restype=ctypes.c_int
    return loaded,command

def verify(lib,pk,msg,sig,internal=False):
    fn=lib.trial_verify_internal if internal else lib.trial_verify_pure
    return fn(sig,len(sig),msg,len(msg),b'',0,pk)==0

def fixture(lib,n):
    pk=(ctypes.c_ubyte*1312)();sig=(ctypes.c_ubyte*2420)();msg=(ctypes.c_ubyte*32)()
    assert lib.trial_fixture(n,pk,sig,msg)==0
    return bytes(pk),bytes(msg),bytes(sig)

def main():
    original,original_command=build(REFERENCE,'original')
    changed,changed_command=build(HERE/'c-ref','twiddle64')
    cases=[]
    def check(name,pk,msg,sig,expected,internal=False,python=False):
        a=verify(original,pk,msg,sig,internal);b=verify(changed,pk,msg,sig,internal)
        p=verify_python(pk,msg,sig,internal=internal) if python else None
        passed=a==b==expected and (not python or p==expected)
        cases.append({'name':name,'original':a,'twiddle64':b,'python':p,'expected':expected,'passed':passed})
        assert passed,cases[-1]
    records=[]
    for n in range(12):
        pk,msg,sig=fixture(original,n)
        assert (pk,msg,sig)==fixture(changed,n),'Twiddle widening altered deterministic signing/keygen'
        records.append({'compact_public_key_hex':pk.hex(),'message_hex':msg.hex(),'compact_signature_hex':sig.hex()})
        check(f'pure-valid-{n}',pk,msg,sig,True,python=True)
        changedmsg=bytes([msg[0]^1])+msg[1:]
        check(f'changed-message-{n}',pk,changedmsg,sig,False,python=True)
        changedkey=bytes([pk[0]^1])+pk[1:]
        check(f'changed-key-{n}',changedkey,msg,sig,False,python=True)
    pk,msg,sig=fixture(original,0)
    for i in range(len(sig)):
        bad=bytearray(sig);bad[i]^=1
        check(f'signature-bit-{i}',pk,msg,bytes(bad),False)
    for i in range(len(pk)):
        bad=bytearray(pk);bad[i]^=1
        check(f'key-bit-{i}',bytes(bad),msg,sig,False)
    acvp_path=REFERENCE.parent/'pythonref/assets/ML-DSA-sigVer-FIPS204/internalProjection.json'
    official=json.loads(acvp_path.read_text())
    for group in official['testGroups']:
        if group['parameterSet']!='ML-DSA-44':continue
        for test in group['tests']:
            check('official-internal-'+str(test['tcId']),bytes.fromhex(group['pk']),bytes.fromhex(test['message']),bytes.fromhex(test['signature']),test['testPassed'],True,True)
    (HERE/'fixtures.json').write_text(json.dumps(records,indent=2)+'\n')
    report={'scope':'Native original-vs-twiddle64 differential checks. Official ACVP vectors use a test-only internal interface; production guest remains pure32-byte empty-context.',
            'commands':{'original':original_command,'twiddle64':changed_command},'compiler':subprocess.check_output(['clang','--version'],text=True).strip(),
            'official_vectors_sha256':hashlib.sha256(acvp_path.read_bytes()).hexdigest(),'deterministic_fixture_bytes_equal':12,
            'case_count':len(cases),'all_passed':all(x['passed'] for x in cases),'cases':cases}
    (HERE/'native-checks.json').write_text(json.dumps(report,indent=2)+'\n')
    print({'cases':len(cases),'all_passed':report['all_passed'],'fixtures_identical':12})

if __name__=='__main__':main()
