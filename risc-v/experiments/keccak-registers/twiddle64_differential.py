#!/usr/bin/env python3
"""Independent oracle for the two-type-change NTT optimization. No proving."""
from pathlib import Path
import hashlib,json,re,subprocess

ROOT=Path(__file__).resolve().parents[3]
OWN=Path(__file__).resolve().parent
BASE=ROOT/'vendor/ETHDILITHIUM/c-ref'
CAND=ROOT/'risc-v/experiments/mldsa-poly64/c-ref'
OUT=OWN/'twiddle64-review';OUT.mkdir(exist_ok=True)

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

changed=[]
for p in BASE.iterdir():
 if p.suffix in ('.c','.h') and (CAND/p.name).exists() and p.read_bytes()!=(CAND/p.name).read_bytes():changed.append(p.name)
assert changed==['ntt.c'],changed
baseline=(BASE/'ntt.c').read_text();candidate=(CAND/'ntt.c').read_text()
expected=baseline.replace('static const int32_t zetas[N]','static const int64_t zetas[N]').replace('  int32_t zeta, t;','  int64_t zeta;\n  int32_t t;').replace('  int32_t t, zeta;','  int32_t t;\n  int64_t zeta;')
assert candidate==expected,'Unexpected NTT edits beyond twiddle/local width'
values=list(map(int,re.findall(r'-?\d+',baseline.split('zetas[N] = {')[1].split('};')[0])))
assert len(values)==256 and max(abs(v) for v in values)<2**31
for label,text in [('baseline',baseline),('candidate',candidate)]:
 text=text.replace('void ntt(',f'void {label}_ntt(').replace('void invntt_tomont(',f'void {label}_invntt_tomont(')
 (OUT/f'{label}.c').write_text(text)
driver=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
void baseline_ntt(int32_t *a);void candidate_ntt(int32_t *a);
void baseline_invntt_tomont(int32_t *a);void candidate_invntt_tomont(int32_t *a);
static uint64_t rng=0x6a09e667f3bcc909ULL;
static uint64_t random64(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
int main(void){
 unsigned comparisons=0;
 for(unsigned test=0;test<192;test++){
  int32_t a[256],b[256];
  for(unsigned i=0;i<256;i++){
   int32_t value=(int32_t)(random64()%8380417);
   switch(test){case 0:value=0;break;case 1:value=1;break;case 2:value=8380416;break;case 3:value=-8380416;break;case 4:value=(i&1)?8380416:-8380416;break;default:if(test<16)value=(i==test-5)?8380416:0;else if(test&1)value=-value;}
   a[i]=b[i]=value;
  }
  baseline_ntt(a);candidate_ntt(b);assert(!memcmp(a,b,sizeof a));comparisons++;
  for(unsigned i=0;i<256;i++){int32_t reduced=a[i]%8380417;if(reduced<0)reduced+=8380417;a[i]=b[i]=reduced;}
  baseline_invntt_tomont(a);candidate_invntt_tomont(b);assert(!memcmp(a,b,sizeof a));comparisons++;
  for(unsigned i=0;i<256;i++){a[i]=b[i]=(int32_t)(random64()%8380417);if(test&1)a[i]=b[i]=-a[i];}
  baseline_invntt_tomont(a);candidate_invntt_tomont(b);assert(!memcmp(a,b,sizeof a));comparisons++;
 }
 printf("%u exact full-array comparisons passed\n",comparisons);return 0;
}
'''
(OUT/'driver.c').write_text(driver)
command=['clang','-O3','-g','-fno-strict-aliasing','-DETHDILITHIUM=0','-DDILITHIUM_MODE=2','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',str(BASE),str(OUT/'baseline.c'),str(OUT/'candidate.c'),str(BASE/'reduce.c'),str(OUT/'driver.c'),'-o',str(OUT/'check')]
subprocess.run(command,check=True,capture_output=True,text=True)
made=subprocess.run([str(OUT/'check')],check=True,capture_output=True,text=True)
assert '576 exact full-array comparisons passed' in made.stdout
report={'scope':'Independent NTT-width equivalence, no proof production','changed_reference_files':changed,'exact_expected_diff':True,'twiddle_count':len(values),'max_absolute_twiddle':max(abs(v) for v in values),'int32_twiddle_bounds_checked':True,'coefficients_and_t_remain_int32':True,'montgomery_reduce_unchanged':sha(BASE/'reduce.c')==sha(CAND/'reduce.c'),'arrays':192,'full_array_comparisons':576,'oracle':'Original pinned C NTT, shared unchanged Montgomery reduction','sanitizers':'AddressSanitizer + UndefinedBehaviorSanitizer, no recovery','command':command,'stdout':made.stdout,'stderr':made.stderr,'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in [BASE/'ntt.c',CAND/'ntt.c',BASE/'reduce.c',CAND/'reduce.c',OUT/'driver.c',OUT/'baseline.c',OUT/'candidate.c']}}
(OWN/'twiddle64-independent-results.json').write_text(json.dumps(report,indent=2)+'\n');print(made.stdout.strip())
