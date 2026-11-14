
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
