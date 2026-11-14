#include <stdio.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "keccak_prng.h"

__attribute__((visibility("default"))) int trial_verify_internal(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
#if ETHDILITHIUM
  inner_keccak256_prng_ctx prng;
#else
  keccak_state state;
#endif

  if (ctxlen > 255 || siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
    return -1;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

/* Compute CRH(H(rho, t1), msg) */
#if ETHDILITHIUM
  inner_keccak256_init(&prng);
  inner_keccak256_inject(&prng, pk, CRYPTO_PUBLICKEYBYTES);
  inner_keccak256_flip(&prng);
  inner_keccak256_extract(&prng, mu, TRBYTES);
  inner_keccak256_init(&prng);
  inner_keccak256_inject(&prng, mu, TRBYTES);
#else
  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
#endif
  mu[0] = 0;
  mu[1] = ctxlen;
#if ETHDILITHIUM
  inner_keccak256_inject(&prng, mu, 2);
  inner_keccak256_inject(&prng, ctx, ctxlen);
  inner_keccak256_inject(&prng, m, mlen);
  inner_keccak256_flip(&prng);
  inner_keccak256_extract(&prng, mu, CRHBYTES);

#else


  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);
#endif

/* Matrix-vector multiplication; compute Az - c2^dt1 */
#if ETHDILITHIUM
  poly_challenge_eth(&cp, c);
#else
  poly_challenge(&cp, c);
#endif

  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

/* Call random oracle and verify challenge */
#if ETHDILITHIUM
  inner_keccak256_init(&prng);
  inner_keccak256_inject(&prng, mu, CRHBYTES);
  inner_keccak256_inject(&prng, buf, K * POLYW1_PACKEDBYTES);
  inner_keccak256_flip(&prng);
  inner_keccak256_extract(&prng, c2, CTILDEBYTES);
#else
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);
#endif

  for (i = 0; i < CTILDEBYTES; ++i)
    if (c[i] != c2[i])
      return -1;

  return 0;
}


__attribute__((visibility("default")))
int trial_verify_pure(const uint8_t *sig,size_t slen,const uint8_t *msg,size_t mlen,const uint8_t *ctx,size_t clen,const uint8_t *pk) {
 return crypto_sign_verify(sig,slen,msg,mlen,ctx,clen,pk);
}
int pqbench_mldsa_fixture(uint64_t,uint8_t*,uint8_t*,uint8_t*);
__attribute__((visibility("default")))
int trial_fixture(uint64_t n,uint8_t *pk,uint8_t *sig,uint8_t *msg) {return pqbench_mldsa_fixture(n,pk,sig,msg);}
