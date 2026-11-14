#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "fips202.h"

/* Deterministic public benchmark randomness, never production signing keys. */
static uint64_t fixture_index, random_counter;
void randombytes(uint8_t *out, size_t len) {
  uint8_t seed[32] = {'p','q','b','e','n','c','h','/','m','l','d','s','a','/','v','1'};
  for (size_t j = 0; j < 8; ++j) {
    seed[16+j] = (uint8_t)(fixture_index >> (8*j));
    seed[24+j] = (uint8_t)(random_counter >> (8*j));
  }
  ++random_counter;
  shake256(out, len, seed, sizeof seed);
}

int pqbench_mldsa_fixture(uint64_t index, uint8_t *pk, uint8_t *sig, uint8_t *message) {
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t seed[16] = {'m','l','d','s','a','m','s','g'};
  size_t siglen = 0;
  fixture_index = index;
  random_counter = 0;
  for (size_t j = 0; j < 8; ++j) seed[8+j] = (uint8_t)(index >> (8*j));
  shake256(message, 32, seed, sizeof seed);
  if (crypto_sign_keypair(pk, sk)) return -1;
  if (crypto_sign_signature(sig, &siglen, message, 32, 0, 0, sk)) return -1;
  return siglen == CRYPTO_BYTES ? crypto_sign_verify(sig, siglen, message, 32, 0, 0, pk) : -1;
}

