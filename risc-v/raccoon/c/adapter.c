/* Compact Raccoon-128-1 boundary. Vendor sources remain unchanged. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "racc_core.h"
#include "racc_serial.h"
#include "xof_sample.h"
#include "ct_util.h"
#include "sha3_t.h"

_Static_assert(RACC_D == 1 && RACC_KAPPA == 128, "Raccoon-128-1 only");
_Static_assert(RACC_PK_SZ == 2256 && RACC_SIG_SZ == 11524, "serialized sizes");

/* Bounded decoding of NIST Section 2.5.1. The reference decoder eagerly
   fetches the next byte after bit 7, including at the end of the last byte.
   Read a bit only when requested, and reject every nonzero trailing bit. */
typedef struct {
    const uint8_t *bytes;
    size_t position;
} sig_bits;

static int get_bit(sig_bits *reader, uint64_t *bit) {
    if (reader->position >= 8 * RACC_SIG_SZ) return 0;
    *bit = (reader->bytes[reader->position / 8] >> (reader->position % 8)) & 1;
    ++reader->position;
    return 1;
}

static int decode_signature(racc_sig_t *sig, const uint8_t *bytes) {
    sig_bits reader = {bytes, 8 * RACC_CH_SZ};
    uint64_t bit, x;
    memcpy(sig->ch, bytes, RACC_CH_SZ);
    for (size_t i = 0; i < RACC_K; ++i) {
        for (size_t j = 0; j < RACC_N; ++j) {
            x = 0;
            for (;;) {
                if (!get_bit(&reader, &bit)) return 0;
                if (bit == 0) break;
                if (++x > RACC_BOO_H) return 0;
            }
            if (x != 0) {
                if (!get_bit(&reader, &bit)) return 0;
                sig->h[i][j] = bit ? -(int64_t)x : (int64_t)x;
            } else sig->h[i][j] = 0;
        }
    }
    for (size_t i = 0; i < RACC_ELL; ++i) {
        for (size_t j = 0; j < RACC_N; ++j) {
            x = 0;
            for (size_t n = 0; n < RACC_ZLBITS; ++n) {
                if (!get_bit(&reader, &bit)) return 0;
                x |= bit << n;
            }
            for (;;) {
                if (!get_bit(&reader, &bit)) return 0;
                if (bit == 0) break;
                x += UINT64_C(1) << RACC_ZLBITS;
                if (x > RACC_BOO) return 0;
            }
            if (x > RACC_BOO) return 0;
            if (x != 0) {
                if (!get_bit(&reader, &bit)) return 0;
                sig->z[i][j] = bit ? RACC_Q - (int64_t)x : (int64_t)x;
            } else sig->z[i][j] = 0;
        }
    }
    while (reader.position < 8 * RACC_SIG_SZ) {
        if (!get_bit(&reader, &bit) || bit != 0) return 0;
    }
    return 1;
}

int pqbench_raccoon_verify(const uint8_t *pk, const uint8_t *message,
                          const uint8_t *signature) {
    racc_pk_t public_key;
    racc_sig_t sig;
    uint8_t mu[RACC_MU_SZ];
    if (racc_decode_pk(&public_key, pk) != RACC_PK_SZ ||
        !decode_signature(&sig, signature)) return 0;
    /* Section 2.5.2 serializes t in Z_qt, not every 7-bit integer. */
    for (size_t i = 0; i < RACC_K; ++i)
        for (size_t j = 0; j < RACC_N; ++j)
            if (public_key.t[i][j] >= RACC_QT) return 0;
    xof_chal_mu(mu, public_key.tr, message, 32);
    return racc_core_verify(&sig, mu, &public_key);
}

#ifndef __riscv
#include "api.h"
#include "nist_random.h"

/* Reproducible public test material. This RNG is never used in the guest. */
int pqbench_raccoon_fixture(uint64_t index, uint8_t *pk, uint8_t *signature,
                           uint8_t *message) {
    uint8_t entropy[48], sk[RACC_SK_SZ], sm[RACC_SIG_SZ + 32];
    uint8_t input[32] = "pqbench/raccoon1281/v1";
    unsigned long long length = 0;
    for (size_t i = 0; i < 8; ++i) input[24 + i] = (uint8_t)(index >> (8*i));
    shake256(entropy, sizeof entropy, input, sizeof input);
    input[21] = 'm';
    shake256(message, 32, input, sizeof input);
    nist_randombytes_init(entropy, NULL, 256);
    if (crypto_sign_keypair(pk, sk) != 0 ||
        crypto_sign(sm, &length, message, 32, sk) != 0 ||
        length != sizeof sm) return -1;
    memcpy(signature, sm, RACC_SIG_SZ);
    return pqbench_raccoon_verify(pk, message, signature) ? 0 : -1;
}

/* First official NIST KAT generation step, with externally supplied seed and
   message. Returns the exact reference API bytes, independently crosschecked. */
int pqbench_raccoon_kat(const uint8_t *seed, const uint8_t *message, size_t mlen,
                       uint8_t *pk, uint8_t *sk, uint8_t *sm) {
    unsigned long long length = 0;
    nist_randombytes_init(seed, NULL, 256);
    if (crypto_sign_keypair(pk, sk) != 0 ||
        crypto_sign(sm, &length, message, mlen, sk) != 0) return -1;
    return length == RACC_SIG_SZ + mlen ? 0 : -1;
}
#endif
