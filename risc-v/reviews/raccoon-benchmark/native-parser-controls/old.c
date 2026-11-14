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

size_t review_decode_old(const uint8_t *bytes, uint8_t *output) {
    racc_sig_t value = {0};
    if (!decode_signature(&value, bytes)) return 0;
    memcpy(output, &value, sizeof(value));
    return sizeof(value);
}
