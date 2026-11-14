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

static int get_low_response(sig_bits *reader, uint64_t *value) {
    _Static_assert(RACC_ZLBITS == 40, "fixed standard response low bits");
    if (reader->position > 8 * RACC_SIG_SZ - RACC_ZLBITS) return 0;
    size_t first = reader->position / 8;
    unsigned shift = reader->position % 8;
    size_t count = (shift + RACC_ZLBITS + 7) / 8;
    uint64_t raw = 0;
    for (size_t i = 0; i < count; ++i)
        raw |= (uint64_t)reader->bytes[first + i] << (8 * i);
    *value = (raw >> shift) & ((UINT64_C(1) << RACC_ZLBITS) - 1);
    reader->position += RACC_ZLBITS;
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
            if (!get_low_response(&reader, &x)) return 0;
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
    size_t trailing = reader.position / 8;
    unsigned consumed = reader.position % 8;
    if (consumed != 0) {
        if (bytes[trailing] & (uint8_t)(0xffu << consumed)) return 0;
        ++trailing;
    }
    while (trailing < RACC_SIG_SZ) {
        if (bytes[trailing++] != 0) return 0;
    }
    return 1;
}

size_t review_decode_new(const uint8_t *bytes, uint8_t *output) {
    racc_sig_t value = {0};
    if (!decode_signature(&value, bytes)) return 0;
    memcpy(output, &value, sizeof(value));
    return sizeof(value);
}

int review_low40(const uint8_t *bytes, size_t position, uint64_t *value, size_t *after) {
    sig_bits reader = {bytes, position};
    int result = get_low_response(&reader, value);
    *after = reader.position;
    return result;
}
uint64_t review_get64(const uint8_t *bytes) { return get64u_le(bytes); }
void review_put64(uint8_t *bytes, uint64_t value) { put64u_le(bytes,value); }
