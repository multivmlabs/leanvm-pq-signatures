#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "rounding.h"

/* Enumerate the guest's admissible (r1,r0,wrap), not its witness generator. */
int main(void) {
  uint8_t *seen = calloc(Q, 1);
  uint64_t pairs = 0, mismatch = 0, missing = 0, repeated = 0;
  for (int high = 0; high < 44; ++high) {
    int low_min = high == 0 ? -GAMMA2 : 1-GAMMA2;
    for (int low = low_min; low <= GAMMA2; ++low) {
      for (int wrap = 0; wrap <= 1; ++wrap) {
        int64_t r = (int64_t)high * 2 * GAMMA2 + low + (int64_t)wrap * Q;
        if (r < 0 || r >= Q) continue;
        ++pairs;
        ++seen[r];
        int32_t c_low;
        int c_high = decompose(&c_low, (int32_t)r);
        if (c_high != high || c_low != low) ++mismatch;
        for (int h = 0; h <= 1; ++h) {
          int expected = h ? (high + (low > 0 ? 1 : 43)) % 44 : high;
          if (use_hint((int32_t)r, h) != expected) ++mismatch;
        }
      }
    }
  }
  for (int r = 0; r < Q; ++r) {
    if (!seen[r]) ++missing;
    if (seen[r] > 1) ++repeated;
  }
  /* Predetermined negative control: allowing -GAMMA2 at nonzero high
   * must create exactly 43 extra representations (the half-way ties). */
  uint64_t loose_collisions = 0;
  for (int high = 1; high < 44; ++high) {
    int r = high * 2 * GAMMA2 - GAMMA2;
    if (seen[r] == 1) ++loose_collisions;
  }
  free(seen);
  printf("{\"canonical_pairs\":%llu,\"native_mismatches\":%llu,\"missing\":%llu,\"repeated\":%llu,\"control_loose_negative_tie_collisions\":%llu}\n",
         (unsigned long long)pairs, (unsigned long long)mismatch,
         (unsigned long long)missing, (unsigned long long)repeated,
         (unsigned long long)loose_collisions);
  return pairs != Q || mismatch || missing || repeated || loose_collisions != 43;
}
