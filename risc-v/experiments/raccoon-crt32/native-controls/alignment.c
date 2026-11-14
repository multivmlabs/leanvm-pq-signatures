#include "/Users/manuelbsantos/Documents/Github/work/multivm-labs/aggregation/eip-8288/risc-v/experiments/raccoon-crt32/c/include/plat_local.h"
uint64_t read_export(const uint8_t *p) { return get64u_le(p); }
void write_export(uint8_t *p, uint64_t x) { put64u_le(p,x); }
