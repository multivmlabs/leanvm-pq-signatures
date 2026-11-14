/* Freestanding libc primitives for compiler-generated aggregate operations.
 * Native test symbols are prefixed and never override the host's libc. */
#include <stddef.h>
#include <stdint.h>
#ifndef __riscv
#define memcpy pqbench_raccoon_memcpy
#define memset pqbench_raccoon_memset
#define memmove pqbench_raccoon_memmove
#endif

void *memcpy(void *dst, const void *src, size_t n) {
  volatile unsigned char *d = dst;
  const volatile unsigned char *s = src;
  for (size_t i = 0; i < n; ++i) d[i] = s[i];
  return dst;
}

void *memset(void *dst, int c, size_t n) {
  volatile unsigned char *d = dst;
  for (size_t i = 0; i < n; ++i) d[i] = (unsigned char)c;
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  volatile unsigned char *d = dst;
  const volatile unsigned char *s = src;
  if ((uintptr_t)d <= (uintptr_t)s) return memcpy(dst, src, n);
  for (size_t i = n; i > 0; --i) d[i - 1] = s[i - 1];
  return dst;
}
