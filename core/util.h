#pragma once
/* Small helpers shared by the whole core. No heap, no libc beyond string.h. */
#include <stddef.h>
#include <stdint.h>

/* Wipe secrets; the volatile write keeps the compiler from dropping it. */
void secure_zero(void *p, size_t n);

/* All-ones mask if x != 0, else 0 (constant time). */
static inline uint32_t ct_mask_nz(uint32_t x) { return (uint32_t)(-(int32_t)((x | (0u - x)) >> 31)); }
/* All-ones mask if bit == 1 (bit must be 0 or 1). */
static inline uint32_t ct_mask_bit(uint32_t bit) { return 0u - bit; }
