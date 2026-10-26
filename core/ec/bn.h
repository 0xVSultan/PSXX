#pragma once
/* 256-bit helpers on 8 little-endian 32-bit limbs. All functions are branch-free on their data. */
#include <stdint.h>
#include "util.h"

#define BN_LIMBS 8

static inline uint32_t bn_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8])
{
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)a[i] + b[i]; r[i] = (uint32_t)c; c >>= 32; }
    return (uint32_t)c;
}

static inline uint32_t bn_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        r[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 32) & 1;
    }
    return borrow;
}

/* r = mask ? a : r  (mask is 0 or 0xFFFFFFFF) */
static inline void bn_cmov(uint32_t r[8], const uint32_t a[8], uint32_t mask)
{
    for (int i = 0; i < 8; i++) r[i] ^= mask & (r[i] ^ a[i]);
}

/* 0xFFFFFFFF if a == 0 else 0 */
static inline uint32_t bn_zero_mask(const uint32_t a[8])
{
    uint32_t o = 0;
    for (int i = 0; i < 8; i++) o |= a[i];
    return ~ct_mask_nz(o);
}

/* 1 if a < b else 0 */
static inline uint32_t bn_lt(const uint32_t a[8], const uint32_t b[8])
{
    uint32_t t[8];
    return bn_sub(t, a, b);
}

static inline void bn_from_le(uint32_t r[8], const uint8_t in[32])
{
    for (int i = 0; i < 8; i++)
        r[i] = (uint32_t)in[4*i] | (uint32_t)in[4*i+1] << 8 | (uint32_t)in[4*i+2] << 16 | (uint32_t)in[4*i+3] << 24;
}
static inline void bn_to_le(uint8_t out[32], const uint32_t a[8])
{
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uint8_t)a[i]; out[4*i+1] = (uint8_t)(a[i] >> 8);
        out[4*i+2] = (uint8_t)(a[i] >> 16); out[4*i+3] = (uint8_t)(a[i] >> 24);
    }
}
static inline void bn_from_be(uint32_t r[8], const uint8_t in[32])
{
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = in + 28 - 4 * i;
        r[i] = (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
    }
}
static inline void bn_to_be(uint8_t out[32], const uint32_t a[8])
{
    for (int i = 0; i < 8; i++) {
        uint8_t *p = out + 28 - 4 * i;
        p[3] = (uint8_t)a[i]; p[2] = (uint8_t)(a[i] >> 8); p[1] = (uint8_t)(a[i] >> 16); p[0] = (uint8_t)(a[i] >> 24);
    }
}

/* r = (a + b) mod m, for a, b < m. */
void bn_add_mod(uint32_t r[8], const uint32_t a[8], const uint32_t b[8], const uint32_t m[8]);

/* r = x mod m for an nw-limb little-endian x (shift-and-subtract, 1 bit per step). m < 2^256. */
void bn_mod_wide(uint32_t r[8], const uint32_t *x, int nw, const uint32_t m[8]);

/* 256 x 256 -> 512 bit product, and the square: unrolled product scanning (bn_comba.h, tools/gen_bn_fast.py). */
#include "ec/bn_comba.h"
static inline void bn_mul_wide(uint32_t t[16], const uint32_t a[8], const uint32_t b[8]) { bn_mul_wide_comba(t, a, b); }
static inline void bn_sqr_wide(uint32_t t[16], const uint32_t a[8]) { bn_sqr_wide_comba(t, a); }
