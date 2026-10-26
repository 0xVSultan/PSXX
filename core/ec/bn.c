#include "ec/bn.h"

/* the bigger helpers of bn.h: one copy for every curve */

void bn_add_mod(uint32_t r[8], const uint32_t a[8], const uint32_t b[8], const uint32_t m[8])
{
    uint32_t s[8], t[8];
    uint32_t carry = bn_add(s, a, b);
    uint32_t borrow = bn_sub(t, s, m);
    /* subtract if the sum overflowed 256 bits (carry) or s >= m (no borrow) */
    bn_cmov(s, t, ct_mask_nz(carry | (borrow ^ 1)));
    for (int i = 0; i < 8; i++) r[i] = s[i];
}

void bn_mod_wide(uint32_t r[8], const uint32_t *x, int nw, const uint32_t m[8])
{
    uint32_t acc[9] = {0};
    for (int bit = nw * 32 - 1; bit >= 0; bit--) {
        uint32_t in = (x[bit >> 5] >> (bit & 31)) & 1;
        for (int i = 8; i > 0; i--) acc[i] = (acc[i] << 1) | (acc[i-1] >> 31);
        acc[0] = (acc[0] << 1) | in;
        /* t = acc - m (9 limbs) */
        uint32_t t[9], borrow = 0;
        for (int i = 0; i < 9; i++) {
            uint64_t d = (uint64_t)acc[i] - (i < 8 ? m[i] : 0) - borrow;
            t[i] = (uint32_t)d;
            borrow = (uint32_t)(d >> 32) & 1;
        }
        uint32_t mask = borrow - 1;           /* no borrow -> acc >= m -> take t */
        for (int i = 0; i < 9; i++) acc[i] ^= mask & (acc[i] ^ t[i]);
    }
    for (int i = 0; i < 8; i++) r[i] = acc[i];
    secure_zero(acc, sizeof acc);
}
