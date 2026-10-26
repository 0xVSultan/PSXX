#include "hash/sha2_k.h"

uint32_t sha2_kh[80], sha2_kl[80], sha2_ivh[8], sha2_ivl[8];

/* the first 64 bits of the fraction of the e-th root of p (e = 2 or 3): the largest r with r^e <= p * 2^(64 e), bit by bit (r < 2^67; 32 bit limbs, the low one first),
 * without its integer part */
static void root(uint32_t p, int e, uint32_t *out)
{
    uint32_t r[3] = {0, 0, 0};

    for (int b = 66; b >= 0; b--) {
        uint32_t v[8] = {1}, w[8];
        int i = 7;
        r[b >> 5] |= 1u << (b & 31);
        for (int k = 0; k < e; k++) {                                   /* v = r^e: v * r, v of at most 5 limbs before the last product */
            for (int m = 0; m < 8; m++) w[m] = 0;
            for (int m = 0; m < 5; m++) {
                uint32_t c = 0;
                for (int j = 0; j < 3; j++) {
                    uint64_t t = (uint64_t) v[m] * r[j] + w[m + j] + c;
                    w[m + j] = (uint32_t) t;
                    c = (uint32_t) (t >> 32);
                }
                w[m + 3] = c;
            }
            for (int m = 0; m < 8; m++) v[m] = w[m];
        }
        while (i > 0 && v[i] == (i == 2 * e ? p : 0)) i--;              /* against p * 2^(64 e): p in limb 2 e */
        if (v[i] > (i == 2 * e ? p : 0)) r[b >> 5] &= ~(1u << (b & 31));
    }
    out[0] = r[1];
    out[1] = r[0];
}

void sha2_tables(void)
{
    uint32_t p = 1, k[2], h0 = 0;

    if (sha2_kh[0]) return;
    for (int i = 0; i < 80; i++) {
        uint32_t q;
        do {                                                            /* the next prime */
            p++;
            for (q = 2; q * q <= p && p % q; q++) ;
        } while (q * q <= p);
        for (int e = 3; e >= 2 && (e == 3 || i < 8); e--) {
            root(p, e, k);
            if (e == 2) { sha2_ivh[i] = k[0]; sha2_ivl[i] = k[1]; }
            else { if (i) sha2_kh[i] = k[0]; else h0 = k[0]; sha2_kl[i] = k[1]; }
        }
    }
    sha2_kh[0] = h0;                                                    /* the last: it says that the tables are ready */
}
