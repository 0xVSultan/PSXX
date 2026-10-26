#include "ec/poseidon.h"
#include <string.h>
#include "ec/pallas.h"
#include "ec/poseidon_consts.h"

static pl_fp mds[3][3];
static uint8_t rc[192][32];             /* the round constants, little-endian; converted when used: 6 KB less RAM than field elements */
static int ready;

/* The round constants are not stored in the image (they were 6 KB that does not compress): they are what the Grain LFSR of the Poseidon reference gives
 * (generate_parameters_grain.sage 1 0 255 3 8 56 <the prime of the Pallas base field>, as Zcash's Orchard uses it), made when the first permutation is needed:
 * the 80 bit state is the field type, the s-box, n = 255, t = 3, R_F = 8, R_P = 56 and 30 ones; after 160 idle steps a bit is the second of a pair (b1, b2) that
 * has b1 = 1; a constant is 255 such bits, the first one the most significant, and is drawn again if it is not below the prime. tests/test_poseidon.c checks the
 * permutation against the reference (tools/gen_poseidon_vectors.py). The MDS matrix is the first thing the reference draws after the constants; it is kept as a table. */
static uint32_t g0, g1, g2;             /* the state: element i of the reference's list is bit i of g0 (0 .. 31), g1 (32 .. 63), g2 (64 .. 79) */

static unsigned grain_step(void)
{
    unsigned nb = (g0 ^ (g0 >> 13) ^ (g0 >> 23) ^ (g1 >> 6) ^ (g1 >> 19) ^ (g1 >> 30)) & 1;     /* elements 0, 13, 23, 38, 51, 62 */

    g0 = (g0 >> 1) | (g1 << 31);
    g1 = (g1 >> 1) | (g2 << 31);
    g2 = (g2 >> 1) | (nb << 15);
    return nb;
}

static unsigned grain_bit(void)
{
    unsigned b = grain_step();

    while (!b) { grain_step(); b = grain_step(); }
    return grain_step();
}

static void make_constants(void)
{
    static const uint8_t PRIME_BE[32] = {0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xed, 0, 0, 0, 1};

    g0 = 0x3003fc02u; g1 = 0xfffc7010u; g2 = 0xffffu;
    for (int i = 0; i < 160; i++) grain_step();
    for (int k = 0; k < 192; k++) {
        uint8_t be[32];

        do {
            memset(be, 0, sizeof be);
            for (int i = 254; i >= 0; i--) if (grain_bit()) be[31 - (i >> 3)] |= (uint8_t) (1u << (i & 7));
        } while (memcmp(be, PRIME_BE, 32) >= 0);
        for (int i = 0; i < 32; i++) rc[k][i] = be[31 - i];
    }
}

static void setup(void)
{
    if (ready) return;
    make_constants();
    for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++) pl_fp_from_le(mds[i][j], POS_MDS[i][j]);
    ready = 1;
}

static void pow5(pl_fp x)
{
    pl_fp t;
    pl_fp_sqr(t, x);
    pl_fp_sqr(t, t);
    pl_fp_mul(x, t, x);
}

static void mix(pl_fp s[3])
{
    pl_fp n[3], t;
    for (int i = 0; i < 3; i++) {
        pl_fp_mul(n[i], mds[i][0], s[0]);
        pl_fp_mul(t, mds[i][1], s[1]); pl_fp_add(n[i], n[i], t);
        pl_fp_mul(t, mds[i][2], s[2]); pl_fp_add(n[i], n[i], t);
    }
    memcpy(s, n, sizeof n);
}

void poseidon_perm(uint8_t st[3][32])
{
    pl_fp s[3];
    int k = 0;
    setup();
    for (int i = 0; i < 3; i++) pl_fp_from_le(s[i], st[i]);
    for (int r = 0; r < 64; r++) {
        int full = r < 4 || r >= 60;
        for (int i = 0; i < 3; i++) { pl_fp c; pl_fp_from_le(c, rc[k++]); pl_fp_add(s[i], s[i], c); }
        if (full) for (int i = 0; i < 3; i++) pow5(s[i]);
        else pow5(s[0]);
        mix(s);
    }
    for (int i = 0; i < 3; i++) pl_fp_to_le(st[i], s[i]);
}

void poseidon_hash2(uint8_t out[32], const uint8_t x[32], const uint8_t y[32])
{
    uint8_t st[3][32];
    memcpy(st[0], x, 32);
    memcpy(st[1], y, 32);
    memset(st[2], 0, 32);
    st[2][8] = 2;                                    /* 2^65 */
    poseidon_perm(st);
    memcpy(out, st[0], 32);
}
