#include "ec/secp256k1.h"
#include "ec/bn.h"
#include "ec/fbtab.h"
#include "ec/ec_consts.h"
#include "hash/sha256.h"
#include <string.h>

typedef uint32_t fe[8];
static const uint32_t FP[8] = SECP_P;
static const uint32_t FN[8] = SECP_N;
static const uint32_t GX[8] = SECP_GX;
static const uint32_t GY[8] = SECP_GY;

/* ---- field arithmetic mod p = 2^256 - 2^32 - 977 (values are "weak": < 2^256, not necessarily < p) ---- */

/* r += c * (2^32 + 977), c < 2^34. Returns the carry out of bit 255 (0 or 1). */
static uint32_t fe_add_fold(fe r, uint64_t c)
{
    uint64_t s = (uint64_t)r[0] + c * 977;
    r[0] = (uint32_t)s;
    uint64_t cc = s >> 32;
    s = (uint64_t)r[1] + (uint32_t)c + cc;
    r[1] = (uint32_t)s;
    cc = (s >> 32) + (c >> 32);
    for (int i = 2; i < 8; i++) { s = (uint64_t)r[i] + cc; r[i] = (uint32_t)s; cc = s >> 32; }
    return (uint32_t)cc;
}

/* r -= c * (2^32 + 977), c in {0,1}. Returns the borrow out of bit 255. */
static uint32_t fe_sub_fold(fe r, uint32_t c)
{
    uint64_t u = (uint64_t)r[0] - (uint64_t)c * 977;
    r[0] = (uint32_t)u;
    uint32_t borrow = (uint32_t)(u >> 32) & 1;
    u = (uint64_t)r[1] - c - borrow;
    r[1] = (uint32_t)u;
    borrow = (uint32_t)(u >> 32) & 1;
    for (int i = 2; i < 8; i++) { u = (uint64_t)r[i] - borrow; r[i] = (uint32_t)u; borrow = (uint32_t)(u >> 32) & 1; }
    return borrow;
}

static void fe_add(fe r, const fe a, const fe b)
{
    uint32_t c = bn_add(r, a, b);
    c = fe_add_fold(r, c);
    fe_add_fold(r, c);
}

static void fe_sub(fe r, const fe a, const fe b)
{
    uint32_t bo = bn_sub(r, a, b);
    bo = fe_sub_fold(r, bo);
    fe_sub_fold(r, bo);
}

static void fe_reduce_wide(fe r, const uint32_t t[16])
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)t[i] + (uint64_t)t[8 + i] * 977 + (i ? t[8 + i - 1] : 0) + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    carry += t[15];
    uint32_t c = fe_add_fold(r, carry);
    fe_add_fold(r, c);
}

static void fe_mul(fe r, const fe a, const fe b)
{
    uint32_t t[16];
    bn_mul_wide(t, a, b);
    fe_reduce_wide(r, t);
}

static void fe_sqr(fe r, const fe a)
{
    uint32_t t[16];
    bn_sqr_wide(t, a);
    fe_reduce_wide(r, t);
}

static void fe_mul_small(fe r, const fe a, uint32_t k)
{
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)a[i] * k; r[i] = (uint32_t)c; c >>= 32; }
    uint32_t o = fe_add_fold(r, c);
    fe_add_fold(r, o);
}

/* canonical representative in [0, p) */
static void fe_normalize(fe r)
{
    fe t;
    uint32_t borrow = bn_sub(t, r, FP);
    bn_cmov(r, t, borrow - 1);   /* r >= p -> r - p */
}

static void fe_set(fe r, const fe a) { memcpy(r, a, 32); }
static void fe_zero(fe r) { memset(r, 0, 32); }
static void fe_one(fe r) { memset(r, 0, 32); r[0] = 1; }

static void fe_sqr_n(fe r, const fe a, int n)
{
    fe_sqr(r, a);
    for (int i = 1; i < n; i++) fe_sqr(r, r);
}

/* a^(p-2) by the addition chain of libsecp256k1: 255 squarings and 15 multiplications (the exponent is public). */
static void fe_inv(fe r, const fe a)
{
    fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
    fe_sqr(x2, a);           fe_mul(x2, x2, a);
    fe_sqr(x3, x2);          fe_mul(x3, x3, a);
    fe_sqr_n(x6, x3, 3);     fe_mul(x6, x6, x3);
    fe_sqr_n(x9, x6, 3);     fe_mul(x9, x9, x3);
    fe_sqr_n(x11, x9, 2);    fe_mul(x11, x11, x2);
    fe_sqr_n(x22, x11, 11);  fe_mul(x22, x22, x11);
    fe_sqr_n(x44, x22, 22);  fe_mul(x44, x44, x22);
    fe_sqr_n(x88, x44, 44);  fe_mul(x88, x88, x44);
    fe_sqr_n(x176, x88, 88); fe_mul(x176, x176, x88);
    fe_sqr_n(x220, x176, 44); fe_mul(x220, x220, x44);
    fe_sqr_n(x223, x220, 3); fe_mul(x223, x223, x3);
    fe_sqr_n(t, x223, 23);   fe_mul(t, t, x22);
    fe_sqr_n(t, t, 5);       fe_mul(t, t, a);
    fe_sqr_n(t, t, 3);       fe_mul(t, t, x2);
    fe_sqr_n(t, t, 2);       fe_mul(r, t, a);
}

/* ---- group: complete projective formulas for a = 0 (Renes-Costello-Batina 2015, Alg. 7 and 9, b3 = 21) ---- */

typedef struct { fe X, Y, Z; } pt;

static void pt_identity(pt *p) { fe_zero(p->X); fe_one(p->Y); fe_zero(p->Z); }

static void pt_add(pt *r, const pt *p, const pt *q)
{
    fe t0, t1, t2, t3, t4, X3, Y3, Z3;
    fe_mul(t0, p->X, q->X);  fe_mul(t1, p->Y, q->Y);  fe_mul(t2, p->Z, q->Z);
    fe_add(t3, p->X, p->Y);  fe_add(t4, q->X, q->Y);  fe_mul(t3, t3, t4);
    fe_add(t4, t0, t1);      fe_sub(t3, t3, t4);      fe_add(t4, p->Y, p->Z);
    fe_add(X3, q->Y, q->Z);  fe_mul(t4, t4, X3);      fe_add(X3, t1, t2);
    fe_sub(t4, t4, X3);      fe_add(X3, p->X, p->Z);  fe_add(Y3, q->X, q->Z);
    fe_mul(X3, X3, Y3);      fe_add(Y3, t0, t2);      fe_sub(Y3, X3, Y3);
    fe_add(X3, t0, t0);      fe_add(t0, X3, t0);      fe_mul_small(t2, t2, 21);
    fe_add(Z3, t1, t2);      fe_sub(t1, t1, t2);      fe_mul_small(Y3, Y3, 21);
    fe_mul(X3, t4, Y3);      fe_mul(t2, t3, t1);      fe_sub(X3, t2, X3);
    fe_mul(Y3, Y3, t0);      fe_mul(t1, t1, Z3);      fe_add(Y3, t1, Y3);
    fe_mul(t0, t0, t3);      fe_mul(Z3, Z3, t4);      fe_add(Z3, Z3, t0);
    fe_set(r->X, X3); fe_set(r->Y, Y3); fe_set(r->Z, Z3);
}

static void pt_dbl(pt *r, const pt *p)
{
    fe t0, t1, t2, X3, Y3, Z3;
    fe_sqr(t0, p->Y);        fe_add(Z3, t0, t0);      fe_add(Z3, Z3, Z3);
    fe_add(Z3, Z3, Z3);      fe_mul(t1, p->Y, p->Z);  fe_sqr(t2, p->Z);
    fe_mul_small(t2, t2, 21);
    fe_mul(X3, t2, Z3);      fe_add(Y3, t0, t2);      fe_mul(Z3, t1, Z3);
    fe_add(t1, t2, t2);      fe_add(t2, t1, t2);      fe_sub(t0, t0, t2);
    fe_mul(Y3, t0, Y3);      fe_add(Y3, X3, Y3);      fe_mul(t1, p->X, p->Y);
    fe_mul(X3, t0, t1);      fe_add(X3, X3, X3);
    fe_set(r->X, X3); fe_set(r->Y, Y3); fe_set(r->Z, Z3);
}

/* r = p + (qx, qy) with the second point affine (Z = 1): RCB 2015, Algorithm 8, 11 multiplications; complete. */
static void pt_add_mixed(pt *r, const pt *p, const fe qx, const fe qy)
{
    fe t0, t1, t2, t3, t4, X3, Y3, Z3;
    fe_mul(t0, p->X, qx);    fe_mul(t1, p->Y, qy);
    fe_add(t3, qx, qy);      fe_add(t4, p->X, p->Y);  fe_mul(t3, t3, t4);
    fe_add(t4, t0, t1);      fe_sub(t3, t3, t4);
    fe_mul(t4, qy, p->Z);    fe_add(t4, t4, p->Y);
    fe_mul(Y3, qx, p->Z);    fe_add(Y3, Y3, p->X);
    fe_add(X3, t0, t0);      fe_add(t0, X3, t0);
    fe_mul_small(t2, p->Z, 21);
    fe_add(Z3, t1, t2);      fe_sub(t1, t1, t2);
    fe_mul_small(Y3, Y3, 21);
    fe_mul(X3, t4, Y3);      fe_mul(t2, t3, t1);      fe_sub(X3, t2, X3);
    fe_mul(Y3, Y3, t0);      fe_mul(t1, t1, Z3);      fe_add(Y3, t1, Y3);
    fe_mul(t0, t0, t3);      fe_mul(Z3, Z3, t4);      fe_add(Z3, Z3, t0);
    fe_set(r->X, X3); fe_set(r->Y, Y3); fe_set(r->Z, Z3);
}

/* ---- fixed base multiplication k * G with a table: 65 windows of 4 bits with signed digits -8..8, so the table holds
 * d * 16^i * G for d = 1..8 (affine, 8 words x then 8 words y): 65 * 8 * 64 = 33 280 bytes of RAM, built on the first use
 * (about 0.8 s on a PSX). k * G is then 65 mixed additions and no doublings (about 8 times faster than double-and-add).
 * The digit is picked by scanning the eight entries with masks and the sign by a masked negation: constant time. ---- */
static uint32_t fb_tab[FB_WINDOWS][8][16];

/* The table is built in small steps (fbtab.c), so that a progress screen can be drawn in between: one window of eight points, or the conversion
 * of eight windows to affine form, each a few milliseconds on a PSX. The work area of eight windows is shared with the ed25519 table, which is
 * built after this one (never at the same time). */
static void sp_set_base(void *p) { pt *b = p; memcpy(b->X, GX, 32); memcpy(b->Y, GY, 32); fe_one(b->Z); }
static void sp_add(void *r, const void *p, const void *q) { pt_add(r, p, q); }
static void sp_dbl(void *r, const void *p) { pt_dbl(r, p); }
static const fb_ops FB_OPS = { 24, sp_set_base, sp_add, sp_dbl, fe_mul, fe_inv, fe_normalize };
static fb_state fb;

/* One unit of work towards the table; returns the progress in percent (100: the table is ready). */
int secp256k1_table_step(void) { return fb_step(&fb, &FB_OPS, fb_tab); }

static void fb_build(void)
{
    while (secp256k1_table_step() < 100) {}
}

/* r = k * G, k is 32 byte big-endian */
static void pt_mul_g(pt *r, const uint8_t k[32])
{
    int8_t dig[FB_WINDOWS];
    uint32_t carry = 0;
    pt acc, t;
    fe zero;

    if (!fb.ready) fb_build();
    for (int i = 0; i < 64; i++) {                                   /* signed digits: v > 8 becomes v - 16 and a carry */
        uint32_t v = (uint32_t) ((k[31 - (i >> 1)] >> ((i & 1) * 4)) & 15) + carry;
        carry = (8u - v) >> 31;
        dig[i] = (int8_t) (v - (carry << 4));
    }
    dig[64] = (int8_t) carry;
    fe_zero(zero);
    pt_identity(&acc);
    for (int i = 0; i < FB_WINDOWS; i++) {
        uint32_t dv = (uint32_t) (int32_t) dig[i], neg = dv >> 31, m = 0u - neg;
        uint32_t a = (dv ^ m) - m;                                   /* |digit| */
        fe sx, sy, ny;
        fe_zero(sx); fe_zero(sy);
        for (int j = 0; j < 8; j++) {
            uint32_t eq = ~ct_mask_nz(a ^ (uint32_t) (j + 1));
            for (int w = 0; w < 8; w++) {
                sx[w] |= eq & fb_tab[i][j][w];
                sy[w] |= eq & fb_tab[i][j][8 + w];
            }
        }
        fe_sub(ny, zero, sy);
        bn_cmov(sy, ny, m);                                          /* negative digit: -y */
        pt_add_mixed(&t, &acc, sx, sy);
        m = ct_mask_nz(a);                                           /* digit 0: no addition */
        bn_cmov(acc.X, t.X, m); bn_cmov(acc.Y, t.Y, m); bn_cmov(acc.Z, t.Z, m);
    }
    *r = acc;
    secure_zero(&t, sizeof t);
    secure_zero(dig, sizeof dig);
}

static void pt_to_affine(uint8_t x[32], uint8_t y[32], const pt *p)
{
    fe zi, ax, ay;
    fe_inv(zi, p->Z);
    fe_mul(ax, p->X, zi);  fe_mul(ay, p->Y, zi);
    fe_normalize(ax);      fe_normalize(ay);
    bn_to_be(x, ax);       bn_to_be(y, ay);
}

/* ---- public API ---- */

int secp256k1_privkey_verify(const uint8_t k[32])
{
    uint32_t v[8];
    bn_from_be(v, k);
    return (int)(bn_lt(v, FN) & ~bn_zero_mask(v) & 1);
}

int secp256k1_pubkey_xy(uint8_t x[32], uint8_t y[32], const uint8_t priv[32])
{
    pt r;
    if (!secp256k1_privkey_verify(priv)) return -1;
    pt_mul_g(&r, priv);
    pt_to_affine(x, y, &r);
    secure_zero(&r, sizeof r);
    return 0;
}

int secp256k1_pubkey_create(uint8_t out[33], const uint8_t priv[32])
{
    uint8_t x[32], y[32];
    if (secp256k1_pubkey_xy(x, y, priv)) return -1;
    out[0] = (uint8_t)(0x02 | (y[31] & 1));
    memcpy(out + 1, x, 32);
    return 0;
}

int secp256k1_pubkey_create_uncompressed(uint8_t out[65], const uint8_t priv[32])
{
    if (secp256k1_pubkey_xy(out + 1, out + 33, priv)) return -1;
    out[0] = 0x04;
    return 0;
}

int secp256k1_privkey_tweak_add(uint8_t key[32], const uint8_t tweak[32])
{
    uint32_t k[8], t[8], r[8];
    bn_from_be(k, key);
    bn_from_be(t, tweak);
    if (!bn_lt(t, FN)) return -1;
    bn_add_mod(r, k, t, FN);
    if (bn_zero_mask(r)) return -1;
    bn_to_be(key, r);
    secure_zero(k, sizeof k); secure_zero(r, sizeof r);
    return 0;
}

int secp256k1_privkey_mul(uint8_t key[32], const uint8_t factor[32])
{
    uint32_t k[8], f[8], t[16], r[8];
    bn_from_be(k, key);
    bn_from_be(f, factor);
    if (!bn_lt(f, FN) || bn_zero_mask(f)) return -1;
    bn_mul_wide(t, k, f);
    bn_mod_wide(r, t, 16, FN);
    if (bn_zero_mask(r)) return -1;
    bn_to_be(key, r);
    secure_zero(k, sizeof k); secure_zero(r, sizeof r); secure_zero(t, sizeof t);
    return 0;
}

/* ---- BIP340 verification (the loader checks the signature of a package with it). Public data only, so no constant time: k * P by double and add with the complete
 * formulas (estimated 0.2 s on a PSX in all), twice. ---- */

static void pt_mul_aff(pt *r, const fe x, const fe y, const uint32_t k[8])
{
    pt acc;
    pt_identity(&acc);
    for (int i = 255; i >= 0; i--) {
        pt_dbl(&acc, &acc);
        if ((k[i >> 5] >> (i & 31)) & 1) pt_add_mixed(&acc, &acc, x, y);
    }
    *r = acc;
}

int secp256k1_schnorr_verify(const uint8_t sig[64], const uint8_t msg[32], const uint8_t pub[32])
{
    fe r, px, py, c, t, z;
    uint32_t s[8], e[8], k[8], ex[8];
    uint8_t h[32];
    sha256_ctx sc;
    pt a, b;

    bn_from_be(r, sig);
    bn_from_be(s, sig + 32);
    bn_from_be(px, pub);
    if (!bn_lt(r, FP) || !bn_lt(s, FN) || !bn_lt(px, FP)) return -1;

    /* lift_x: py = (x^3 + 7)^((p + 1) / 4), the root with an even y; (p + 1) / 4 is the exponent of the square root as p = 3 mod 4 */
    fe_sqr(t, px); fe_mul(t, t, px);
    fe_zero(z); z[0] = 7;
    fe_add(c, t, z);
    memcpy(ex, FP, 32);
    ex[0] += 1;                                                  /* p + 1: the low word of p is 0xFFFFFC2F, no carry */
    for (int i = 0; i < 8; i++) ex[i] = (ex[i] >> 2) | (i < 7 ? ex[i + 1] << 30 : 0);
    fe_one(py);
    for (int i = 255; i >= 0; i--) {
        fe_sqr(py, py);
        if ((ex[i >> 5] >> (i & 31)) & 1) fe_mul(py, py, c);
    }
    fe_normalize(py);
    fe_sqr(t, py); fe_normalize(t); fe_normalize(c);
    if (memcmp(t, c, 32)) return -1;                             /* x is not on the curve */
    if (py[0] & 1) bn_sub(py, FP, py);                           /* the even root */

    sha256_tagged_init(&sc, "BIP0340/challenge");
    sha256_update(&sc, sig, 32);
    sha256_update(&sc, pub, 32);
    sha256_update(&sc, msg, 32);
    sha256_final(&sc, h);
    bn_from_be(e, h);
    if (!bn_lt(e, FN)) bn_sub(e, e, FN);                         /* 2^256 < 2n: one subtraction is the reduction */
    bn_sub(k, FN, e);                                            /* R = s G - e P = s G + (n - e) P */
    pt_mul_aff(&a, GX, GY, s);
    pt_mul_aff(&b, px, py, k);
    pt_add(&a, &a, &b);
    fe_normalize(a.Z);
    if (bn_zero_mask(a.Z)) return -1;                            /* the point at infinity */
    fe_inv(z, a.Z);
    fe_mul(a.X, a.X, z); fe_mul(a.Y, a.Y, z);
    fe_normalize(a.X); fe_normalize(a.Y);
    return (a.Y[0] & 1) || memcmp(a.X, r, 32) ? -1 : 0;
}

/* ---- the field operations for code outside this file: the vanity search of the overlay (core/ec/secp_van.c) ---- */

void secp_fe_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) { fe_mul(r, a, b); }
void secp_fe_sqr(uint32_t r[8], const uint32_t a[8]) { fe_sqr(r, a); }
void secp_fe_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) { fe_add(r, a, b); }
void secp_fe_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) { fe_sub(r, a, b); }
void secp_fe_mul_small(uint32_t r[8], const uint32_t a[8], uint32_t k) { fe_mul_small(r, a, k); }
void secp_fe_inv(uint32_t r[8], const uint32_t a[8]) { fe_inv(r, a); }
void secp_fe_norm(uint32_t a[8]) { fe_normalize(a); }
