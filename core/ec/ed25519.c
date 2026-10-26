#include "ec/ed25519.h"
#include "ec/ed25519_ge.h"
#include "ec/bn.h"
#include "ec/fbtab.h"
#include "ec/ec_consts.h"
#include "hash/sha512.h"
#include <string.h>

typedef ed_fe fe;
static const uint32_t FP[8] = ED_P;
static const uint32_t FL[8] = ED_L;
static const uint32_t D2[8] = ED_D2;
static const uint32_t BX[8] = ED_BX;
static const uint32_t BY[8] = ED_BY;

/* ---- field arithmetic mod p = 2^255 - 19 (weak form: < 2^256; 2^256 = 38 mod p) ---- */

/* r += c * 38, c < 2^32. Returns the carry out of bit 255 (0 or 1). */
static uint32_t fe_add_fold(fe r, uint32_t c)
{
    uint64_t s = (uint64_t)r[0] + (uint64_t)c * 38;
    r[0] = (uint32_t)s;
    uint64_t cc = s >> 32;
    for (int i = 1; i < 8; i++) { s = (uint64_t)r[i] + cc; r[i] = (uint32_t)s; cc = s >> 32; }
    return (uint32_t)cc;
}

/* r -= c * 38, c in {0,1}. Returns the borrow out of bit 255. */
static uint32_t fe_sub_fold(fe r, uint32_t c)
{
    uint64_t u = (uint64_t)r[0] - (uint64_t)c * 38;
    r[0] = (uint32_t)u;
    uint32_t borrow = (uint32_t)(u >> 32) & 1;
    for (int i = 1; i < 8; i++) { u = (uint64_t)r[i] - borrow; r[i] = (uint32_t)u; borrow = (uint32_t)(u >> 32) & 1; }
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

static void fe_mul(fe r, const fe a, const fe b)
{
    uint32_t t[16];
    uint64_t carry = 0;
    bn_mul_wide(t, a, b);
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)t[i] + (uint64_t)t[8 + i] * 38 + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    uint32_t c = fe_add_fold(r, (uint32_t)carry);
    fe_add_fold(r, c);
}

static void fe_sqr(fe r, const fe a)
{
    uint32_t t[16];
    uint64_t carry = 0;
    bn_sqr_wide(t, a);
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)t[i] + (uint64_t)t[8 + i] * 38 + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    uint32_t c = fe_add_fold(r, (uint32_t)carry);
    fe_add_fold(r, c);
}

/* canonical representative in [0, p) */
static void fe_normalize(fe r)
{
    fe t;
    uint32_t top = r[7] >> 31;
    r[7] &= 0x7fffffffu;
    /* r += 19 * top  (cannot overflow: r < 2^255) */
    uint64_t s = (uint64_t)r[0] + 19 * top;
    r[0] = (uint32_t)s;
    uint64_t cc = s >> 32;
    for (int i = 1; i < 8; i++) { s = (uint64_t)r[i] + cc; r[i] = (uint32_t)s; cc = s >> 32; }
    uint32_t borrow = bn_sub(t, r, FP);
    bn_cmov(r, t, borrow - 1);
}

static void fe_set(fe r, const fe a) { memcpy(r, a, 32); }
static void fe_zero(fe r) { memset(r, 0, 32); }
static void fe_one(fe r) { memset(r, 0, 32); r[0] = 1; }

static void fe_sqr_n(fe r, const fe a, int n)
{
    fe_sqr(r, a);
    for (int i = 1; i < n; i++) fe_sqr(r, r);
}

/* a^(p-2) = a^(2^255 - 21) by the addition chain of ref10: 254 squarings and 11 multiplications (the exponent is public) */
static void fe_inv(fe r, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sqr(t0, z);
    fe_sqr_n(t1, t0, 2);
    fe_mul(t1, z, t1);                    /* z^9 */
    fe_mul(t0, t0, t1);                   /* z^11 */
    fe_sqr(t2, t0);
    fe_mul(t1, t1, t2);                   /* z^(2^5 - 1) */
    fe_sqr_n(t2, t1, 5);   fe_mul(t1, t2, t1);   /* 2^10 - 1 */
    fe_sqr_n(t2, t1, 10);  fe_mul(t2, t2, t1);   /* 2^20 - 1 */
    fe_sqr_n(t3, t2, 20);  fe_mul(t2, t3, t2);   /* 2^40 - 1 */
    fe_sqr_n(t2, t2, 10);  fe_mul(t1, t2, t1);   /* 2^50 - 1 */
    fe_sqr_n(t2, t1, 50);  fe_mul(t2, t2, t1);   /* 2^100 - 1 */
    fe_sqr_n(t3, t2, 100); fe_mul(t2, t3, t2);   /* 2^200 - 1 */
    fe_sqr_n(t2, t2, 50);  fe_mul(t1, t2, t1);   /* 2^250 - 1 */
    fe_sqr_n(t1, t1, 5);   fe_mul(r, t1, t0);    /* 2^255 - 21 */
}

/* ---- group: extended twisted Edwards coordinates, unified (complete) addition ---- */

typedef ed_ge ge;

static void ge_identity(ge *p) { fe_zero(p->X); fe_one(p->Y); fe_one(p->Z); fe_zero(p->T); }

/* add-2008-hwcd-3, a = -1, k = 2d. Valid for all inputs, including doubling and the identity. */
static void ge_add(ge *r, const ge *p, const ge *q)
{
    fe A, B, C, D, E, F, G, H, t0, t1;
    fe_sub(t0, p->Y, p->X);  fe_sub(t1, q->Y, q->X);  fe_mul(A, t0, t1);
    fe_add(t0, p->Y, p->X);  fe_add(t1, q->Y, q->X);  fe_mul(B, t0, t1);
    fe_mul(t0, p->T, q->T);  fe_mul(C, t0, D2);
    fe_mul(t0, p->Z, q->Z);  fe_add(D, t0, t0);
    fe_sub(E, B, A);  fe_sub(F, D, C);  fe_add(G, D, C);  fe_add(H, B, A);
    fe_mul(r->X, E, F);  fe_mul(r->Y, G, H);  fe_mul(r->T, E, H);  fe_mul(r->Z, F, G);
}

/* dbl-2008-hwcd for a = -1: 4 multiplications and 4 squarings, complete (the identity doubles to the identity). r may alias p. */
static void ge_dbl(ge *r, const ge *p)
{
    fe A, B, C, D, E, F, G, H, t;
    fe_sqr(A, p->X); fe_sqr(B, p->Y); fe_sqr(C, p->Z); fe_add(C, C, C);
    fe_add(t, p->X, p->Y); fe_sqr(E, t); fe_sub(E, E, A); fe_sub(E, E, B);
    fe_zero(D); fe_sub(D, D, A);
    fe_add(G, D, B); fe_sub(F, G, C); fe_sub(H, D, B);
    fe_mul(r->X, E, F); fe_mul(r->Y, G, H); fe_mul(r->T, E, H); fe_mul(r->Z, F, G);
}

static void ge_neg(ge *r, const ge *p)
{
    fe z;
    fe_zero(z);
    fe_sub(r->X, z, p->X);
    fe_set(r->Y, p->Y);
    fe_set(r->Z, p->Z);
    fe_sub(r->T, z, p->T);
}

/* r = k * p, k 32 byte little-endian (all 256 bits used). Fixed 4 bit windows: 252 doublings and 64 additions, the table entry is
 * picked by scanning all 16 with masks, and a zero digit adds the identity (the addition is complete): constant time. */
static void ge_mul(ge *r, const ge *p, const uint8_t k[32])
{
    ge tab[16], acc, sel;
    ge_identity(&tab[0]);
    tab[1] = *p;
    for (int i = 2; i < 16; i++) {
        if (i & 1) ge_add(&tab[i], &tab[i - 1], p);
        else ge_dbl(&tab[i], &tab[i >> 1]);
    }
    ge_identity(&acc);
    for (int w = 63; w >= 0; w--) {
        uint32_t d = (uint32_t) ((k[w >> 1] >> ((w & 1) * 4)) & 15);
        ge_dbl(&acc, &acc); ge_dbl(&acc, &acc); ge_dbl(&acc, &acc); ge_dbl(&acc, &acc);
        sel = tab[0];
        for (uint32_t j = 1; j < 16; j++) {
            uint32_t m = ~ct_mask_nz(d ^ j);
            bn_cmov(sel.X, tab[j].X, m); bn_cmov(sel.Y, tab[j].Y, m);
            bn_cmov(sel.Z, tab[j].Z, m); bn_cmov(sel.T, tab[j].T, m);
        }
        ge_add(&acc, &acc, &sel);
    }
    *r = acc;
    secure_zero(tab, sizeof tab);
    secure_zero(&sel, sizeof sel);
}

static void ge_encode(uint8_t out[32], const ge *p)
{
    fe zi, x, y;
    fe_inv(zi, p->Z);
    fe_mul(x, p->X, zi);
    fe_mul(y, p->Y, zi);
    fe_normalize(x);
    fe_normalize(y);
    bn_to_le(out, y);
    out[31] |= (uint8_t)((x[0] & 1) << 7);
}

static void ge_base(ge *b)
{
    fe_set(b->X, BX); fe_set(b->Y, BY); fe_one(b->Z);
    fe_mul(b->T, b->X, b->Y);
}

/* r = p + (qx, qy) with the second point affine (Z = 1, T = qx * qy): add-2008-hwcd-3 with 9 multiplications */
static void ge_add_mixed(ge *r, const ge *p, const fe qx, const fe qy)
{
    fe A, B, C, D, E, F, G, H, t0, t1;
    fe_sub(t0, p->Y, p->X);  fe_sub(t1, qy, qx);  fe_mul(A, t0, t1);
    fe_add(t0, p->Y, p->X);  fe_add(t1, qy, qx);  fe_mul(B, t0, t1);
    fe_mul(t1, qx, qy);      fe_mul(t0, p->T, t1); fe_mul(C, t0, D2);
    fe_add(D, p->Z, p->Z);
    fe_sub(E, B, A);  fe_sub(F, D, C);  fe_add(G, D, C);  fe_add(H, B, A);
    fe_mul(r->X, E, F);  fe_mul(r->Y, G, H);  fe_mul(r->T, E, H);  fe_mul(r->Z, F, G);
}

/* ---- fixed base multiplication k * B with a table, as in secp256k1.c: 65 windows of 4 bits with signed digits -8..8,
 * d * 16^i * B for d = 1..8 stored affine (x then y, 8 words each): 33 280 bytes of RAM, built on first use. k is used as
 * is, all 256 bits (the top window only carries). Constant time: the digit is picked by scanning with masks, the sign is
 * a masked negation of x (the negative of (x, y) is (-x, y)), digit 0 skips the addition by a mask. ---- */
static uint32_t fb_tab[FB_WINDOWS][8][16];

/* Built in small steps like the secp256k1 table (fbtab.c): the work area fb_buf is shared, the two tables are built one after the other. */
static void ed_set_base(void *p) { ge_base(p); }
static void ed_add(void *r, const void *p, const void *q) { ge_add(r, p, q); }
static void ed_dbl(void *r, const void *p) { ge_add(r, p, p); }
static const fb_ops FB_OPS = { 32, ed_set_base, ed_add, ed_dbl, fe_mul, fe_inv, fe_normalize };
static fb_state fb;

/* One unit of work towards the table, the progress in percent (100: ready). */
int ed25519_table_step(void) { return fb_step(&fb, &FB_OPS, fb_tab); }

static void fb_build(void)
{
    while (ed25519_table_step() < 100) {}
}

/* r = k * B, k 32 byte little-endian */
static void ge_mul_base(ge *r, const uint8_t k[32])
{
    int8_t dig[FB_WINDOWS];
    uint32_t carry = 0;
    ge acc, t;
    fe zero;

    if (!fb.ready) fb_build();
    for (int i = 0; i < 64; i++) {                                   /* signed digits: v > 8 becomes v - 16 and a carry */
        uint32_t v = (uint32_t) ((k[i >> 1] >> ((i & 1) * 4)) & 15) + carry;
        carry = (8u - v) >> 31;
        dig[i] = (int8_t) (v - (carry << 4));
    }
    dig[64] = (int8_t) carry;
    fe_zero(zero);
    ge_identity(&acc);
    for (int i = 0; i < FB_WINDOWS; i++) {
        uint32_t dv = (uint32_t) (int32_t) dig[i], neg = dv >> 31, m = 0u - neg;
        uint32_t a = (dv ^ m) - m;                                   /* |digit| */
        fe sx, sy, nx;
        fe_zero(sx); fe_zero(sy);
        for (int j = 0; j < 8; j++) {
            uint32_t eq = ~ct_mask_nz(a ^ (uint32_t) (j + 1));
            for (int w = 0; w < 8; w++) {
                sx[w] |= eq & fb_tab[i][j][w];
                sy[w] |= eq & fb_tab[i][j][8 + w];
            }
        }
        fe_sub(nx, zero, sx);
        bn_cmov(sx, nx, m);                                          /* negative digit: -x */
        ge_add_mixed(&t, &acc, sx, sy);
        m = ct_mask_nz(a);                                           /* digit 0: no addition */
        bn_cmov(acc.X, t.X, m); bn_cmov(acc.Y, t.Y, m); bn_cmov(acc.Z, t.Z, m); bn_cmov(acc.T, t.T, m);
    }
    *r = acc;
    secure_zero(&t, sizeof t);
    secure_zero(dig, sizeof dig);
}

static const uint32_t FD[8] = ED_D;

/* r = a^e, e given as 8 limbs (public exponent) */
static void fe_pow(fe r, const fe a, const uint32_t e[8])
{
    fe acc, base;
    fe_one(acc);
    fe_set(base, a);
    for (int i = 0; i < 255; i++) {
        if ((e[i >> 5] >> (i & 31)) & 1) fe_mul(acc, acc, base);
        fe_sqr(base, base);
    }
    fe_set(r, acc);
}

static int fe_equal(const fe a, const fe b)
{
    fe x, y;
    fe_set(x, a); fe_set(y, b);
    fe_normalize(x); fe_normalize(y);
    return memcmp(x, y, 32) == 0;
}

/* RFC 8032 point decoding (public data, so not constant time). Returns 0 on success. */
static int ge_decode(ge *p, const uint8_t in[32])
{
    uint8_t buf[32];
    fe y, u, v, v3, x, t, I, e, one;
    uint32_t ex[8];
    int sign = in[31] >> 7;

    memcpy(buf, in, 32);
    buf[31] &= 0x7f;
    bn_from_le(y, buf);
    if (!bn_lt(y, FP)) return -1;
    fe_one(one);
    fe_sqr(u, y);
    fe_mul(v, u, FD);
    fe_add(v, v, one);                  /* v = d y^2 + 1 */
    fe_sub(u, u, one);                  /* u = y^2 - 1 */
    fe_sqr(v3, v); fe_mul(v3, v3, v);   /* v^3 */
    fe_sqr(t, v3); fe_mul(t, t, v);     /* v^7 */
    fe_mul(t, t, u);                    /* u v^7 */
    /* (p - 5) / 8 = 2^252 - 3 */
    memset(ex, 0xff, 32); ex[7] = 0x0fffffffu; ex[0] = 0xfffffffdu;
    fe_pow(t, t, ex);
    fe_mul(x, t, u); fe_mul(x, x, v3);  /* x = u v^3 (u v^7)^((p-5)/8) */
    fe_sqr(t, x); fe_mul(t, t, v);      /* v x^2 */
    if (!fe_equal(t, u)) {
        fe nu;
        fe_zero(nu); fe_sub(nu, nu, u);
        if (!fe_equal(t, nu)) return -1;
        /* I = sqrt(-1) = 2^((p-1)/4) */
        fe_zero(e); e[0] = 2;
        memset(ex, 0xff, 32); ex[7] = 0x1fffffffu; ex[0] = 0xfffffffbu;   /* (p - 1) / 4 = 2^253 - 5 */
        fe_pow(I, e, ex);
        fe_mul(x, x, I);
    }
    fe_normalize(x);
    if ((int)(x[0] & 1) != sign) { fe_zero(t); fe_sub(x, t, x); fe_normalize(x); }
    else if (sign && bn_zero_mask(x) == 0xffffffffu) return -1;   /* x = 0 with the sign bit set */
    fe_set(p->X, x); fe_set(p->Y, y); fe_one(p->Z);
    fe_mul(p->T, x, y);
    return 0;
}

/* ---- public API ---- */

int ed25519_subaddress_keys(uint8_t D[32], uint8_t C[32], const uint8_t B[32], const uint8_t a[32], const uint8_t m[32])
{
    ge b, mg, d, c;
    if (ge_decode(&b, B)) return -1;
    ge_mul_base(&mg, m);
    ge_add(&d, &b, &mg);
    ge_mul(&c, &d, a);
    ge_encode(D, &d);
    ge_encode(C, &c);
    secure_zero(&mg, sizeof mg);
    secure_zero(&c, sizeof c);
    return 0;
}

void ed25519_scalarmult_base(uint8_t out[32], const uint8_t scalar[32])
{
    ge r;
    ge_mul_base(&r, scalar);
    ge_encode(out, &r);
    secure_zero(&r, sizeof r);
}

void ed25519_pubkey_from_seed(uint8_t pub[32], const uint8_t seed[32])
{
    uint8_t h[64];
    sha512(seed, 32, h);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    ed25519_scalarmult_base(pub, h);
    secure_zero(h, sizeof h);
}

void ed25519_sc_reduce64(uint8_t out[32], const uint8_t in[64])
{
    uint32_t x[16], r[8];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)in[4*i] | (uint32_t)in[4*i+1] << 8 | (uint32_t)in[4*i+2] << 16 | (uint32_t)in[4*i+3] << 24;
    bn_mod_wide(r, x, 16, FL);
    bn_to_le(out, r);
    secure_zero(x, sizeof x); secure_zero(r, sizeof r);
}

void ed25519_sc_reduce32(uint8_t s[32])
{
    uint32_t x[8], r[8];
    bn_from_le(x, s);
    bn_mod_wide(r, x, 8, FL);
    bn_to_le(s, r);
    secure_zero(x, sizeof x); secure_zero(r, sizeof r);
}

void ed25519_sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t x[8], y[8], z[8];
    bn_from_le(x, a); bn_from_le(y, b);
    bn_add_mod(z, x, y, FL);
    bn_to_le(r, z);
    secure_zero(x, sizeof x); secure_zero(y, sizeof y); secure_zero(z, sizeof z);
}

void ed25519_sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t x[8], y[8], t[16], z[8];
    bn_from_le(x, a); bn_from_le(y, b);
    bn_mul_wide(t, x, y);
    bn_mod_wide(z, t, 16, FL);
    bn_to_le(r, z);
    secure_zero(x, sizeof x); secure_zero(y, sizeof y); secure_zero(t, sizeof t); secure_zero(z, sizeof z);
}

/* ---- Ristretto255 (RFC 9496): the prime order group of Schnorrkel / sr25519, encoding only ---- */

static const uint32_t SQRT_M1[8] = {0x4a0ea0b0, 0xc4ee1b27, 0xad2fe478, 0x2f431806, 0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480};
static const uint32_t INVSQRT_A_MINUS_D[8] = {0x805d40ea, 0x99c8fdaa, 0x5a4172be, 0x9d2f1617, 0xfe01d840, 0x16c27b91, 0xcfaffca2, 0x786c8905};
static const uint32_t P58[8] = {0xfffffffd, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x0fffffff};

static int fe_is_neg(const fe a)
{
    fe t;
    fe_set(t, a);
    fe_normalize(t);
    return (int) (t[0] & 1);
}

static void fe_neg(fe r, const fe a)
{
    fe z;
    fe_zero(z);
    fe_sub(r, z, a);
}

/* r = 1 / sqrt(v) (the non negative root), for a v that is a square: SQRT_RATIO_M1(1, v) of RFC 9496 */
static void fe_invsqrt(fe r, const fe v)
{
    fe v2, v3, v7, t, x, check, one, mone, mi;
    fe_sqr(v2, v);
    fe_mul(v3, v2, v);
    fe_sqr(t, v3);
    fe_mul(v7, t, v);
    fe_pow(t, v7, P58);
    fe_mul(x, v3, t);
    fe_sqr(check, x);
    fe_mul(check, check, v);
    fe_one(one);
    fe_neg(mone, one);
    fe_neg(mi, SQRT_M1);
    if (fe_equal(check, mone) || fe_equal(check, mi)) fe_mul(x, x, SQRT_M1);
    if (fe_is_neg(x)) fe_neg(x, x);
    fe_set(r, x);
}

static void ristretto_encode(uint8_t out[32], const ge *p)
{
    fe u1, u2, t0, t1, invs, den1, den2, zinv, ix0, iy0, enc, x, y, den_inv, s, tmp;
    fe_add(t0, p->Z, p->Y);
    fe_sub(t1, p->Z, p->Y);
    fe_mul(u1, t0, t1);
    fe_mul(u2, p->X, p->Y);
    fe_sqr(t0, u2);
    fe_mul(t0, t0, u1);
    fe_invsqrt(invs, t0);
    fe_mul(den1, invs, u1);
    fe_mul(den2, invs, u2);
    fe_mul(zinv, den1, den2);
    fe_mul(zinv, zinv, p->T);
    fe_mul(ix0, p->X, SQRT_M1);
    fe_mul(iy0, p->Y, SQRT_M1);
    fe_mul(enc, den1, INVSQRT_A_MINUS_D);
    fe_mul(tmp, p->T, zinv);
    if (fe_is_neg(tmp)) { fe_set(x, iy0); fe_set(y, ix0); fe_set(den_inv, enc); }
    else { fe_set(x, p->X); fe_set(y, p->Y); fe_set(den_inv, den2); }
    fe_mul(tmp, x, zinv);
    if (fe_is_neg(tmp)) fe_neg(y, y);
    fe_sub(tmp, p->Z, y);
    fe_mul(s, den_inv, tmp);
    if (fe_is_neg(s)) fe_neg(s, s);
    fe_normalize(s);
    bn_to_le(out, s);
}

void ed25519_ristretto_basemul(uint8_t out[32], const uint8_t scalar[32])
{
    ge r;
    ge_mul_base(&r, scalar);
    ristretto_encode(out, &r);
    secure_zero(&r, sizeof r);
}

/* ---- Monero: hash to point (crypto-ops.c, ge_fromfe_frombytes_vartime), the generic group interface ---- */

static const uint32_t XM_MA[8] = {0xfff892e7u,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0x7fffffffu};     /* -A */
static const uint32_t XM_MA2[8] = {0xdb3de3c9u,0xffffffc8u,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0x7fffffffu};   /* -A^2 */
static const uint32_t XM_FFFB1[8] = {0xcde3bdffu,0xdd58968au,0x46d58c72u,0x2e6bfb57u,0xbe04e61cu,0xdf563ac8u,0x2529e4e8u,0x018e0410u};  /* sqrt(-2A(A+2)) */
static const uint32_t XM_FFFB2[8] = {0x9f83650du,0x2d219b7cu,0xfba90820u,0xae21fcb9u,0x3fe9a041u,0x6e2bae48u,0xfba5d309u,0x32f9e1f5u};  /* sqrt(2A(A+2)) */
static const uint32_t XM_FFFB3[8] = {0x17302c66u,0x581b7d87u,0xa5964229u,0x4024ff4eu,0x3f0da2edu,0xb8954640u,0x14c208efu,0x674a110du};  /* sqrt(-i A(A+2)) */
static const uint32_t XM_FFFB4[8] = {0x494c6e67u,0x7ac2e6fcu,0x5ec0b5b6u,0x11b903f7u,0x8108bcd1u,0xd93f0b77u,0xef982406u,0x65bc0cfcu};  /* sqrt(i A(A+2)) */

/* r = z^(2^252 - 3) */
static void fe_pow22523(fe r, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sqr(t0, z);
    fe_sqr_n(t1, t0, 2);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sqr(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sqr_n(t2, t1, 5);   fe_mul(t1, t2, t1);
    fe_sqr_n(t2, t1, 10);  fe_mul(t2, t2, t1);
    fe_sqr_n(t3, t2, 20);  fe_mul(t2, t3, t2);
    fe_sqr_n(t2, t2, 10);  fe_mul(t1, t2, t1);
    fe_sqr_n(t2, t1, 50);  fe_mul(t2, t2, t1);
    fe_sqr_n(t3, t2, 100); fe_mul(t2, t3, t2);
    fe_sqr_n(t2, t2, 50);  fe_mul(t1, t2, t1);
    fe_sqr_n(t1, t1, 2);   fe_mul(r, t1, z);
}

/* r = u^(m+1) / v^(m+1) with m = (p - 5) / 8 (Monero's fe_divpowm1) */
static void fe_divpowm1(fe r, const fe u, const fe v)
{
    fe v3, uv7, t0;
    fe_sqr(v3, v); fe_mul(v3, v3, v);
    fe_sqr(uv7, v3); fe_mul(uv7, uv7, v); fe_mul(uv7, uv7, u);
    fe_pow22523(t0, uv7);
    fe_mul(t0, t0, v3);
    fe_mul(r, t0, u);
}

static int fe_isnonzero(const fe a)
{
    fe t;
    uint32_t o = 0;
    fe_set(t, a);
    fe_normalize(t);
    for (int i = 0; i < 8; i++) o |= t[i];
    return o != 0;
}

void ed_hash_to_point(ed_ge *r, const uint8_t h[32])
{
    fe u, v, w, x, y, z, X, Z, Y;
    int neg = 0, sign;

    bn_from_le(u, h);
    fe_sqr(v, u); fe_add(v, v, v);                         /* 2 u^2 */
    fe_one(w); fe_add(w, v, w);                            /* w = 2 u^2 + 1 */
    fe_sqr(x, w);
    fe_mul(y, XM_MA2, v);
    fe_add(x, x, y);                                       /* x = w^2 - 2 A^2 u^2 */
    fe_divpowm1(X, w, x);
    fe_sqr(y, X);
    fe_mul(x, y, x);
    fe_sub(y, w, x);
    fe_set(z, XM_MA);
    if (fe_isnonzero(y)) {
        fe_add(y, w, x);
        if (fe_isnonzero(y)) neg = 1;
        else fe_mul(X, X, XM_FFFB1);
    } else fe_mul(X, X, XM_FFFB2);
    if (!neg) {
        fe_mul(X, X, u);
        fe_mul(z, z, v);
        sign = 0;
    } else {
        fe_mul(x, x, SQRT_M1);
        fe_sub(y, w, x);
        if (fe_isnonzero(y)) fe_mul(X, X, XM_FFFB3);
        else fe_mul(X, X, XM_FFFB4);
        sign = 1;
    }
    fe_normalize(X);
    if ((int) (X[0] & 1) != sign) { fe_zero(y); fe_sub(X, y, X); fe_normalize(X); }
    fe_add(Z, z, w);
    fe_sub(Y, z, w);
    {
        ge p;
        fe_mul(p.X, X, Z); fe_set(p.Y, Y); fe_set(p.Z, Z); fe_mul(p.T, X, Y);
        ge_dbl(&p, &p); ge_dbl(&p, &p); ge_dbl(&p, &p);        /* times the cofactor 8 */
        *r = p;
    }
}

int ed_ge_decode(ed_ge *p, const uint8_t in[32]) { return ge_decode(p, in); }
void ed_ge_encode(uint8_t out[32], const ed_ge *p) { ge_encode(out, p); }
void ed_ge_identity(ed_ge *p) { ge_identity(p); }
void ed_ge_add(ed_ge *r, const ed_ge *p, const ed_ge *q) { ge_add(r, p, q); }
void ed_ge_mul(ed_ge *r, const ed_ge *p, const uint8_t k[32]) { ge_mul(r, p, k); }
void ed_ge_mul_base(ed_ge *r, const uint8_t k[32]) { ge_mul_base(r, k); }

void ed_ge_neg(ed_ge *r, const ed_ge *p)
{
    fe z;
    fe_zero(z);
    fe_sub(r->X, z, p->X);
    fe_set(r->Y, p->Y);
    fe_set(r->Z, p->Z);
    fe_sub(r->T, z, p->T);
}

void ed_ge_sub(ed_ge *r, const ed_ge *p, const ed_ge *q)
{
    ge n;
    ed_ge_neg(&n, q);
    ge_add(r, p, &n);
}

void ed_ge_mul8(ed_ge *r, const ed_ge *p)
{
    ge_dbl(r, p); ge_dbl(r, r); ge_dbl(r, r);
}

int ed_ge_equal(const ed_ge *p, const ed_ge *q)
{
    fe a, b;
    fe_mul(a, p->X, q->Z); fe_mul(b, q->X, p->Z);
    if (!fe_equal(a, b)) return 0;
    fe_mul(a, p->Y, q->Z); fe_mul(b, q->Y, p->Z);
    return fe_equal(a, b);
}

int ed_ge_is_identity(const ed_ge *p)
{
    ge id;
    ge_identity(&id);
    return ed_ge_equal(p, &id);
}

/* width-5 NAF of a scalar: digits d[i] (odd, |d| <= 15, at most one in five non zero) with k = sum d[i] 2^i. Returns the number of digits. */
#define NAF_W 5
static int wnaf(int8_t d[264], const uint8_t k[32])
{
    uint32_t x[9];
    int n = 0;
    bn_from_le(x, k);
    x[8] = 0;
    for (;;) {
        uint32_t o = 0;
        int dig = 0;
        for (int i = 0; i < 9; i++) o |= x[i];
        if (!o) break;
        if (x[0] & 1) {
            dig = (int) (x[0] & ((1u << NAF_W) - 1));
            if (dig >= (1 << (NAF_W - 1))) dig -= 1 << NAF_W;
            if (dig > 0) {                                       /* x -= dig */
                uint64_t b = (uint64_t) dig;
                for (int i = 0; i < 9 && b; i++) { uint64_t t = (uint64_t) x[i] - b; x[i] = (uint32_t) t; b = (t >> 32) & 1; }
            } else {                                             /* x += -dig */
                uint64_t c = (uint64_t) -dig;
                for (int i = 0; i < 9 && c; i++) { uint64_t t = (uint64_t) x[i] + c; x[i] = (uint32_t) t; c = t >> 32; }
            }
        }
        d[n++] = (int8_t) dig;
        for (int i = 0; i < 8; i++) x[i] = (x[i] >> 1) | (x[i + 1] << 31);
        x[8] >>= 1;
    }
    return n;
}

/* odd multiples 1P, 3P, ... 15P */
static void odd_table(ge t[8], const ge *p)
{
    ge p2;
    t[0] = *p;
    ge_dbl(&p2, p);
    for (int i = 1; i < 8; i++) ge_add(&t[i], &t[i - 1], &p2);
}

void ed_ge_mul2_vt(ed_ge *r, const uint8_t k1[32], const ed_ge *p1, const uint8_t k2[32], const ed_ge *p2)
{
    int8_t d1[264], d2[264];
    ge t1[8], t2[8], acc, n;
    int n1 = wnaf(d1, k1), n2 = wnaf(d2, k2), top = n1 > n2 ? n1 : n2;
    if (n1) odd_table(t1, p1);
    if (n2) odd_table(t2, p2);
    ge_identity(&acc);
    for (int i = top - 1; i >= 0; i--) {
        ge_dbl(&acc, &acc);
        if (i < n1 && d1[i]) {
            int v = d1[i];
            if (v > 0) ge_add(&acc, &acc, &t1[v >> 1]);
            else { ge_neg(&n, &t1[(-v) >> 1]); ge_add(&acc, &acc, &n); }
        }
        if (i < n2 && d2[i]) {
            int v = d2[i];
            if (v > 0) ge_add(&acc, &acc, &t2[v >> 1]);
            else { ge_neg(&n, &t2[(-v) >> 1]); ge_add(&acc, &acc, &n); }
        }
    }
    *r = acc;
}

void ed25519_sc_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t x[8], y[8], t[8];
    bn_from_le(x, a); bn_from_le(y, b);
    bn_sub(t, FL, y);                                    /* L - b, equal to L when b = 0 */
    bn_mod_wide(y, t, 8, FL);
    bn_add_mod(t, x, y, FL);
    bn_to_le(r, t);
    secure_zero(x, sizeof x); secure_zero(y, sizeof y); secure_zero(t, sizeof t);
}
