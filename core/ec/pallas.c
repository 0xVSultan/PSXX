#include "ec/pallas.h"
#include <string.h>
#include "ec/bn.h"
#include "hash/blake2b.h"

/* ---- constants (plain little-endian 32 bit limbs; see tools/gen_chain_vectors.py for how they were derived) ---- */

static const uint32_t P[8]  = {0x00000001, 0x992d30ed, 0x094cf91b, 0x224698fc, 0, 0, 0, 0x40000000};
static const uint32_t Q[8]  = {0x00000001, 0x8c46eb21, 0x0994a8dd, 0x224698fc, 0, 0, 0, 0x40000000};
static const uint32_t R1[8] = {0xfffffffd, 0x34786d38, 0xe41914ad, 0x992c350b, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff};  /* 2^256 mod p */
static const uint32_t R2[8] = {0x0000000f, 0x8c78ecb3, 0x8b0de0e7, 0xd7d30dbd, 0xc3c95d18, 0x7797a99b, 0x7b9cb714, 0x096d41af};  /* 2^512 mod p */
static const uint32_t PM2[8] = {0xffffffff, 0x992d30ec, 0x094cf91b, 0x224698fc, 0, 0, 0, 0x40000000};                              /* p - 2 */
static const uint32_t TM1D2[8] = {0xcc969876, 0x04a67c8d, 0x11234c7e, 0, 0, 0, 0x20000000, 0};     /* (T - 1) / 2, p - 1 = 2^32 * T */
static const uint32_t ROOT[8] = {0xd87ea32f, 0xbdad6fab, 0xb7bb7584, 0xea322bf2, 0x0561f81a, 0x36212083, 0xac30ebda, 0x2bce74de};  /* 5^T */
static const uint32_t ISO_A[8] = {0x657a014b, 0x92bb4b0b, 0x1a27a59f, 0xb7413458, 0x58370742, 0x49be2d72, 0xb0ea8c9c, 0x18354a2e};
static const uint32_t ISO_B[8] = {1265, 0, 0, 0, 0, 0, 0, 0};
static const uint32_t SSWU_Z[8] = {0xfffffff4, 0x992d30ec, 0x094cf91b, 0x224698fc, 0, 0, 0, 0x40000000};    /* -13 */
static const uint32_t SSWU_C1[8] = {0x9470d7f8, 0x1c3006d8, 0x211b7b10, 0x7612d2d7, 0x2a13c1eb, 0xd97cab45, 0xaf7b3324, 0x3d115d87};  /* -B / A */
static const uint32_t SSWU_C2[8] = {0x9d89d89e, 0xd873d7bd, 0x79bb24bb, 0xaab8b0fe, 0xd89d89d8, 0x89d89d89, 0x9d89d89d, 0x189d89d8};  /* -1 / Z */
static const uint32_t ISO[13][8] = {
    {0xaaaaaaab, 0x775f6034, 0x73d8375b, 0x40817754, 0x8e38e38e, 0xe38e38e3, 0x38e38e38, 0x0e38e38e},
    {0x2814fb76, 0x8cf863b0, 0xe4b99495, 0x0f93b82e, 0x51cf412a, 0x267c7ffa, 0x1872d88e, 0x3509afd5},
    {0xf37ea4f7, 0x0eb64fae, 0xcfeb6d69, 0x380af066, 0x3d98fd13, 0x98c7d7ac, 0xc5253753, 0x17329b9e},
    {0x55555580, 0xeebec069, 0xe7b06eb6, 0x8102eea8, 0x1c71c71c, 0xc71c71c7, 0x71c71c71, 0x1c71c71c},
    {0x68bcd71f, 0xc47f2ab6, 0xc96b6980, 0x9c434ac1, 0xe0494a79, 0x5a607fcc, 0xdc099cff, 0x1d572e7d},
    {0xae5b6604, 0x2aa3af1e, 0x9a1fc81c, 0xb4abf9fb, 0x7f22b105, 0x1d13bf2a, 0xcaecd5d1, 0x325669be},
    {0xe38e38e4, 0x5ad985b5, 0xd461bad2, 0x7642b01a, 0x84bda12f, 0x4bda12f6, 0xbda12f68, 0x1a12f684},
    {0x140a7dbb, 0xc67c31d8, 0x725cca4a, 0x07c9dc17, 0x28e7a095, 0x133e3ffd, 0x8c396c47, 0x1a84d7ea},
    {0xd225b234, 0x02e2be87, 0xf7459378, 0x1765e924, 0xe1db9ff1, 0x303216cc, 0xd2ddcadd, 0x3fb98ff0},
    {0x71c71c4f, 0x93e53ab3, 0x134eb3e4, 0x0ac03e8e, 0x97b425ed, 0x7b425ed0, 0xb425ed09, 0x025ed097},
    {0x1d1b42ae, 0x5a28279b, 0xa97aa1b3, 0x5941a3a4, 0x506defb6, 0x0790bfb3, 0xca0e6b7f, 0x0c02c5bc},
    {0x0b12320a, 0x4d90ab82, 0xbbc5661d, 0xd976bbfa, 0x7d681310, 0x573b3d7f, 0x60c68173, 0x17033d3c},
    {0xfffffde5, 0x992d30ec, 0x094cf91b, 0x224698fc, 0, 0, 0, 0x40000000}};

/* ---- field: Montgomery arithmetic, p = 1 mod 2^32, so the reduction factor is -t0 ---- */

#ifdef PL_COUNT_MULS
unsigned long pl_muls;
#define COUNT_MUL() (pl_muls++)
#else
#define COUNT_MUL() ((void) 0)
#endif

/* t[0..8] (< 2p) -> r < p: one conditional subtraction */
static void final_sub(pl_fp r, const uint32_t t[9])
{
    uint32_t s[8], borrow = bn_sub(s, t, P);
    uint32_t take = ct_mask_nz(t[8] | (borrow ^ 1));
    for (int i = 0; i < 8; i++) r[i] = t[i];
    bn_cmov(r, s, take);
}

/* Montgomery reduction of a 16 limb product: r = t / 2^256 mod p (t < p * 2^256, t[16] scratch). p = 1 + P1 2^32 + P2 2^64 +
 * P3 2^96 + 2^254, so the factor of limb i is m = -t[i] and adding m * p costs three multiplications and a shift. The carry out of
 * limb i + 7 goes into limb i + 8, and its overflow bit travels one limb further with every round (no data dependent loop). */
static void redc(pl_fp r, uint32_t *t)
{
    uint32_t ex = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t m = 0u - t[i];
        uint64_t c = (uint64_t) t[i] + m;                          /* limb i becomes 0, carry 1 unless it was 0 */
        c >>= 32;
        c += (uint64_t) m * P[1] + t[i + 1]; t[i + 1] = (uint32_t) c; c >>= 32;
        c += (uint64_t) m * P[2] + t[i + 2]; t[i + 2] = (uint32_t) c; c >>= 32;
        c += (uint64_t) m * P[3] + t[i + 3]; t[i + 3] = (uint32_t) c; c >>= 32;
        c += t[i + 4]; t[i + 4] = (uint32_t) c; c >>= 32;
        c += t[i + 5]; t[i + 5] = (uint32_t) c; c >>= 32;
        c += t[i + 6]; t[i + 6] = (uint32_t) c; c >>= 32;
        c += ((uint64_t) m << 30) + t[i + 7]; t[i + 7] = (uint32_t) c; c >>= 32;
        c += (uint64_t) t[i + 8] + ex; t[i + 8] = (uint32_t) c; ex = (uint32_t) (c >> 32);
    }
    t[16] = ex;
    final_sub(r, t + 8);
}

/* the product lives in the scratchpad on the PSX (1 cycle per access, main RAM costs about 6): bytes 0x380.. of it, clear of
 * the areas of Keccak and SHA-512 (0x000..0x27F) */
#ifdef PALLAS_SCRATCH
#define FP_T ((uint32_t *) 0x1F800380u)
#define FP_T_DECL
#else
#define FP_T t_
#define FP_T_DECL uint32_t t_[17];
#endif

static void fp_mul(pl_fp r, const pl_fp a, const pl_fp b)
{
    FP_T_DECL
    COUNT_MUL();
    bn_mul_wide(FP_T, a, b);                            /* unrolled product scanning (bn_comba.h) */
    redc(r, FP_T);
}

static void fp_sqr(pl_fp r, const pl_fp a)
{
    FP_T_DECL
    COUNT_MUL();
    bn_sqr_wide(FP_T, a);                               /* 36 products instead of 64 */
    redc(r, FP_T);
}
static void fp_add(pl_fp r, const pl_fp a, const pl_fp b) { bn_add_mod(r, a, b, P); }

static void fp_sub(pl_fp r, const pl_fp a, const pl_fp b)
{
    uint32_t t[8], borrow = bn_sub(r, a, b);
    bn_add(t, r, P);
    bn_cmov(r, t, 0u - borrow);
}

static void fp_neg(pl_fp r, const pl_fp a)
{
    pl_fp z;
    memset(z, 0, sizeof z);
    fp_sub(r, z, a);
}

static void fp_set(pl_fp r, const pl_fp a) { memcpy(r, a, 32); }
static void fp_zero(pl_fp r) { memset(r, 0, 32); }
static void fp_one(pl_fp r) { memcpy(r, R1, 32); }
static int  fp_is_zero(const pl_fp a) { uint32_t o = 0; for (int i = 0; i < 8; i++) o |= a[i]; return o == 0; }
static int  fp_eq(const pl_fp a, const pl_fp b) { return memcmp(a, b, 32) == 0; }

static void fp_to_mont(pl_fp r, const uint32_t plain[8]) { fp_mul(r, plain, R2); }

static void fp_to_plain(uint32_t r[8], const pl_fp a)
{
    static const uint32_t ONE[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    fp_mul(r, a, ONE);
}

/* x * 15 (b3 = 3 * 5) */
static void fp_mul15(pl_fp r, const pl_fp a)
{
    pl_fp t;
    fp_add(t, a, a);
    fp_add(t, t, t);
    fp_add(t, t, t);
    fp_add(t, t, t);        /* 16 a */
    fp_sub(r, t, a);
}

/* r = a^e for a public exponent of `bits` bits */
static void fp_pow(pl_fp r, const pl_fp a, const uint32_t e[8], int bits)
{
    pl_fp acc, base;
    fp_one(acc);
    fp_set(base, a);
    for (int i = bits - 1; i >= 0; i--) {
        fp_sqr(acc, acc);
        if ((e[i >> 5] >> (i & 31)) & 1) fp_mul(acc, acc, base);
    }
    fp_set(r, acc);
}

static void fp_inv(pl_fp r, const pl_fp a) { fp_pow(r, a, PM2, 255); }       /* 0 maps to 0 */

typedef struct { pl_fp A, B, Z, C1, C2, iso[13], rootpow[32], zc, zeta, z27, g16[16], wtab[8][16]; int ready; } sswu_consts;
static sswu_consts K;
static void init_consts(void);

/* Tonelli-Shanks for p = 1 mod 2^32. Returns 1 and a root if a is a square (0 counts), else 0. */
static int fp_sqrt(pl_fp r, const pl_fp a)
{
    pl_fp z, x, b, c, t, one;
    int y = 32;
    fp_one(one);
    fp_pow(z, a, TM1D2, 222);
    fp_mul(x, a, z);                 /* a^((T+1)/2) */
    fp_mul(b, x, z);                 /* a^T */
    fp_set(t, b);
    for (int i = 0; i < 31; i++) fp_sqr(t, t);       /* a^((p-1)/2): 1 for a square, -1 for a non square */
    if (fp_is_zero(t)) { fp_zero(r); return 1; }
    if (!fp_eq(t, one)) return 0;
    init_consts();
    (void) c; (void) y;
    while (!fp_eq(b, one)) {
        int k = 1;
        pl_fp b2k;
        fp_sqr(b2k, b);
        while (!fp_eq(b2k, one)) { fp_sqr(b2k, b2k); k++; }
        fp_mul(x, x, K.rootpow[31 - k]);                   /* w = c^(2^(y-k-1)) = ROOT^(2^(31-k)) */
        fp_mul(b, b, K.rootpow[32 - k]);                   /* b * w^2 */
    }
    fp_set(r, x);
    return 1;
}

/* A square root of s, or, when s is a non square, of Z s (Z a fixed non square): a single exponentiation serves both cases.
 * Tonelli-Shanks with p - 1 = 2^32 T: x = s^((T+1)/2) and b = s^T satisfy x^2 = s b, and b = zeta^(2e) for the primitive 2^32nd
 * root of unity zeta = Z^T and e < 2^31; the root is x zeta^(-e). The logarithm e is found four bits at a time (Pohlig-Hellman:
 * eight stages of a few squarings and a 16 entry table) instead of by the bit by bit search of the textbook algorithm.
 * Returns 1 when s is a square (r^2 = s, 0 counts) and 0 otherwise (r^2 = Z s). */
static int fp_sqrt_or_z(pl_fp r, const pl_fp s)
{
    pl_fp z, x, b, c, c0, t, one;
    int sq;

    fp_one(one);
    init_consts();
    fp_pow(z, s, TM1D2, 222);
    fp_mul(x, s, z);                 /* s^((T+1)/2) */
    fp_mul(b, x, z);                 /* s^T */
    if (fp_is_zero(b)) { fp_zero(r); return 1; }
    fp_set(c0, b);
    for (int i = 0; i < 27; i++) fp_sqr(c0, c0);     /* b^(2^27): of order 16 or less for a square, 32 for a non square */
    fp_set(t, c0);
    for (int i = 0; i < 4; i++) fp_sqr(t, t);
    sq = fp_eq(t, one);
    if (!sq) {                       /* (Z s)^((T+1)/2) = zc * x, (Z s)^T = zeta * b, and its 2^27th power gets zeta^(2^27) */
        fp_mul(x, x, K.zc);
        fp_mul(b, b, K.zeta);
        fp_mul(c0, c0, K.z27);
    }
    for (int st = 0; st < 8; st++) {
        int d = -1;
        if (st == 0) {
            fp_set(c, c0);
        } else {
            fp_set(c, b);
            for (int i = 0; i < 27 - 4 * st; i++) fp_sqr(c, c);   /* b^(2^(27 - 4 st)); b itself at st = 7 */
        }
        if (st < 7) { for (int i = 0; i < 16; i++) if (fp_eq(c, K.g16[i])) { d = i; break; } }
        else        { for (int i = 0; i < 8; i++)  if (fp_eq(c, K.g16[2 * i])) { d = i; break; } }
        if (d < 0) { fp_zero(r); return 0; }           /* cannot happen */
        if (d) {
            fp_mul(x, x, K.wtab[st][d]);                  /* x zeta^(-d 16^st) */
            fp_sqr(t, K.wtab[st][d]);
            fp_mul(b, b, t);                              /* b zeta^(-2 d 16^st) */
        }
    }
    fp_set(r, x);
    return sq;
}

/* ---- the curve y^2 = x^3 + 5, complete projective formulas (Renes, Costello, Batina 2016, algorithms 7 and 9) ---- */

/* a point from its affine coordinates (32 bytes little-endian each, plain), for the tables read from a card */
void pl_from_affine(pl_pt *p, const uint8_t x[32], const uint8_t y[32])
{
    uint32_t t[8];
    bn_from_le(t, x); fp_to_mont(p->X, t);
    bn_from_le(t, y); fp_to_mont(p->Y, t);
    fp_one(p->Z);
}

void pl_identity(pl_pt *p)
{
    fp_zero(p->X);
    fp_one(p->Y);
    fp_zero(p->Z);
}

void pl_add(pl_pt *r, const pl_pt *a, const pl_pt *b)
{
    pl_fp t0, t1, t2, t3, t4, X3, Y3, Z3;
    fp_mul(t0, a->X, b->X);
    fp_mul(t1, a->Y, b->Y);
    fp_mul(t2, a->Z, b->Z);
    fp_add(t3, a->X, a->Y);
    fp_add(t4, b->X, b->Y);
    fp_mul(t3, t3, t4);
    fp_add(t4, t0, t1);
    fp_sub(t3, t3, t4);
    fp_add(t4, a->Y, a->Z);
    fp_add(X3, b->Y, b->Z);
    fp_mul(t4, t4, X3);
    fp_add(X3, t1, t2);
    fp_sub(t4, t4, X3);
    fp_add(X3, a->X, a->Z);
    fp_add(Y3, b->X, b->Z);
    fp_mul(X3, X3, Y3);
    fp_add(Y3, t0, t2);
    fp_sub(Y3, X3, Y3);
    fp_add(X3, t0, t0);
    fp_add(t0, X3, t0);
    fp_mul15(t2, t2);
    fp_add(Z3, t1, t2);
    fp_sub(t1, t1, t2);
    fp_mul15(Y3, Y3);
    fp_mul(X3, t4, Y3);
    fp_mul(t2, t3, t1);
    fp_sub(X3, t2, X3);
    fp_mul(Y3, Y3, t0);
    fp_mul(t1, t1, Z3);
    fp_add(Y3, t1, Y3);
    fp_mul(t0, t0, t3);
    fp_mul(Z3, Z3, t4);
    fp_add(Z3, Z3, t0);
    fp_set(r->X, X3);
    fp_set(r->Y, Y3);
    fp_set(r->Z, Z3);
}

void pl_dbl(pl_pt *r, const pl_pt *a)
{
    pl_fp t0, t1, t2, X3, Y3, Z3;
    fp_sqr(t0, a->Y);
    fp_add(Z3, t0, t0);
    fp_add(Z3, Z3, Z3);
    fp_add(Z3, Z3, Z3);
    fp_mul(t1, a->Y, a->Z);
    fp_sqr(t2, a->Z);
    fp_mul15(t2, t2);
    fp_mul(X3, t2, Z3);
    fp_add(Y3, t0, t2);
    fp_mul(Z3, t1, Z3);
    fp_add(t1, t2, t2);
    fp_add(t2, t1, t2);
    fp_sub(t0, t0, t2);
    fp_mul(Y3, t0, Y3);
    fp_add(Y3, X3, Y3);
    fp_mul(t1, a->X, a->Y);
    fp_mul(X3, t0, t1);
    fp_add(X3, X3, X3);
    fp_set(r->X, X3);
    fp_set(r->Y, Y3);
    fp_set(r->Z, Z3);
}

/* Fixed 4 bit windows from the top: 4 doublings and one addition per window (the complete formulas accept the identity, so a
 * digit 0 needs no special case), the summand picked from the 16 entry table by scanning it with masks: constant time. */
void pl_mul(pl_pt *r, const pl_pt *a, const uint8_t k[32])
{
    pl_pt tab[16], acc, sel;

    pl_identity(&tab[0]);
    tab[1] = *a;
    for (int i = 2; i < 16; i++) pl_add(&tab[i], &tab[i - 1], a);
    pl_identity(&acc);
    for (int i = 63; i >= 0; i--) {
        uint32_t d = (uint32_t) ((k[i >> 1] >> ((i & 1) * 4)) & 15);
        for (int j = 0; j < 4; j++) pl_dbl(&acc, &acc);
        memset(&sel, 0, sizeof sel);
        for (uint32_t j = 0; j < 16; j++) {
            uint32_t m = ~ct_mask_nz(d ^ j);
            for (int w = 0; w < 8; w++) {
                sel.X[w] |= m & tab[j].X[w];
                sel.Y[w] |= m & tab[j].Y[w];
                sel.Z[w] |= m & tab[j].Z[w];
            }
        }
        pl_add(&acc, &acc, &sel);
    }
    *r = acc;
    secure_zero(tab, sizeof tab);
    secure_zero(&sel, sizeof sel);
}

/* ---- encoding ---- */

static void affine(pl_fp x, pl_fp y, const pl_pt *p)
{
    pl_fp zi;
    fp_inv(zi, p->Z);
    fp_mul(x, p->X, zi);
    fp_mul(y, p->Y, zi);
}

void pl_encode(uint8_t out[32], const pl_pt *p)
{
    pl_fp x, y;
    uint32_t xp[8], yp[8];
    if (fp_is_zero(p->Z)) { memset(out, 0, 32); return; }
    affine(x, y, p);
    fp_to_plain(xp, x);
    fp_to_plain(yp, y);
    bn_to_le(out, xp);
    out[31] |= (uint8_t) ((yp[0] & 1) << 7);
}

void pl_x_bytes(uint8_t out[32], const pl_pt *p)
{
    pl_fp x, y;
    uint32_t xp[8];
    if (fp_is_zero(p->Z)) { memset(out, 0, 32); return; }
    affine(x, y, p);
    fp_to_plain(xp, x);
    bn_to_le(out, xp);
}

int pl_decode(pl_pt *p, const uint8_t in[32])
{
    uint8_t buf[32];
    uint32_t xp[8], yp[8], zero = 0;
    pl_fp x, y, y2, five;
    int sign, i;
    for (i = 0; i < 32; i++) zero |= in[i];
    if (!zero) { pl_identity(p); return 0; }
    memcpy(buf, in, 32);
    sign = buf[31] >> 7;
    buf[31] &= 0x7f;
    bn_from_le(xp, buf);
    if (!bn_lt(xp, P)) return -1;
    fp_to_mont(x, xp);
    fp_sqr(y2, x);
    fp_mul(y2, y2, x);
    {
        static const uint32_t FIVE[8] = {5, 0, 0, 0, 0, 0, 0, 0};
        fp_to_mont(five, FIVE);
    }
    fp_add(y2, y2, five);
    if (!fp_sqrt(y, y2)) return -1;
    fp_to_plain(yp, y);
    if ((int) (yp[0] & 1) != sign) fp_neg(y, y);
    fp_set(p->X, x);
    fp_set(p->Y, y);
    fp_one(p->Z);
    return 0;
}

/* ---- hash to curve ---- */

/* The constants and tables of the hash-to-curve (about 4.7 KB, a few hundred field operations), in three steps: pallas_table_step()
 * does one and returns the progress in percent, 100 when done. init_consts() finishes them all on first use. */
static int K_stage;

int pallas_table_step(void)
{
    if (K.ready) return 100;
    if (K_stage == 0) {
        fp_to_mont(K.A, ISO_A);
        fp_to_mont(K.B, ISO_B);
        fp_to_mont(K.Z, SSWU_Z);
        fp_to_mont(K.C1, SSWU_C1);
        fp_to_mont(K.C2, SSWU_C2);
        for (int i = 0; i < 13; i++) fp_to_mont(K.iso[i], ISO[i]);
        fp_to_mont(K.rootpow[0], ROOT);                       /* ROOT^(2^i), the 2-power roots of unity for the square root */
        for (int i = 1; i < 32; i++) fp_sqr(K.rootpow[i], K.rootpow[i - 1]);
        K_stage = 1;
        return 20;
    }
    if (K_stage == 1) {   /* Z is a non square: zeta = Z^T has order exactly 2^32 and zc = Z^((T+1)/2); they turn the root of a non square s into the root of Z s */
        pl_fp zt;
        fp_pow(zt, K.Z, TM1D2, 222);                          /* Z^((T-1)/2) */
        fp_mul(K.zc, zt, K.Z);
        fp_sqr(K.zeta, zt);
        fp_mul(K.zeta, K.zeta, K.Z);
        K_stage = 2;
        return 60;
    }
    {   /* tables of the discrete logarithm in <zeta> (order 2^32): z27 = zeta^(2^27), g16[i] = (zeta^(2^28))^i, and wtab[s][i] = zeta^(-i 16^s) */
        pl_fp u, inv, bs;
        fp_set(u, K.zeta);
        fp_one(inv);
        fp_one(K.g16[0]);
        for (int i = 0; i < 32; i++) {                        /* zeta^-1 = zeta^(2^32 - 1) = product of zeta^(2^i) */
            if (i == 27) fp_set(K.z27, u);
            if (i == 28) fp_set(K.g16[1], u);
            fp_mul(inv, inv, u);
            fp_sqr(u, u);
        }
        for (int i = 2; i < 16; i++) fp_mul(K.g16[i], K.g16[i - 1], K.g16[1]);
        fp_set(bs, inv);
        for (int st = 0; st < 8; st++) {
            fp_one(K.wtab[st][0]);
            for (int i = 1; i < 16; i++) fp_mul(K.wtab[st][i], K.wtab[st][i - 1], bs);
            for (int i = 0; i < 4; i++) fp_sqr(bs, bs);       /* zeta^(-16^(st+1)) */
        }
    }
    K.ready = 1;
    return 100;
}

static void init_consts(void)
{
    while (!K.ready) pallas_table_step();
}

/* the 3-isogeny to Pallas for the point (x, y) of the isogenous curve, kept projective: (Na Db : Nb Da : Da Db) */
static void iso_map(pl_pt *out, const pl_fp x, const pl_fp y)
{
    pl_fp x2_, x3, na, da, nb, db, t, yy;
    fp_sqr(x2_, x);
    fp_mul(x3, x2_, x);
    fp_mul(na, K.iso[0], x3);  fp_mul(t, K.iso[1], x2_);  fp_add(na, na, t);
    fp_mul(t, K.iso[2], x);    fp_add(na, na, t);         fp_add(na, na, K.iso[3]);
    fp_mul(da, K.iso[4], x);   fp_add(da, da, x2_);       fp_add(da, da, K.iso[5]);
    fp_mul(nb, K.iso[6], x3);  fp_mul(t, K.iso[7], x2_);  fp_add(nb, nb, t);
    fp_mul(t, K.iso[8], x);    fp_add(nb, nb, t);         fp_add(nb, nb, K.iso[9]);
    fp_mul(yy, nb, y);
    fp_mul(db, K.iso[11], x);  fp_mul(t, K.iso[10], x2_); fp_add(db, db, t);
    fp_add(db, db, x3);        fp_add(db, db, K.iso[12]);
    fp_mul(out->Z, da, db);
    fp_mul(out->X, na, db);
    fp_mul(out->Y, yy, da);
}

/* Simplified SWU on y^2 = x^3 + A x + B (the 3-isogenous curve), then the isogeny: the straight-line form of the hash-to-curve
 * draft (appendix F.2) with the square root of the ratio replaced by one root of N D (see fp_sqrt_or_z), so the only inversion is
 * that of tv4, which the two maps of a hash share (Montgomery's trick). Phase A needs no inversion, phase B finishes the point. */
typedef struct { pl_fp u, tv1, tv3, tv4, r; int sq; } sswu_state;

/* everything of phase A before the square root: the radicand s = N D goes to *s */
static void sswu_a_pre(sswu_state *w, const pl_fp u, pl_fp s)
{
    pl_fp tv2, tv5, tv6, N, one;

    fp_one(one);
    fp_set(w->u, u);
    fp_sqr(w->tv1, u);
    fp_mul(w->tv1, w->tv1, K.Z);                         /* Z u^2 */
    fp_sqr(tv2, w->tv1);
    fp_add(tv2, tv2, w->tv1);                            /* tv1^2 + tv1 */
    fp_add(w->tv3, tv2, one);
    fp_mul(w->tv3, w->tv3, K.B);                         /* B (tv2 + 1) */
    if (fp_is_zero(tv2)) fp_set(w->tv4, K.Z); else fp_neg(w->tv4, tv2);
    fp_mul(w->tv4, w->tv4, K.A);                         /* A (-tv2, or Z when tv2 = 0) */
    fp_sqr(tv2, w->tv3);
    fp_sqr(tv6, w->tv4);
    fp_mul(tv5, K.A, tv6);
    fp_add(tv2, tv2, tv5);
    fp_mul(N, tv2, w->tv3);                              /* tv3^3 + A tv3 tv4^2 */
    fp_mul(tv6, tv6, w->tv4);                            /* D = tv4^3 */
    fp_mul(tv5, K.B, tv6);
    fp_add(N, N, tv5);                                   /* N = tv3^3 + A tv3 tv4^2 + B tv4^3, g(x1) = N / D */
    fp_mul(s, N, tv6);
}

static void sswu_a(sswu_state *w, const pl_fp u)
{
    pl_fp s;
    sswu_a_pre(w, u, s);
    w->sq = fp_sqrt_or_z(w->r, s);                       /* r^2 = N D, or Z N D: r / D = sqrt(N/D) or sqrt(Z N/D) */
}

static void sswu_b(pl_pt *out, const sswu_state *w, const pl_fp inv4)
{
    pl_fp x, y, t;
    uint32_t up[8], yp[8];

    fp_sqr(t, inv4);
    fp_mul(t, t, inv4);                                  /* 1 / D */
    fp_mul(y, w->r, t);                                  /* y1 */
    if (w->sq) {
        fp_mul(x, w->tv3, inv4);
    } else {
        fp_mul(x, w->tv1, w->tv3);
        fp_mul(x, x, inv4);                              /* x2 = tv1 x1 */
        fp_mul(t, w->tv1, w->u);
        fp_mul(y, y, t);                                 /* y = Z u^3 y1 */
    }
    fp_to_plain(up, w->u);
    fp_to_plain(yp, y);
    if ((up[0] & 1) != (yp[0] & 1)) fp_neg(y, y);        /* sgn0(y) = sgn0(u) */
    iso_map(out, x, y);
}

/* expand_message_xmd with BLAKE2b-512 for 128 output bytes */
static void expand_xmd(uint8_t out[128], const uint8_t *msg, size_t mlen, const uint8_t *dst, size_t dlen)
{
    uint8_t b0[64], b1[64], tmp[64], dp[1], zeros[128], l[3] = {0x00, 0x80, 0x00};
    blake2b_ctx c;
    dp[0] = (uint8_t) dlen;
    memset(zeros, 0, sizeof zeros);
    blake2b_init(&c, 64, NULL, 0, NULL, NULL);
    blake2b_update(&c, zeros, 128);
    blake2b_update(&c, msg, mlen);
    blake2b_update(&c, l, 3);                       /* length 128 as two bytes, then the counter byte 0 */
    blake2b_update(&c, dst, dlen);
    blake2b_update(&c, dp, 1);
    blake2b_final(&c, b0);
    {
        uint8_t i = 1;
        blake2b_init(&c, 64, NULL, 0, NULL, NULL);
        blake2b_update(&c, b0, 64);
        blake2b_update(&c, &i, 1);
        blake2b_update(&c, dst, dlen);
        blake2b_update(&c, dp, 1);
        blake2b_final(&c, b1);
    }
    for (int i = 0; i < 64; i++) tmp[i] = b0[i] ^ b1[i];
    {
        uint8_t i = 2;
        blake2b_init(&c, 64, NULL, 0, NULL, NULL);
        blake2b_update(&c, tmp, 64);
        blake2b_update(&c, &i, 1);
        blake2b_update(&c, dst, dlen);
        blake2b_update(&c, dp, 1);
        blake2b_final(&c, out + 64);
    }
    memcpy(out, b1, 64);
}

/* 64 bytes big-endian -> field element (Montgomery) */
static void field_from_be64(pl_fp r, const uint8_t in[64])
{
    uint32_t w[16], plain[8];
    for (int i = 0; i < 16; i++) {
        const uint8_t *q = in + 60 - 4 * i;                 /* limb i, least significant first */
        w[i] = (uint32_t) q[3] | (uint32_t) q[2] << 8 | (uint32_t) q[1] << 16 | (uint32_t) q[0] << 24;
    }
    bn_mod_wide(plain, w, 16, P);
    fp_to_mont(r, plain);
}

/* n hashes with one domain and n messages of mlen bytes each, back to back; the field inversion of every map is shared by up to 16
 * hashes (32 maps) with Montgomery's trick: one inversion costs about 320 multiplications, a hash 1200 */
void pl_group_hash_batch(pl_pt *out, size_t n, const uint8_t *domain, size_t dlen, const uint8_t *msgs, size_t mlen)
{
    static const char SUFFIX[] = "-pallas_XMD:BLAKE2b_SSWU_RO_";
    uint8_t dst[96], u[128];
    size_t dn;

    init_consts();
    if (dlen > 60) dlen = 60;
    memcpy(dst, domain, dlen);
    dn = dlen;
    memcpy(dst + dn, SUFFIX, sizeof SUFFIX - 1);
    dn += sizeof SUFFIX - 1;
    while (n) {
        sswu_state ws[32];
        pl_pt q[32];
        pl_fp pre[32], inv, ik, u0, u1;
        size_t m = n < 16 ? n : 16;
        int cnt = (int) (2 * m);

        for (size_t h = 0; h < m; h++) {
            expand_xmd(u, msgs + h * mlen, mlen, dst, dn);
            field_from_be64(u0, u);
            field_from_be64(u1, u + 64);
            sswu_a(&ws[2 * h], u0);
            sswu_a(&ws[2 * h + 1], u1);
        }
        fp_set(pre[0], ws[0].tv4);
        for (int k = 1; k < cnt; k++) fp_mul(pre[k], pre[k - 1], ws[k].tv4);
        fp_inv(inv, pre[cnt - 1]);
        for (int k = cnt - 1; k >= 0; k--) {
            if (k) fp_mul(ik, inv, pre[k - 1]); else fp_set(ik, inv);
            fp_mul(inv, inv, ws[k].tv4);
            sswu_b(&q[k], &ws[k], ik);
        }
        for (size_t h = 0; h < m; h++) pl_add(&out[h], &q[2 * h], &q[2 * h + 1]);
        out += m;
        msgs += m * mlen;
        n -= m;
    }
}

void pl_group_hash(pl_pt *out, const uint8_t *domain, size_t dlen, const uint8_t *msg, size_t mlen)
{
    pl_group_hash_batch(out, 1, domain, dlen, msg, mlen);
}

static struct { uint8_t used, dlen, mlen; uint8_t d[32], m[32]; pl_pt p; } gh_cache[8];

void pl_group_hash_cached(pl_pt *out, const uint8_t *domain, size_t dlen, const uint8_t *msg, size_t mlen)
{
    int free_slot = -1;
    static const uint8_t EMPTY[1] = {0};
    if (!msg) msg = EMPTY;
    if (dlen <= 32 && mlen <= 32) {
        for (int i = 0; i < 8; i++) {
            if (!gh_cache[i].used) { if (free_slot < 0) free_slot = i; continue; }
            if (gh_cache[i].dlen == dlen && gh_cache[i].mlen == mlen && !memcmp(gh_cache[i].d, domain, dlen) && !memcmp(gh_cache[i].m, msg, mlen)) {
                *out = gh_cache[i].p;
                return;
            }
        }
    }
    pl_group_hash(out, domain, dlen, msg, mlen);
    if (free_slot >= 0 && dlen <= 32 && mlen <= 32) {
        gh_cache[free_slot].used = 1;
        gh_cache[free_slot].dlen = (uint8_t) dlen;
        gh_cache[free_slot].mlen = (uint8_t) mlen;
        memcpy(gh_cache[free_slot].d, domain, dlen);
        memcpy(gh_cache[free_slot].m, msg, mlen);
        gh_cache[free_slot].p = *out;
    }
}

/* ---- scalars ---- */

void pl_reduce_scalar(uint8_t out[32], const uint8_t in[64])
{
    uint32_t w[16], r[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t) in[4 * i] | (uint32_t) in[4 * i + 1] << 8 | (uint32_t) in[4 * i + 2] << 16 | (uint32_t) in[4 * i + 3] << 24;
    bn_mod_wide(r, w, 16, Q);
    bn_to_le(out, r);
}

void pl_reduce_base(uint8_t out[32], const uint8_t in[64])
{
    uint32_t w[16], r[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t) in[4 * i] | (uint32_t) in[4 * i + 1] << 8 | (uint32_t) in[4 * i + 2] << 16 | (uint32_t) in[4 * i + 3] << 24;
    bn_mod_wide(r, w, 16, P);
    bn_to_le(out, r);
}

void pl_scalar_from_base(uint8_t out[32], const uint8_t in[32])
{
    uint32_t x[8], t[8];
    bn_from_le(x, in);
    {
        uint32_t borrow = bn_sub(t, x, Q);
        bn_cmov(x, t, borrow - 1);        /* x >= q: x - q (p < 2q, so once is enough) */
    }
    bn_to_le(out, x);
}

/* ---- arithmetic modulo the group order q (inputs below q) ---- */

void pl_sc_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t x[8], y[8], z[8];
    bn_from_le(x, a); bn_from_le(y, b);
    bn_add_mod(z, x, y, Q);
    bn_to_le(out, z);
}

void pl_sc_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint32_t x[8], y[8], t[16], z[8];
    bn_from_le(x, a); bn_from_le(y, b);
    bn_mul_wide(t, x, y);
    bn_mod_wide(z, t, 16, Q);
    bn_to_le(out, z);
}

void pl_sc_neg(uint8_t out[32], const uint8_t a[32])
{
    uint32_t x[8], t[8];
    bn_from_le(x, a);
    bn_sub(t, Q, x);
    bn_cmov(t, x, bn_zero_mask(x));               /* -0 = 0 */
    bn_to_le(out, t);
}

/* ---- field element access (Poseidon) ---- */

void pl_fp_from_le(pl_fp r, const uint8_t in[32])
{
    uint32_t x[8], t[8], borrow;
    bn_from_le(x, in);
    borrow = bn_sub(t, x, P);
    bn_cmov(x, t, borrow - 1);                          /* below 2^256 < 4p: reduce a few times */
    borrow = bn_sub(t, x, P);
    bn_cmov(x, t, borrow - 1);
    borrow = bn_sub(t, x, P);
    bn_cmov(x, t, borrow - 1);
    fp_to_mont(r, x);
}

void pl_fp_to_le(uint8_t out[32], const pl_fp a)
{
    uint32_t x[8];
    fp_to_plain(x, a);
    bn_to_le(out, x);
}

void pl_fp_add(pl_fp r, const pl_fp a, const pl_fp b) { fp_add(r, a, b); }
void pl_fp_mul(pl_fp r, const pl_fp a, const pl_fp b) { fp_mul(r, a, b); }
void pl_fp_sqr(pl_fp r, const pl_fp a) { fp_sqr(r, a); }

/* ---- the table of the 1024 Sinsemilla points S_j = GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j)), built in small steps ----
 * One point costs about 800 field multiplications (83 ms on the PSX), the table 88 s: a console builds it a few milliseconds a frame while
 * the user is busy with the menus. The work is cut into pieces of a few multiplications: the square roots (the bulk) and the inversions
 * are exponentiations that go on a few squarings at a time. 16 points are made together, so one inversion serves the 32 maps (as in
 * pl_group_hash_batch) and one more turns the 16 points affine. A finished point is 64 bytes: x and y, 32 bytes little-endian each. */

#define ST_N 1024
static uint8_t st_tab[ST_N][64];
static uint8_t st_have[ST_N];                    /* 1: the point is in the table */
static int st_built;                             /* the number of points in the table */
static int st_next;                              /* the next group of 16 the builder looks at */

typedef struct {
    int stage, i, st, cnt, sq;
    pl_fp s, z, x, b, c, c0, t, r;
} st_sqrt;

/* a few steps of acc = base^e (e of `bits` bits, most significant first), *i the next bit; 1 when done */
static int pow_step(pl_fp acc, int *i, const pl_fp base, const uint32_t *e, int *bud)
{
    while (*bud > 0 && *i >= 0) {
        fp_sqr(acc, acc);
        if ((e[*i >> 5] >> (*i & 31)) & 1) { fp_mul(acc, acc, base); (*bud)--; }
        (*bud)--;
        (*i)--;
    }
    return *i < 0;
}

/* fp_sqrt_or_z as a state machine: 1 when done (q->r and q->sq hold the result) */
static int sqrt_step(st_sqrt *q, int *bud)
{
    pl_fp one;
    fp_one(one);
    while (*bud > 0) {
        switch (q->stage) {
        case 0:
            fp_one(q->z);
            q->i = 221;
            q->stage = 1;
            break;
        case 1:
            if (pow_step(q->z, &q->i, q->s, TM1D2, bud)) q->stage = 2;
            break;
        case 2:
            fp_mul(q->x, q->s, q->z);
            fp_mul(q->b, q->x, q->z);
            *bud -= 2;
            if (fp_is_zero(q->b)) { fp_zero(q->r); q->sq = 1; q->stage = 9; break; }
            fp_set(q->c0, q->b);
            q->cnt = 27;
            q->stage = 3;
            break;
        case 3:
            fp_sqr(q->c0, q->c0);
            (*bud)--;
            if (--q->cnt == 0) { fp_set(q->t, q->c0); q->cnt = 4; q->stage = 4; }
            break;
        case 4:
            fp_sqr(q->t, q->t);
            (*bud)--;
            if (--q->cnt == 0) {
                q->sq = fp_eq(q->t, one);
                if (!q->sq) {
                    fp_mul(q->x, q->x, K.zc);
                    fp_mul(q->b, q->b, K.zeta);
                    fp_mul(q->c0, q->c0, K.z27);
                    *bud -= 3;
                }
                q->st = 0;
                q->stage = 5;
            }
            break;
        case 5:
            if (q->st == 0) { fp_set(q->c, q->c0); q->cnt = 0; }
            else { fp_set(q->c, q->b); q->cnt = 27 - 4 * q->st; }
            q->stage = 6;
            break;
        case 6: {
            int d = -1;
            if (q->cnt > 0) { fp_sqr(q->c, q->c); q->cnt--; (*bud)--; break; }
            if (q->st < 7) { for (int i = 0; i < 16; i++) if (fp_eq(q->c, K.g16[i])) { d = i; break; } }
            else           { for (int i = 0; i < 8; i++)  if (fp_eq(q->c, K.g16[2 * i])) { d = i; break; } }
            if (d < 0) { fp_zero(q->r); q->sq = 0; q->stage = 9; break; }           /* cannot happen */
            if (d) {
                pl_fp t;
                fp_mul(q->x, q->x, K.wtab[q->st][d]);
                fp_sqr(t, K.wtab[q->st][d]);
                fp_mul(q->b, q->b, t);
                *bud -= 3;
            }
            if (++q->st == 8) { fp_set(q->r, q->x); q->stage = 9; } else q->stage = 5;
            break;
        }
        default:
            return 1;
        }
    }
    return q->stage == 9;
}

static struct {
    int phase, g0, m, sub, k, i;
    uint8_t dst[96];
    size_t dn;
    pl_fp u1f, inv, ik;
    st_sqrt sq;
    sswu_state ws[32];
    pl_fp pre[32];
    pl_pt q[32], pt[16];
} J;

void pl_stable_reset(void)
{
    memset(&J, 0, sizeof J);
    memset(st_have, 0, sizeof st_have);
    st_built = 0;
    st_next = 0;
}

int pl_stable_get(unsigned j, uint8_t xy[64])
{
    if (j >= ST_N || !st_have[j]) return -1;
    memcpy(xy, st_tab[j], 64);
    return 0;
}

int pl_stable_built(void) { return st_built; }

static void st_store(unsigned j, const uint8_t xy[64])
{
    memcpy(st_tab[j], xy, 64);
    if (!st_have[j]) { st_have[j] = 1; st_built++; }
}

/* points computed by someone else (a note commitment that did not find them in the table) go into the table: the affine form of all of them
 * with one inversion */
void pl_stable_add(const unsigned *j, const pl_pt *p, size_t n)
{
    pl_fp pre[16], inv, zi, x, y;
    if (n == 0 || n > 16) return;
    fp_set(pre[0], p[0].Z);
    for (size_t k = 1; k < n; k++) fp_mul(pre[k], pre[k - 1], p[k].Z);
    fp_inv(inv, pre[n - 1]);
    for (size_t k = n; k-- > 0;) {
        uint8_t xy[64];
        if (k) fp_mul(zi, inv, pre[k - 1]); else fp_set(zi, inv);
        fp_mul(inv, inv, p[k].Z);
        fp_mul(x, p[k].X, zi);
        fp_mul(y, p[k].Y, zi);
        pl_fp_to_le(xy, x);
        pl_fp_to_le(xy + 32, y);
        if (j[k] < ST_N) st_store(j[k], xy);
    }
}

/* about `ops` field multiplications of work; returns the number of points done (1024: the table is complete) */
int pl_stable_step(int ops)
{
    static const char SUFFIX[] = "-pallas_XMD:BLAKE2b_SSWU_RO_", DOM[] = "z.cash:SinsemillaS";
    int bud = ops;

    while (bud > 0 && st_next < ST_N / 16) {
        switch (J.phase) {
        case 0:                                                  /* a group of 16 points */
            init_consts();
            {   /* a group that is complete (its points came from note commitments) is skipped */
                int miss = 0;
                for (int k = 0; k < 16; k++) miss += !st_have[st_next * 16 + k];
                if (!miss) { st_next++; break; }
            }
            memcpy(J.dst, DOM, sizeof DOM - 1);
            J.dn = sizeof DOM - 1;
            memcpy(J.dst + J.dn, SUFFIX, sizeof SUFFIX - 1);
            J.dn += sizeof SUFFIX - 1;
            J.g0 = st_next * 16;
            J.m = 0;
            J.sub = 0;
            J.phase = 1;
            break;
        case 1:                                                  /* the 32 maps of phase A */
            if (J.sub == 0) {
                pl_fp u, s;
                if ((J.m & 1) == 0) {                            /* a new hash: its two field elements */
                    uint8_t msg[4], ub[128];
                    uint32_t v = (uint32_t) (J.g0 + (J.m >> 1));
                    msg[0] = (uint8_t) v; msg[1] = (uint8_t) (v >> 8); msg[2] = 0; msg[3] = 0;
                    expand_xmd(ub, msg, 4, J.dst, J.dn);
                    field_from_be64(u, ub);
                    field_from_be64(J.u1f, ub + 64);
                    bud -= 20;
                } else fp_set(u, J.u1f);
                sswu_a_pre(&J.ws[J.m], u, s);
                memset(&J.sq, 0, sizeof J.sq);
                fp_set(J.sq.s, s);
                J.sub = 1;
                bud -= 15;
            } else if (sqrt_step(&J.sq, &bud)) {
                fp_set(J.ws[J.m].r, J.sq.r);
                J.ws[J.m].sq = J.sq.sq;
                J.sub = 0;
                if (++J.m == 32) { J.phase = 2; J.sub = 0; }
            }
            break;
        case 2:                                                  /* one inversion for the 32 maps */
            if (J.sub == 0) {
                fp_set(J.pre[0], J.ws[0].tv4);
                for (int k = 1; k < 32; k++) fp_mul(J.pre[k], J.pre[k - 1], J.ws[k].tv4);
                fp_one(J.inv);
                J.i = 254;
                J.sub = 1;
                bud -= 31;
            } else if (pow_step(J.inv, &J.i, J.pre[31], PM2, &bud)) { J.phase = 3; J.k = 31; }
            break;
        case 3: {                                                /* phase B of every map, the pairs added */
            int k = J.k;
            if (k) fp_mul(J.ik, J.inv, J.pre[k - 1]); else fp_set(J.ik, J.inv);
            fp_mul(J.inv, J.inv, J.ws[k].tv4);
            sswu_b(&J.q[k], &J.ws[k], J.ik);
            if (!(k & 1)) pl_add(&J.pt[k >> 1], &J.q[k], &J.q[k + 1]);
            bud -= 40;
            if (--J.k < 0) { J.phase = 4; J.sub = 0; }
            break;
        }
        case 4:                                                  /* the 16 points affine: one more inversion */
            if (J.sub == 0) {
                fp_set(J.pre[0], J.pt[0].Z);
                for (int k = 1; k < 16; k++) fp_mul(J.pre[k], J.pre[k - 1], J.pt[k].Z);
                fp_one(J.inv);
                J.i = 254;
                J.sub = 1;
                bud -= 15;
            } else if (J.sub == 1) {
                if (pow_step(J.inv, &J.i, J.pre[15], PM2, &bud)) { J.k = 15; J.sub = 2; }
            } else {
                int k = J.k;
                pl_fp zi, x, y;
                if (k) fp_mul(zi, J.inv, J.pre[k - 1]); else fp_set(zi, J.inv);
                fp_mul(J.inv, J.inv, J.pt[k].Z);
                fp_mul(x, J.pt[k].X, zi);
                fp_mul(y, J.pt[k].Y, zi);
                {
                    uint8_t xy[64];
                    pl_fp_to_le(xy, x);
                    pl_fp_to_le(xy + 32, y);
                    st_store((unsigned) (J.g0 + k), xy);
                }
                bud -= 6;
                if (--J.k < 0) { st_next++; J.phase = 0; }
            }
            break;
        }
    }
    return st_built;
}

/* the affine coordinates of a point (plain, 32 bytes little-endian each): one inversion; the identity gives zeros */
void pl_to_affine_le(uint8_t x[32], uint8_t y[32], const pl_pt *p)
{
    pl_fp ax, ay;
    affine(ax, ay, p);
    pl_fp_to_le(x, ax);
    pl_fp_to_le(y, ay);
}
