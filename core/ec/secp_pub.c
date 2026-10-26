#include "ec/secp_pub.h"
#include <string.h>
#include "ec/secp256k1.h"
#include "ec/bn.h"
#include "ec/ec_consts.h"
#include "hash/sha512.h"
#include "util.h"

typedef uint32_t fe[8];

static const uint32_t FP[8] = SECP_P;

static void sqrn(fe r, const fe a, int n)
{
    secp_fe_sqr(r, a);
    for (int i = 1; i < n; i++) secp_fe_sqr(r, r);
}

/* a^((p+1)/4): a square root when a is a square (p = 3 mod 4); the addition chain of libsecp256k1 */
static void fe_sqrt(fe r, const fe a)
{
    fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;

    secp_fe_sqr(x2, a);       secp_fe_mul(x2, x2, a);
    secp_fe_sqr(x3, x2);      secp_fe_mul(x3, x3, a);
    sqrn(x6, x3, 3);          secp_fe_mul(x6, x6, x3);
    sqrn(x9, x6, 3);          secp_fe_mul(x9, x9, x3);
    sqrn(x11, x9, 2);         secp_fe_mul(x11, x11, x2);
    sqrn(x22, x11, 11);       secp_fe_mul(x22, x22, x11);
    sqrn(x44, x22, 22);       secp_fe_mul(x44, x44, x22);
    sqrn(x88, x44, 44);       secp_fe_mul(x88, x88, x44);
    sqrn(x176, x88, 88);      secp_fe_mul(x176, x176, x88);
    sqrn(x220, x176, 44);     secp_fe_mul(x220, x220, x44);
    sqrn(x223, x220, 3);      secp_fe_mul(x223, x223, x3);
    sqrn(t, x223, 23);        secp_fe_mul(t, t, x22);
    sqrn(t, t, 6);            secp_fe_mul(t, t, x2);
    sqrn(r, t, 2);
}

static int fe_eq(const fe a, const fe b)
{
    fe x, y;
    memcpy(x, a, 32); memcpy(y, b, 32);
    secp_fe_norm(x); secp_fe_norm(y);
    return !memcmp(x, y, 32);
}

/* x, y of a compressed point (y reduced); -1 if it is not on the curve */
static int lift(fe x, fe y, const uint8_t c[33])
{
    fe rhs, s, seven = {7, 0, 0, 0, 0, 0, 0, 0};

    if (c[0] != 2 && c[0] != 3) return -1;
    bn_from_be(x, c + 1);
    if (!bn_lt(x, FP)) return -1;
    secp_fe_sqr(rhs, x);
    secp_fe_mul(rhs, rhs, x);
    secp_fe_add(rhs, rhs, seven);
    fe_sqrt(y, rhs);
    secp_fe_sqr(s, y);
    if (!fe_eq(s, rhs)) return -1;
    secp_fe_norm(y);
    if ((y[0] & 1) != (uint32_t) (c[0] & 1)) { fe zero = {0}; secp_fe_sub(y, zero, y); secp_fe_norm(y); }
    return 0;
}

int secp256k1_pubkey_add(uint8_t r[33], const uint8_t a[33], const uint8_t b[33])
{
    fe x1, y1, x2, y2, dx, inv, l, x3, y3, t;
    uint8_t xb[32];

    if (lift(x1, y1, a) || lift(x2, y2, b)) return -1;
    secp_fe_sub(dx, x2, x1);
    if (fe_eq(dx, (const uint32_t[8]) {0})) return -1;
    secp_fe_inv(inv, dx);
    secp_fe_sub(t, y2, y1);
    secp_fe_mul(l, t, inv);
    secp_fe_sqr(x3, l);
    secp_fe_sub(x3, x3, x1);
    secp_fe_sub(x3, x3, x2);
    secp_fe_sub(t, x1, x3);
    secp_fe_mul(y3, l, t);
    secp_fe_sub(y3, y3, y1);
    secp_fe_norm(x3); secp_fe_norm(y3);
    bn_to_be(xb, x3);
    r[0] = (uint8_t) (2 | (y3[0] & 1));
    memcpy(r + 1, xb, 32);
    return 0;
}

int secp256k1_ckd_pub(uint8_t child_pub[33], uint8_t child_cc[32], const uint8_t pub[33], const uint8_t cc[32], uint32_t index)
{
    uint8_t data[37], i[64], p[33];
    int rc;

    if (index & 0x80000000u) return -1;
    memcpy(data, pub, 33);
    data[33] = (uint8_t) (index >> 24); data[34] = (uint8_t) (index >> 16); data[35] = (uint8_t) (index >> 8); data[36] = (uint8_t) index;
    hmac_sha512(cc, 32, data, sizeof data, i);
    if (secp256k1_pubkey_create(p, i)) return -1;                       /* I_L is 0 or not below n */
    rc = secp256k1_pubkey_add(child_pub, p, pub);
    if (!rc) memcpy(child_cc, i + 32, 32);
    secure_zero(i, sizeof i);
    return rc;
}

/* ---- ECDH for the Nostr encryption (NIP-04, NIP-44): the x coordinate of k * P, P the point of an x only public key (the even y: the x of k * P does not depend on it). The key is
 * secret, so the loop is constant time: every bit doubles and adds, and a mask decides whether the sum is kept. The complete formulas of secp256k1.c (Renes-Costello-Batina 2015,
 * Algorithms 8 and 9 for a = 0, b3 = 21) on the field operations of that file. ---- */

typedef struct { fe X, Y, Z; } ept;

static void ept_dbl(ept *r, const ept *p)
{
    fe t0, t1, t2, X3, Y3, Z3;
    secp_fe_sqr(t0, p->Y);        secp_fe_add(Z3, t0, t0);      secp_fe_add(Z3, Z3, Z3);
    secp_fe_add(Z3, Z3, Z3);      secp_fe_mul(t1, p->Y, p->Z);  secp_fe_sqr(t2, p->Z);
    secp_fe_mul_small(t2, t2, 21);
    secp_fe_mul(X3, t2, Z3);      secp_fe_add(Y3, t0, t2);      secp_fe_mul(Z3, t1, Z3);
    secp_fe_add(t1, t2, t2);      secp_fe_add(t2, t1, t2);      secp_fe_sub(t0, t0, t2);
    secp_fe_mul(Y3, t0, Y3);      secp_fe_add(Y3, X3, Y3);      secp_fe_mul(t1, p->X, p->Y);
    secp_fe_mul(X3, t0, t1);      secp_fe_add(X3, X3, X3);
    memcpy(r->X, X3, 32); memcpy(r->Y, Y3, 32); memcpy(r->Z, Z3, 32);
}

/* r = p + (qx, qy), the second point affine */
static void ept_add_mixed(ept *r, const ept *p, const fe qx, const fe qy)
{
    fe t0, t1, t2, t3, t4, X3, Y3, Z3;
    secp_fe_mul(t0, p->X, qx);    secp_fe_mul(t1, p->Y, qy);
    secp_fe_add(t3, qx, qy);      secp_fe_add(t4, p->X, p->Y);  secp_fe_mul(t3, t3, t4);
    secp_fe_add(t4, t0, t1);      secp_fe_sub(t3, t3, t4);
    secp_fe_mul(t4, qy, p->Z);    secp_fe_add(t4, t4, p->Y);
    secp_fe_mul(Y3, qx, p->Z);    secp_fe_add(Y3, Y3, p->X);
    secp_fe_add(X3, t0, t0);      secp_fe_add(t0, X3, t0);
    secp_fe_mul_small(t2, p->Z, 21);
    secp_fe_add(Z3, t1, t2);      secp_fe_sub(t1, t1, t2);
    secp_fe_mul_small(Y3, Y3, 21);
    secp_fe_mul(X3, t4, Y3);      secp_fe_mul(t2, t3, t1);      secp_fe_sub(X3, t2, X3);
    secp_fe_mul(Y3, Y3, t0);      secp_fe_mul(t1, t1, Z3);      secp_fe_add(Y3, t1, Y3);
    secp_fe_mul(t0, t0, t3);      secp_fe_mul(Z3, Z3, t4);      secp_fe_add(Z3, Z3, t0);
    memcpy(r->X, X3, 32); memcpy(r->Y, Y3, 32); memcpy(r->Z, Z3, 32);
}

static void ept_cmov(ept *r, const ept *p, uint32_t m)
{
    for (int i = 0; i < 8; i++) {
        r->X[i] ^= (r->X[i] ^ p->X[i]) & m;
        r->Y[i] ^= (r->Y[i] ^ p->Y[i]) & m;
        r->Z[i] ^= (r->Z[i] ^ p->Z[i]) & m;
    }
}

int secp256k1_ecdh_x(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t comp[33];
    uint32_t k[8];
    fe px, py, z;
    ept acc, t;

    if (!secp256k1_privkey_verify(priv)) return -1;
    comp[0] = 2;
    memcpy(comp + 1, pub, 32);
    if (lift(px, py, comp)) return -1;
    bn_from_be(k, priv);
    memset(&acc, 0, sizeof acc);
    acc.Y[0] = 1;                                                           /* the point at infinity (0 : 1 : 0) */
    for (int i = 255; i >= 0; i--) {
        ept_dbl(&acc, &acc);
        ept_add_mixed(&t, &acc, px, py);
        ept_cmov(&acc, &t, 0u - ((k[i >> 5] >> (i & 31)) & 1));
    }
    secure_zero(k, sizeof k);
    secp_fe_norm(acc.Z);
    if (fe_eq(acc.Z, (const uint32_t[8]) {0})) return -1;
    secp_fe_inv(z, acc.Z);
    secp_fe_mul(acc.X, acc.X, z);
    secp_fe_norm(acc.X);
    bn_to_be(out, acc.X);
    secure_zero(&acc, sizeof acc);
    return 0;
}
