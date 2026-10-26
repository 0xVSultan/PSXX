#include "ec/secp_van.h"
#include <string.h>
#include "ec/secp256k1.h"
#include "ec/bn.h"
#include "ec/ec_consts.h"

typedef uint32_t fe[8];
typedef struct { fe X, Y, Z; } pt;

static const uint32_t GX[8] = SECP_GX;
static const uint32_t GY[8] = SECP_GY;
static const uint32_t FN[8] = SECP_N;

#define fe_mul secp_fe_mul
#define fe_sqr secp_fe_sqr
#define fe_add secp_fe_add
#define fe_sub secp_fe_sub
#define fe_mul_small secp_fe_mul_small
#define fe_inv secp_fe_inv
#define fe_normalize secp_fe_norm

static void fe_set(fe r, const fe a) { memcpy(r, a, 32); }
static void fe_zero(fe r) { memset(r, 0, 32); }
static void fe_one(fe r) { memset(r, 0, 32); r[0] = 1; }

/* r = p + (qx, qy) with the second point affine: RCB 2015, Algorithm 8, complete (the same as pt_add_mixed of secp256k1.c) */
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

int secp256k1_van_init(van_ctx *c, const uint8_t s[32])
{
    pt acc;
    fe inv;
    uint8_t x[32], y[32];
    uint32_t k[8], d[8], lim[8] = {VAN_N, 0, 0, 0, 0, 0, 0, 0};

    bn_from_be(k, s);
    bn_sub(d, FN, k);                                  /* n - s */
    if (!bn_lt(lim, k) || !bn_lt(lim, d) || bn_zero_mask(k)) return -1;       /* s <= VAN_N or n - s <= VAN_N, or 0 */
    if (secp256k1_pubkey_xy(x, y, s)) return -1;
    bn_from_be(c->x0, x); bn_from_be(c->y0, y);
    memcpy(c->s, s, 32);
    c->base = 0;
    c->pphase = c->pi = 0;
    memcpy(acc.X, GX, 32); memcpy(acc.Y, GY, 32); fe_one(acc.Z);
    for (int i = 0; i < VAN_N; i++) {                  /* i*G projective: X, Y, Z in tx, ty and dinv (the arrays are free until the first prepare) */
        fe_set(c->tx[i], acc.X); fe_set(c->ty[i], acc.Y); fe_set(c->dinv[i], acc.Z);
        pt_add_mixed(&acc, &acc, GX, GY);
    }
    fe_set(c->pre[0], c->dinv[0]);
    for (int i = 1; i < VAN_N; i++) fe_mul(c->pre[i], c->pre[i - 1], c->dinv[i]);
    fe_inv(inv, c->pre[VAN_N - 1]);
    for (int i = VAN_N - 1; i >= 0; i--) {
        fe zi;
        if (i) fe_mul(zi, inv, c->pre[i - 1]); else fe_set(zi, inv);
        fe_mul(inv, inv, c->dinv[i]);
        fe_mul(c->tx[i], c->tx[i], zi); fe_mul(c->ty[i], c->ty[i], zi);
        fe_normalize(c->tx[i]); fe_normalize(c->ty[i]);
    }
    {   /* D = 2 * VAN_N * G: (VAN_N G) + (VAN_N G) with the complete formula, then one more inversion for the affine point */
        pt d;
        fe zi;
        fe_set(d.X, c->tx[VAN_N - 1]); fe_set(d.Y, c->ty[VAN_N - 1]); fe_one(d.Z);
        pt_add_mixed(&d, &d, c->tx[VAN_N - 1], c->ty[VAN_N - 1]);
        fe_inv(zi, d.Z);
        fe_mul(c->dx, d.X, zi); fe_mul(c->dy, d.Y, zi);
        fe_normalize(c->dx); fe_normalize(c->dy);
    }
    return 0;
}

int secp256k1_van_prepare_step(van_ctx *c, int n)
{
    fe dx;

    if (c->pphase == 0) {                                  /* the running products of the differences */
        for (; n > 0 && c->pi < VAN_N; n--, c->pi++) {
            fe_sub(dx, c->tx[c->pi], c->x0);
            if (c->pi) fe_mul(c->pre[c->pi], c->pre[c->pi - 1], dx); else fe_set(c->pre[0], dx);
        }
        if (c->pi == VAN_N) c->pphase = 1;
        return 0;
    }
    if (c->pphase == 1) {                                  /* one inversion serves all */
        fe_inv(c->pinv, c->pre[VAN_N - 1]);
        c->pi = VAN_N - 1;
        c->pphase = 2;
        return 0;
    }
    for (; n > 0 && c->pi >= 0; n--, c->pi--) {            /* and back: the inverse of every difference */
        fe_sub(dx, c->tx[c->pi], c->x0);
        if (c->pi) fe_mul(c->dinv[c->pi], c->pinv, c->pre[c->pi - 1]); else fe_set(c->dinv[0], c->pinv);
        fe_mul(c->pinv, c->pinv, dx);
    }
    if (c->pi < 0) { c->pphase = 0; c->pi = 0; return 1; }
    return 0;
}

void secp256k1_van_prepare(van_ctx *c)
{
    while (!secp256k1_van_prepare_step(c, VAN_N)) {}
}

void secp256k1_van_point(const van_ctx *c, int i, int neg, uint8_t x[32], uint8_t *y)
{
    fe ty, l, x3, t;
    if (neg) { fe zero; fe_zero(zero); fe_sub(ty, zero, c->ty[i]); } else fe_set(ty, c->ty[i]);
    fe_sub(t, ty, c->y0);
    fe_mul(l, t, c->dinv[i]);                         /* lambda */
    fe_sqr(x3, l);
    fe_sub(x3, x3, c->x0);
    fe_sub(x3, x3, c->tx[i]);
    fe_normalize(x3);
    bn_to_be(x, x3);
    if (y) {
        fe y3;
        fe_sub(t, c->x0, x3);
        fe_mul(y3, l, t);
        fe_sub(y3, y3, c->y0);
        fe_normalize(y3);
        bn_to_be(y, y3);
    }
}

void secp256k1_van_advance(van_ctx *c)
{
    fe dx, inv, l, x3, y3, t;
    fe_sub(dx, c->dx, c->x0);
    fe_inv(inv, dx);
    fe_sub(t, c->dy, c->y0);
    fe_mul(l, t, inv);
    fe_sqr(x3, l);
    fe_sub(x3, x3, c->x0);
    fe_sub(x3, x3, c->dx);
    fe_sub(t, c->x0, x3);
    fe_mul(y3, l, t);
    fe_sub(y3, y3, c->y0);
    fe_normalize(x3); fe_normalize(y3);
    fe_set(c->x0, x3); fe_set(c->y0, y3);
    c->base += 2 * VAN_N;
}

void secp256k1_van_key(const van_ctx *c, int i, int neg, uint8_t key[32])
{
    uint32_t k[8], o[8] = {0}, t[8];
    o[0] = (uint32_t) c->base; o[1] = (uint32_t) (c->base >> 32);
    bn_from_be(k, c->s);
    bn_add_mod(k, k, o, FN);                             /* s + base */
    memset(o, 0, 32);
    o[0] = (uint32_t) i + 1;
    if (neg) { bn_sub(t, FN, o); bn_add_mod(k, k, t, FN); } else bn_add_mod(k, k, o, FN);
    bn_to_be(key, k);
}
