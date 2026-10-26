#include "sign/redpallas.h"
#include <string.h>
#include "coin/orchard.h"
#include "ec/pallas.h"
#include "hash/blake2b.h"
#include "util.h"

static void spend_auth_g(pl_pt *g)
{
    static const char DOM[] = "z.cash:Orchard";
    pl_group_hash_cached(g, (const uint8_t *) DOM, sizeof DOM - 1, (const uint8_t *) "G", 1);
}

int orchard_ask(uint8_t ask[32], const uint8_t sk[32])
{
    uint8_t t = 0x06, e[64], enc[32], z = 0;
    pl_pt g, ak;

    orchard_prf_expand(e, sk, 32, &t, 1);
    pl_reduce_scalar(ask, e);
    secure_zero(e, sizeof e);
    for (int i = 0; i < 32; i++) z |= ask[i];
    if (!z) return -1;
    spend_auth_g(&g);
    pl_mul(&ak, &g, ask);
    pl_encode(enc, &ak);
    if (enc[31] & 0x80) pl_sc_neg(ask, ask);
    return 0;
}

void redpallas_randomize(uint8_t rsk[32], uint8_t rk[32], const uint8_t ask[32], const uint8_t alpha[32])
{
    pl_pt g, p;
    pl_sc_add(rsk, ask, alpha);
    spend_auth_g(&g);
    pl_mul(&p, &g, rsk);
    pl_encode(rk, &p);
}

/* H*(x) = ToScalar(BLAKE2b-512("Zcash_RedPallasH", x)) of three pieces */
static void h_star(uint8_t out[32], const uint8_t *a, size_t al, const uint8_t *b, size_t bl, const uint8_t *c, size_t cl)
{
    blake2b_ctx x;
    uint8_t h[64];
    blake2b_init(&x, 64, NULL, 0, NULL, (const uint8_t *) "Zcash_RedPallasH");
    blake2b_update(&x, a, al);
    blake2b_update(&x, b, bl);
    blake2b_update(&x, c, cl);
    blake2b_final(&x, h);
    pl_reduce_scalar(out, h);
    secure_zero(h, sizeof h);
}

void redpallas_sign(uint8_t sig[64], const uint8_t rsk[32], const uint8_t msg[32])
{
    pl_pt g, p;
    uint8_t vk[32], T[80], h[64], r[32], R[32], c[32], buf[1 + 32 + 32];
    blake2b_ctx x;

    spend_auth_g(&g);
    pl_mul(&p, &g, rsk);
    pl_encode(vk, &p);
    for (int k = 0; k < 2; k++) {                                   /* T: 80 bytes from the key and the message */
        blake2b_init(&x, 64, NULL, 0, NULL, (const uint8_t *) "PSXX_RedPallasT_");
        buf[0] = (uint8_t) k;
        memcpy(buf + 1, rsk, 32);
        memcpy(buf + 33, msg, 32);
        blake2b_update(&x, buf, sizeof buf);
        blake2b_final(&x, h);
        memcpy(T + 64 * k, h, k ? 16 : 64);
    }
    h_star(r, T, 80, vk, 32, msg, 32);
    pl_mul(&p, &g, r);
    pl_encode(R, &p);
    h_star(c, R, 32, vk, 32, msg, 32);
    pl_sc_mul(c, c, rsk);
    pl_sc_add(sig + 32, r, c);
    memcpy(sig, R, 32);
    secure_zero(r, sizeof r); secure_zero(T, sizeof T); secure_zero(h, sizeof h); secure_zero(buf, sizeof buf); secure_zero(c, sizeof c);
}

int redpallas_verify(const uint8_t sig[64], const uint8_t rk[32], const uint8_t msg[32])
{
    pl_pt g, rp, vkp, l, r;
    uint8_t c[32], e1[32], e2[32];

    if (pl_decode(&rp, sig) || pl_decode(&vkp, rk)) return -1;
    h_star(c, sig, 32, rk, 32, msg, 32);
    spend_auth_g(&g);
    pl_mul(&l, &g, sig + 32);                                       /* [S] G */
    pl_mul(&r, &vkp, c);
    pl_add(&r, &r, &rp);                                            /* R + [c] vk */
    pl_encode(e1, &l);
    pl_encode(e2, &r);
    return memcmp(e1, e2, 32) ? -1 : 0;
}
