/* Ed25519 signatures (RFC 8032) on top of the group and scalar helpers of ed25519.c. */
#include "ec/ed25519.h"
#include "hash/sha512.h"
#include "util.h"

void ed25519_sign_scalar(uint8_t sig[64], const uint8_t a[32], const uint8_t prefix[32], const uint8_t pub[32], const uint8_t *msg, size_t len)
{
    sha512_ctx c;
    uint8_t h[64], r[32], k[32], ka[32];

    sha512_init(&c);                                   /* r = H(prefix || M) mod L, R = r B */
    sha512_update(&c, prefix, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, h);
    ed25519_sc_reduce64(r, h);
    ed25519_scalarmult_base(sig, r);
    sha512_init(&c);                                   /* k = H(R || A || M) mod L, S = r + k a */
    sha512_update(&c, sig, 32);
    sha512_update(&c, pub, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, h);
    ed25519_sc_reduce64(k, h);
    ed25519_sc_mul(ka, k, a);
    ed25519_sc_add(sig + 32, r, ka);
    secure_zero(h, sizeof h); secure_zero(r, sizeof r); secure_zero(k, sizeof k); secure_zero(ka, sizeof ka);
}

void ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *msg, size_t len)
{
    uint8_t h[64], pub[32];

    sha512(seed, 32, h);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    ed25519_scalarmult_base(pub, h);
    ed25519_sign_scalar(sig, h, h + 32, pub, msg, len);
    secure_zero(h, sizeof h);
}
