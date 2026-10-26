/* secp256k1 signatures: ECDSA (RFC 6979 nonce, low S), BIP340 Schnorr and the BIP341 key path tweak.
 * Arithmetic modulo the group order n = 2^256 - c: products are folded with c (129 bits) instead of divided. */
#include "ec/secp256k1.h"
#include "ec/bn.h"
#include "hash/sha256.h"
#include <string.h>

static const uint32_t N[8] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
static const uint32_t HALF_N[8] = {0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF};
static const uint32_t NC[8] = {0x2FC9BEBF, 0x402DA173, 0x50B75FC4, 0x45512319, 1, 0, 0, 0};     /* 2^256 - n */

/* the unrolled products are big: one copy of each, shared by every caller */
static void __attribute__((noinline)) mulw(uint32_t t[16], const uint32_t a[8], const uint32_t b[8]) { bn_mul_wide(t, a, b); }
static void __attribute__((noinline)) sqrw(uint32_t t[16], const uint32_t a[8]) { bn_sqr_wide(t, a); }

/* r = r - n if r >= n (constant time) */
static void sc_final(uint32_t r[8])
{
    uint32_t t[8], borrow = bn_sub(t, r, N);
    bn_cmov(r, t, borrow - 1);
}

/* r = t[0..15] mod n: 2^256 = c (mod n), so lo + hi * c, three times */
static void sc_reduce(uint32_t r[8], const uint32_t t[16])
{
    uint32_t acc[17], p[16];
    uint64_t c = 0;

    memcpy(acc, t, 32);
    memset(acc + 8, 0, 36);
    mulw(p, t + 8, NC);                         /* hi * c < 2^385 */
    for (int i = 0; i < 16; i++) { c += (uint64_t) acc[i] + p[i]; acc[i] = (uint32_t) c; c >>= 32; }
    acc[16] = (uint32_t) c;
    mulw(p, acc + 8, NC);                       /* the new hi < 2^130: hi * c < 2^259 */
    memset(acc + 8, 0, 36);
    c = 0;
    for (int i = 0; i < 16; i++) { c += (uint64_t) acc[i] + p[i]; acc[i] = (uint32_t) c; c >>= 32; }
    /* now acc < 2^260: one more small fold of the bits above 255 (acc[8] < 16) */
    {
        uint32_t h = acc[8];
        uint64_t k = 0;
        for (int i = 0; i < 8; i++) { k += (uint64_t) h * NC[i] + acc[i]; acc[i] = (uint32_t) k; k >>= 32; }
        if (k) {                                       /* wrapped past 2^256: add c once more (cannot wrap again) */
            uint64_t m = 0;
            for (int i = 0; i < 8; i++) { m += (uint64_t) acc[i] + NC[i]; acc[i] = (uint32_t) m; m >>= 32; }
        }
    }
    memcpy(r, acc, 32);
    sc_final(r);
    secure_zero(acc, sizeof acc);
    secure_zero(p, sizeof p);
}

static void sc_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8])
{
    uint32_t t[16];
    mulw(t, a, b);
    sc_reduce(r, t);
    secure_zero(t, sizeof t);
}

static void sc_sqr(uint32_t r[8], const uint32_t a[8])
{
    uint32_t t[16];
    sqrw(t, a);
    sc_reduce(r, t);
    secure_zero(t, sizeof t);
}

/* r = a^(n-2), a in 1 .. n-1: a four bit window over the public exponent */
static void sc_inv(uint32_t r[8], const uint32_t a[8])
{
    uint32_t tab[16][8], res[8];
    uint32_t e[8];
    static const uint32_t TWO[8] = {2, 0, 0, 0, 0, 0, 0, 0};

    bn_sub(e, N, TWO);
    memset(tab[0], 0, 32); tab[0][0] = 1;
    memcpy(tab[1], a, 32);
    for (int i = 2; i < 16; i++) sc_mul(tab[i], tab[i - 1], a);
    memcpy(res, tab[15], 32);                          /* the top nibble of n - 2 is 0xF */
    for (int w = 62; w >= 0; w--) {
        uint32_t d = (e[w >> 3] >> ((w & 7) * 4)) & 15;
        for (int k = 0; k < 4; k++) sc_sqr(res, res);
        if (d) sc_mul(res, res, tab[d]);
    }
    memcpy(r, res, 32);
    secure_zero(tab, sizeof tab);
    secure_zero(res, sizeof res);
}

/* 32 bytes big endian -> a value reduced once mod n (any 256 bit value is < 2n) */
static void sc_from_be(uint32_t r[8], const uint8_t b[32])
{
    bn_from_be(r, b);
    sc_final(r);
}

/* ---- RFC 6979 nonce (HMAC-SHA256), x the private key, h1 the 32 byte hash ---- */
static int rfc6979(uint32_t k[8], const uint8_t x[32], const uint8_t h1[32], const uint8_t *extra)
{
    uint8_t K[32], V[32], buf[32 + 1 + 32 + 32 + 32], h1o[32];
    uint32_t t[8];
    size_t n;

    sc_from_be(t, h1);
    bn_to_be(h1o, t);
    memset(V, 1, 32);
    memset(K, 0, 32);
    for (int round = 0; round < 2; round++) {
        memcpy(buf, V, 32);
        buf[32] = (uint8_t) round;
        memcpy(buf + 33, x, 32);
        memcpy(buf + 65, h1o, 32);
        n = 97;
        if (extra) { memcpy(buf + n, extra, 32); n += 32; }
        hmac_sha256(K, 32, buf, n, K);
        hmac_sha256(K, 32, V, 32, V);
    }
    for (int tries = 0; tries < 64; tries++) {
        hmac_sha256(K, 32, V, 32, V);
        bn_from_be(k, V);
        if (!bn_zero_mask(k) && bn_lt(k, N)) {
            secure_zero(K, sizeof K); secure_zero(V, sizeof V); secure_zero(buf, sizeof buf);
            return 0;
        }
        memcpy(buf, V, 32);
        buf[32] = 0;
        hmac_sha256(K, 32, buf, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }
    return -1;
}

static void sc_neg(uint32_t r[8], const uint32_t a[8])
{
    uint32_t t[8], z = bn_zero_mask(a);
    bn_sub(t, N, a);
    for (int i = 0; i < 8; i++) r[i] = t[i] & ~z;      /* -0 = 0 */
}

int secp256k1_ecdsa_sign(uint8_t sig[64], int *recid, const uint8_t priv[32], const uint8_t hash[32])
{
    uint32_t d[8], k[8], z[8], r[8], s[8], ki[8];
    uint8_t x[32], y[32], kb[32];
    int rec;

    if (!secp256k1_privkey_verify(priv)) return -1;
    bn_from_be(d, priv);
    sc_from_be(z, hash);
    if (rfc6979(k, priv, hash, NULL)) return -1;
    bn_to_be(kb, k);
    if (secp256k1_pubkey_xy(x, y, kb)) return -1;
    bn_from_be(r, x);
    rec = (y[31] & 1) | (bn_lt(r, N) ? 0 : 2);
    sc_final(r);
    if (bn_zero_mask(r)) return -1;
    sc_inv(ki, k);
    sc_mul(s, r, d);                                   /* s = k^-1 (z + r d) */
    bn_add_mod(s, s, z, N);
    sc_mul(s, ki, s);
    if (bn_zero_mask(s)) return -1;
    {                                                  /* low S: s > n/2 -> n - s, which flips the parity of R */
        uint32_t high = bn_lt(HALF_N, s), ns[8];
        sc_neg(ns, s);
        bn_cmov(s, ns, 0u - high);
        rec ^= (int) high;
    }
    bn_to_be(sig, r);
    bn_to_be(sig + 32, s);
    if (recid) *recid = rec;
    secure_zero(d, sizeof d); secure_zero(k, sizeof k); secure_zero(ki, sizeof ki); secure_zero(kb, sizeof kb);
    return 0;
}

int secp256k1_sig_to_der(uint8_t *der, const uint8_t sig[64])
{
    uint8_t *p = der + 2;
    for (int part = 0; part < 2; part++) {
        const uint8_t *v = sig + 32 * part;
        int skip = 0, len;
        while (skip < 31 && v[skip] == 0) skip++;
        len = 32 - skip;
        *p++ = 0x02;
        *p++ = (uint8_t) (len + (v[skip] & 0x80 ? 1 : 0));
        if (v[skip] & 0x80) *p++ = 0;
        memcpy(p, v + skip, (size_t) len);
        p += len;
    }
    der[0] = 0x30;
    der[1] = (uint8_t) (p - der - 2);
    return (int) (p - der);
}

/* ---- BIP340 ---- */

int secp256k1_xonly_pubkey(uint8_t x[32], int *odd, const uint8_t priv[32])
{
    uint8_t y[32];
    if (secp256k1_pubkey_xy(x, y, priv)) return -1;
    if (odd) *odd = y[31] & 1;
    return 0;
}

int secp256k1_schnorr_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t msg[32], const uint8_t *aux)
{
    uint8_t px[32], py[32], rx[32], ry[32], t[32], rnd[32], eb[32], kb[32], zero[32] = {0};
    uint32_t d[8], k[8], e[8], s[8];
    sha256_ctx c;

    if (secp256k1_pubkey_xy(px, py, priv)) return -1;
    bn_from_be(d, priv);
    if (py[31] & 1) sc_neg(d, d);
    sha256_tagged_init(&c, "BIP0340/aux");
    sha256_update(&c, aux ? aux : zero, 32);
    sha256_final(&c, t);
    bn_to_be(kb, d);
    for (int i = 0; i < 32; i++) t[i] ^= kb[i];
    sha256_tagged_init(&c, "BIP0340/nonce");
    sha256_update(&c, t, 32); sha256_update(&c, px, 32); sha256_update(&c, msg, 32);
    sha256_final(&c, rnd);
    sc_from_be(k, rnd);
    if (bn_zero_mask(k)) return -1;
    bn_to_be(kb, k);
    if (secp256k1_pubkey_xy(rx, ry, kb)) return -1;
    if (ry[31] & 1) sc_neg(k, k);
    sha256_tagged_init(&c, "BIP0340/challenge");
    sha256_update(&c, rx, 32); sha256_update(&c, px, 32); sha256_update(&c, msg, 32);
    sha256_final(&c, eb);
    sc_from_be(e, eb);
    sc_mul(s, e, d);
    bn_add_mod(s, s, k, N);
    memcpy(sig, rx, 32);
    bn_to_be(sig + 32, s);
    secure_zero(d, sizeof d); secure_zero(k, sizeof k); secure_zero(kb, sizeof kb); secure_zero(t, sizeof t); secure_zero(rnd, sizeof rnd);
    return 0;
}

int secp256k1_taproot_tweak_seckey(uint8_t out[32], const uint8_t priv[32], const uint8_t *merkle, size_t merkle_len)
{
    uint8_t px[32], py[32], h[32];
    uint32_t d[8], t[8], r[8];
    sha256_ctx c;

    if (secp256k1_pubkey_xy(px, py, priv)) return -1;
    bn_from_be(d, priv);
    if (py[31] & 1) sc_neg(d, d);
    sha256_tagged_init(&c, "TapTweak");
    sha256_update(&c, px, 32);
    if (merkle_len) sha256_update(&c, merkle, merkle_len);
    sha256_final(&c, h);
    bn_from_be(t, h);
    if (!bn_lt(t, N)) return -1;
    bn_add_mod(r, d, t, N);
    if (bn_zero_mask(r)) return -1;
    bn_to_be(out, r);
    secure_zero(d, sizeof d); secure_zero(r, sizeof r);
    return 0;
}
