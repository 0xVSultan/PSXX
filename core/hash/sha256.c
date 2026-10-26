#include "hash/sha256.h"
#include "hash/sha2_k.h"
#include <string.h>

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    SHA2_TABLES();                                  /* K: the high words of SHA-512's (core/hash/sha2_k.h) */
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]; f=h[5]; g=h[6]; hh=h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROR(e,6) ^ ROR(e,11) ^ ROR(e,25)) + ((e & f) ^ (~e & g)) + sha2_kh[i] + w[i];
        uint32_t t2 = (ROR(a,2) ^ ROR(a,13) ^ ROR(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void sha256_init(sha256_ctx *c)
{
    SHA2_TABLES();
    memcpy(c->h, sha2_ivh, sizeof c->h);
    c->len = 0;
    c->fill = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *msg, size_t len)
{
    c->len += len;
    if (c->fill) {
        size_t n = 64 - c->fill;
        if (n > len) n = len;
        memcpy(c->buf + c->fill, msg, n);
        c->fill += (uint32_t)n; msg += n; len -= n;
        if (c->fill < 64) return;
        block(c->h, c->buf);
        c->fill = 0;
    }
    for (; len >= 64; msg += 64, len -= 64) block(c->h, msg);
    memcpy(c->buf, msg, len);
    c->fill = (uint32_t)len;
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad[72] = {0x80};
    size_t padlen = (c->fill < 56) ? 56 - c->fill : 120 - c->fill;
    for (int i = 0; i < 8; i++) pad[padlen + i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_update(c, pad, padlen + 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]=(uint8_t)(c->h[i]>>24); out[4*i+1]=(uint8_t)(c->h[i]>>16);
        out[4*i+2]=(uint8_t)(c->h[i]>>8); out[4*i+3]=(uint8_t)c->h[i];
    }
}

void sha256_tagged_init(sha256_ctx *c, const char *tag)
{
    uint8_t h[32];
    sha256((const uint8_t *)tag, strlen(tag), h);
    sha256_init(c);
    sha256_update(c, h, 32);
    sha256_update(c, h, 32);
}

void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, msg, len);
    sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    uint8_t k[64] = {0}, pad[64], inner[32];
    sha256_ctx c;
    if (klen > 64) sha256(key, klen, k); else memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha256_init(&c); sha256_update(&c, pad, 64); sha256_update(&c, msg, mlen); sha256_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha256_init(&c); sha256_update(&c, pad, 64); sha256_update(&c, inner, 32); sha256_final(&c, out);
    for (size_t i = 0; i < sizeof k; i++) ((volatile uint8_t *)k)[i] = 0;
}
