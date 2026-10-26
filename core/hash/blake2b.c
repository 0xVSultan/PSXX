#include "hash/blake2b.h"
#include "hash/sha2_k.h"
#include <string.h>

#define IV(i) ((uint64_t) sha2_ivh[i] << 32 | sha2_ivl[i])          /* the initial value of SHA-512 (core/hash/sha2_k.h) */

static const uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

#define G(a, b, c, d, x, y)                                                                                         \
    do {                                                                                                            \
        v[a] = v[a] + v[b] + (x); v[d] = rotr(v[d] ^ v[a], 32);                                                     \
        v[c] = v[c] + v[d];       v[b] = rotr(v[b] ^ v[c], 24);                                                     \
        v[a] = v[a] + v[b] + (y); v[d] = rotr(v[d] ^ v[a], 16);                                                     \
        v[c] = v[c] + v[d];       v[b] = rotr(v[b] ^ v[c], 63);                                                     \
    } while (0)

static uint64_t ld64(const uint8_t *p)
{
    return (uint64_t) p[0] | (uint64_t) p[1] << 8 | (uint64_t) p[2] << 16 | (uint64_t) p[3] << 24 | (uint64_t) p[4] << 32 |
           (uint64_t) p[5] << 40 | (uint64_t) p[6] << 48 | (uint64_t) p[7] << 56;
}

static void compress(blake2b_ctx *c, const uint8_t blk[128], int last)
{
    uint64_t m[16], v[16];
    SHA2_TABLES();
    for (int i = 0; i < 16; i++) m[i] = ld64(blk + 8 * i);
    for (int i = 0; i < 8; i++) { v[i] = c->h[i]; v[i + 8] = IV(i); }
    v[12] ^= c->t0;
    v[13] ^= c->t1;
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = SIGMA[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) c->h[i] ^= v[i] ^ v[i + 8];
}

int blake2b_init(blake2b_ctx *c, size_t outlen, const uint8_t *key, size_t keylen, const uint8_t *salt16, const uint8_t *person16)
{
    uint8_t p[64];
    if (outlen < 1 || outlen > 64 || keylen > 64) return -1;
    memset(p, 0, sizeof p);
    p[0] = (uint8_t) outlen;
    p[1] = (uint8_t) keylen;
    p[2] = 1;                       /* fanout */
    p[3] = 1;                       /* depth */
    if (salt16) memcpy(p + 32, salt16, 16);
    if (person16) memcpy(p + 48, person16, 16);
    memset(c, 0, sizeof *c);
    SHA2_TABLES();
    for (int i = 0; i < 8; i++) c->h[i] = IV(i) ^ ld64(p + 8 * i);
    c->outlen = (uint32_t) outlen;
    if (keylen) {
        uint8_t blk[128];
        memset(blk, 0, sizeof blk);
        memcpy(blk, key, keylen);
        blake2b_update(c, blk, 128);
        memset(blk, 0, sizeof blk);
    }
    return 0;
}

void blake2b_update(blake2b_ctx *c, const uint8_t *in, size_t len)
{
    while (len) {
        if (c->fill == 128) {           /* the buffer is full and there is more: compress it (never the last block) */
            c->t0 += 128;
            if (c->t0 < 128) c->t1++;
            compress(c, c->buf, 0);
            c->fill = 0;
        }
        size_t n = 128 - c->fill;
        if (n > len) n = len;
        memcpy(c->buf + c->fill, in, n);
        c->fill += (uint32_t) n;
        in += n;
        len -= n;
    }
}

void blake2b_final(blake2b_ctx *c, uint8_t *out)
{
    uint8_t full[64];
    c->t0 += c->fill;
    if (c->t0 < c->fill) c->t1++;
    memset(c->buf + c->fill, 0, 128 - c->fill);
    compress(c, c->buf, 1);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) full[8 * i + j] = (uint8_t) (c->h[i] >> (8 * j));
    memcpy(out, full, c->outlen);
    memset(full, 0, sizeof full);
}

void blake2b(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    blake2b_ctx c;
    blake2b_init(&c, outlen, NULL, 0, NULL, NULL);
    blake2b_update(&c, in, inlen);
    blake2b_final(&c, out);
}
