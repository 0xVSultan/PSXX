#include "hash/blake3.h"
#include <string.h>

#define CHUNK_START 1u
#define CHUNK_END   2u
#define ROOT        8u

static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static const uint8_t PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void g(uint32_t *v, int a, int b, int c, int d, uint32_t mx, uint32_t my)
{
    v[a] += v[b] + mx; v[d] = ror(v[d] ^ v[a], 16);
    v[c] += v[d];      v[b] = ror(v[b] ^ v[c], 12);
    v[a] += v[b] + my; v[d] = ror(v[d] ^ v[a], 8);
    v[c] += v[d];      v[b] = ror(v[b] ^ v[c], 7);
}

/* the compression function of the first chunk (counter 0): the new chaining value is v[0..7] ^ v[8..15] */
static void compress(uint32_t v[16], const uint32_t cv[8], const uint8_t blk[64], uint32_t blen, uint32_t flags)
{
    uint32_t m[16], t[16];
    memcpy(v, cv, 32);
    memcpy(v + 8, IV, 16);
    v[12] = 0;
    v[13] = 0;
    v[14] = blen;
    v[15] = flags;
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t) blk[4 * i] | (uint32_t) blk[4 * i + 1] << 8 | (uint32_t) blk[4 * i + 2] << 16 | (uint32_t) blk[4 * i + 3] << 24;
    for (int r = 0; r < 7; r++) {
        g(v, 0, 4, 8, 12, m[0], m[1]);
        g(v, 1, 5, 9, 13, m[2], m[3]);
        g(v, 2, 6, 10, 14, m[4], m[5]);
        g(v, 3, 7, 11, 15, m[6], m[7]);
        g(v, 0, 5, 10, 15, m[8], m[9]);
        g(v, 1, 6, 11, 12, m[10], m[11]);
        g(v, 2, 7, 8, 13, m[12], m[13]);
        g(v, 3, 4, 9, 14, m[14], m[15]);
        if (r < 6) {
            for (int i = 0; i < 16; i++) t[i] = m[PERM[i]];
            memcpy(m, t, sizeof m);
        }
    }
    for (int i = 0; i < 8; i++) {
        v[i] ^= v[i + 8];
        v[i + 8] ^= cv[i];
    }
}

int blake3_hash(uint8_t out[32], const uint8_t *in, size_t len)
{
    uint32_t cv[8], v[16];
    uint8_t blk[64];
    uint32_t flags = CHUNK_START;
    size_t nblk;

    if (len > 1024) return -1;
    memcpy(cv, IV, 32);
    nblk = len ? (len + 63) / 64 : 1;
    for (size_t b = 0; b < nblk; b++) {
        size_t n = len - b * 64 > 64 ? 64 : len - b * 64;
        uint32_t f = flags;
        memset(blk, 0, 64);
        memcpy(blk, in + b * 64, n);
        if (b == nblk - 1) f |= CHUNK_END | ROOT;
        compress(v, cv, blk, (uint32_t) n, f);
        memcpy(cv, v, 32);
        flags = 0;
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t) cv[i];
        out[4 * i + 1] = (uint8_t) (cv[i] >> 8);
        out[4 * i + 2] = (uint8_t) (cv[i] >> 16);
        out[4 * i + 3] = (uint8_t) (cv[i] >> 24);
    }
    return 0;
}
