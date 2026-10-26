#include "hash/chacha20poly1305.h"
#include <string.h>
#include "util.h"

static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24); }
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) a += b; d ^= a; d = ROTL(d, 16); c += d; b ^= c; b = ROTL(b, 12); a += b; d ^= a; d = ROTL(d, 8); c += d; b ^= c; b = ROTL(b, 7)

static void chacha_block(uint8_t out[64], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = rd32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = rd32(nonce + 4 * i);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]); QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]); QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) wr32(out + 4 * i, x[i] + s[i]);
}

void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], uint32_t counter, const uint8_t nonce[12])
{
    uint8_t b[64];
    for (size_t o = 0; o < len; o += 64, counter++) {
        size_t n = len - o < 64 ? len - o : 64;
        chacha_block(b, key, counter, nonce);
        for (size_t i = 0; i < n; i++) out[o + i] = in[o + i] ^ b[i];
    }
    secure_zero(b, sizeof b);
}

/* Poly1305 (the 26 bit limb arithmetic of poly1305-donna) over msg, whole blocks plus a last short one */
static void poly1305(uint8_t tag[16], const uint8_t key[32], const uint8_t *m, size_t len)
{
    uint32_t r0 = rd32(key) & 0x3ffffff, r1 = (rd32(key + 3) >> 2) & 0x3ffff03, r2 = (rd32(key + 6) >> 4) & 0x3ffc0ff,
             r3 = (rd32(key + 9) >> 6) & 0x3f03fff, r4 = (rd32(key + 12) >> 8) & 0x00fffff;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, c;
    uint8_t blk[16];

    while (len) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t hibit;
        if (len >= 16) { memcpy(blk, m, 16); hibit = 1u << 24; m += 16; len -= 16; }
        else { memset(blk, 0, 16); memcpy(blk, m, len); blk[len] = 1; hibit = 0; len = 0; }
        h0 += rd32(blk) & 0x3ffffff;
        h1 += (rd32(blk + 3) >> 2) & 0x3ffffff;
        h2 += (rd32(blk + 6) >> 4) & 0x3ffffff;
        h3 += (rd32(blk + 9) >> 6) & 0x3ffffff;
        h4 += (rd32(blk + 12) >> 8) | hibit;
        d0 = (uint64_t) h0 * r0 + (uint64_t) h1 * s4 + (uint64_t) h2 * s3 + (uint64_t) h3 * s2 + (uint64_t) h4 * s1;
        d1 = (uint64_t) h0 * r1 + (uint64_t) h1 * r0 + (uint64_t) h2 * s4 + (uint64_t) h3 * s3 + (uint64_t) h4 * s2;
        d2 = (uint64_t) h0 * r2 + (uint64_t) h1 * r1 + (uint64_t) h2 * r0 + (uint64_t) h3 * s4 + (uint64_t) h4 * s3;
        d3 = (uint64_t) h0 * r3 + (uint64_t) h1 * r2 + (uint64_t) h2 * r1 + (uint64_t) h3 * r0 + (uint64_t) h4 * s4;
        d4 = (uint64_t) h0 * r4 + (uint64_t) h1 * r3 + (uint64_t) h2 * r2 + (uint64_t) h3 * r1 + (uint64_t) h4 * r0;
        c = (uint32_t) (d0 >> 26); h0 = (uint32_t) d0 & 0x3ffffff;
        d1 += c; c = (uint32_t) (d1 >> 26); h1 = (uint32_t) d1 & 0x3ffffff;
        d2 += c; c = (uint32_t) (d2 >> 26); h2 = (uint32_t) d2 & 0x3ffffff;
        d3 += c; c = (uint32_t) (d3 >> 26); h3 = (uint32_t) d3 & 0x3ffffff;
        d4 += c; c = (uint32_t) (d4 >> 26); h4 = (uint32_t) d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;
    }
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    {   /* h - p, select if h >= p */
        uint32_t g0 = h0 + 5, g1, g2, g3, g4, mask;
        c = g0 >> 26; g0 &= 0x3ffffff;
        g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        g4 = h4 + c - (1u << 26);
        mask = (g4 >> 31) - 1;                                    /* all ones when g4 did not borrow: h >= p */
        h0 = (h0 & ~mask) | (g0 & mask); h1 = (h1 & ~mask) | (g1 & mask); h2 = (h2 & ~mask) | (g2 & mask);
        h3 = (h3 & ~mask) | (g3 & mask); h4 = (h4 & ~mask) | (g4 & mask);
    }
    {   /* h mod 2^128 + s */
        uint64_t f;
        uint32_t w0 = (h0 | (h1 << 26)), w1 = ((h1 >> 6) | (h2 << 20)), w2 = ((h2 >> 12) | (h3 << 14)), w3 = ((h3 >> 18) | (h4 << 8));
        f = (uint64_t) w0 + rd32(key + 16); wr32(tag, (uint32_t) f);
        f = (uint64_t) w1 + rd32(key + 20) + (f >> 32); wr32(tag + 4, (uint32_t) f);
        f = (uint64_t) w2 + rd32(key + 24) + (f >> 32); wr32(tag + 8, (uint32_t) f);
        f = (uint64_t) w3 + rd32(key + 28) + (f >> 32); wr32(tag + 12, (uint32_t) f);
    }
}

/* the tag over ciphertext ct (no additional data): ct || padding || 0 (8 bytes) || length (8 bytes) */
static void aead_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ct, size_t len)
{
    uint8_t otk[64];
    uint8_t buf[640];                       /* the note ciphertexts are 580 bytes at most */
    size_t n = (len + 15) & ~(size_t) 15;
    chacha_block(otk, key, 0, nonce);
    memset(buf, 0, sizeof buf);
    memcpy(buf, ct, len);
    for (int i = 0; i < 4; i++) buf[n + 8 + i] = (uint8_t) (len >> (8 * i));
    poly1305(tag, otk, buf, n + 16);
    secure_zero(otk, sizeof otk);
}

int chacha20poly1305_decrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ct, size_t ctlen)
{
    uint8_t tag[16];
    uint32_t diff = 0;
    size_t len;
    if (ctlen < 16 || ctlen - 16 > 600) return -1;
    len = ctlen - 16;
    aead_tag(tag, key, nonce, ct, len);
    for (int i = 0; i < 16; i++) diff |= (uint32_t) (tag[i] ^ ct[len + i]);
    if (diff) return -1;
    chacha20_xor(out, ct, len, key, 1, nonce);
    return 0;
}

void chacha20poly1305_encrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t len)
{
    chacha20_xor(out, in, len, key, 1, nonce);
    aead_tag(out + len, key, nonce, out, len);
}
