#include "coin/ton.h"
#include <string.h>
#include "util.h"
#include "b64.h"
#include "coin/chains.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "tr.h"

void ton_entropy(uint8_t e[64], const char *phrase, const char *password)
{
    hmac_sha512((const uint8_t *) phrase, strlen(phrase), (const uint8_t *) password, strlen(password), e);
}

int ton_entropy_is_basic(const uint8_t e[64])
{
    static const char SALT[] = "TON seed version";
    uint8_t t[64];
    int ok;
    pbkdf2_hmac_sha512(e, 64, (const uint8_t *) SALT, sizeof SALT - 1, 100000 / 256, t, 64);
    ok = t[0] == 0;
    secure_zero(t, sizeof t);
    return ok;
}

int ton_private_seed_cb(uint8_t seed[64], const uint8_t e[64], int (*cb)(uint32_t, uint32_t, void *), void *user)
{
    static const char SALT[] = "TON default seed";
    return pbkdf2_hmac_sha512_cb(e, 64, (const uint8_t *) SALT, sizeof SALT - 1, 100000, seed, 64, cb, user);
}

void ton_private_seed(uint8_t seed[64], const uint8_t e[64]) { ton_private_seed_cb(seed, e, NULL, NULL); }

/* ---- cells ---- */

typedef struct {
    uint8_t b[128];
    int     n;                  /* bits */
} bits;

static void put_bit(bits *w, int v)
{
    if (w->n == 0) memset(w->b, 0, sizeof w->b);
    if (v) w->b[w->n >> 3] |= (uint8_t) (0x80 >> (w->n & 7));
    w->n++;
}

static void put_uint(bits *w, uint32_t v, int nb)
{
    for (int i = nb - 1; i >= 0; i--) put_bit(w, (int) ((v >> i) & 1));
}

static void put_bytes(bits *w, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) put_uint(w, p[i], 8);
}

/* representation hash of an ordinary cell with `nrefs` children (their depth and hash given) */
static void cell_hash(uint8_t out[32], const bits *w, int nrefs, const uint16_t *depth, const uint8_t (*hash)[32])
{
    sha256_ctx c;
    uint8_t d[2], data[128], dd[2];
    int nbytes = (w->n + 7) / 8;
    d[0] = (uint8_t) nrefs;
    d[1] = (uint8_t) (w->n / 8 + nbytes);
    memcpy(data, w->b, (size_t) nbytes);
    if (w->n & 7) data[nbytes - 1] |= (uint8_t) (0x80 >> (w->n & 7));       /* the completion tag */
    sha256_init(&c);
    sha256_update(&c, d, 2);
    sha256_update(&c, data, (size_t) nbytes);
    for (int i = 0; i < nrefs; i++) {
        dd[0] = (uint8_t) (depth[i] >> 8);
        dd[1] = (uint8_t) depth[i];
        sha256_update(&c, dd, 2);
    }
    for (int i = 0; i < nrefs; i++) sha256_update(&c, hash[i], 32);
    sha256_final(&c, out);
}

typedef struct {
    uint8_t  hash[32];          /* hash of the contract code cell */
    uint16_t depth;
} ton_code;

static const ton_code CODE[4] = {
    {{0xb6, 0x10, 0x41, 0xa5, 0x8a, 0x79, 0x80, 0xb9, 0x46, 0xe8, 0xfb, 0x9e, 0x19, 0x8e, 0x3c, 0x90,
      0x4d, 0x24, 0x79, 0x9f, 0xfa, 0x36, 0x57, 0x4e, 0xa4, 0x25, 0x1c, 0x41, 0xa5, 0x66, 0xf5, 0x81}, 0},
    {{0x84, 0xda, 0xfa, 0x44, 0x9f, 0x98, 0xa6, 0x98, 0x77, 0x89, 0xba, 0x23, 0x23, 0x58, 0x07, 0x2b,
      0xc0, 0xf7, 0x6d, 0xc4, 0x52, 0x40, 0x02, 0xa5, 0xd0, 0x91, 0x8b, 0x9a, 0x75, 0xd2, 0xd5, 0x99}, 0},
    {{0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
      0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0}, 7},
    {{0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
      0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f}, 6},
};

int ton_address(char *out, size_t cap, int version, int bounceable, const uint8_t pub[32])
{
    bits w;
    uint8_t data_hash[32], root[32], raw[36], hashes[2][32];
    uint16_t depths[2];
    uint16_t crc;
    char b[52];
    int n;

    if (version < 0 || version > 3 || cap < 49) return -1;
    /* the data cell of the wallet contract */
    w.n = 0;
    if (version == TON_V5R1) {
        put_bit(&w, 1);                              /* signature auth allowed */
        put_uint(&w, 0, 32);                         /* seqno */
        put_uint(&w, 0x7FFFFF11u, 32);               /* wallet id: -239 (main net) xor the context of workchain 0, subwallet 0 */
        put_bytes(&w, pub, 32);
        put_bit(&w, 0);                              /* no extensions */
    } else {
        put_uint(&w, 0, 32);                         /* seqno */
        put_uint(&w, 698983191u, 32);                /* subwallet id 0x29a9a317 */
        put_bytes(&w, pub, 32);
        if (version == TON_V4R2) put_bit(&w, 0);     /* no plugins */
    }
    cell_hash(data_hash, &w, 0, NULL, NULL);
    /* StateInit: no split depth, not special, code, data, no libraries; refs: code, data */
    w.n = 0;
    put_bit(&w, 0);
    put_bit(&w, 0);
    put_bit(&w, 1);
    put_bit(&w, 1);
    put_bit(&w, 0);
    memcpy(hashes[0], CODE[version].hash, 32);
    memcpy(hashes[1], data_hash, 32);
    depths[0] = CODE[version].depth;
    depths[1] = 0;
    cell_hash(root, &w, 2, depths, (const uint8_t (*)[32]) hashes);

    raw[0] = bounceable ? 0x11 : 0x51;
    raw[1] = 0;                                      /* workchain 0 */
    memcpy(raw + 2, root, 32);
    crc = crc16_xmodem(raw, 34);
    raw[34] = (uint8_t) (crc >> 8);
    raw[35] = (uint8_t) crc;
    n = b64_encode(raw, 36, b, sizeof b);
    if (n != 48) return -1;
    for (int i = 0; i < n; i++) out[i] = b[i] == '+' ? '-' : b[i] == '/' ? '_' : b[i];
    out[n] = 0;
    return n;
}
