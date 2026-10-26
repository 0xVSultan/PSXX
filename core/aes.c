#include "aes.h"
#include <string.h>
#include "util.h"

static uint8_t sbox[256], isbox[256];
static int tables_ready;

static uint8_t rotl8(uint8_t x, int n) { return (uint8_t) ((x << n) | (x >> (8 - n))); }
static uint8_t xtime(uint8_t x) { return (uint8_t) ((x << 1) ^ ((x >> 7) * 0x1B)); }

/* multiplication in GF(2^8) mod x^8 + x^4 + x^3 + x + 1, constant time */
static uint8_t gmul8(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        p ^= (uint8_t) (a & (0u - (b & 1)));
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

/* S-box from the multiplicative inverse and the affine map (the usual generator walk over the powers of 3) */
static void make_tables(void)
{
    uint8_t p = 1, q = 1;

    do {
        p = (uint8_t) (p ^ (p << 1) ^ ((p >> 7) * 0x1B));          /* p *= 3 */
        q ^= (uint8_t) (q << 1);                                   /* q /= 3 */
        q ^= (uint8_t) (q << 2);
        q ^= (uint8_t) (q << 4);
        q ^= (uint8_t) ((q >> 7) * 0x09);
        sbox[p] = (uint8_t) (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63);
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) isbox[sbox[i]] = (uint8_t) i;
    tables_ready = 1;
}

int aes_init(aes_ctx *c, const uint8_t *key, int keybits)
{
    int nk = keybits / 32, total;
    uint8_t rcon = 1;

    if (keybits != 128 && keybits != 192 && keybits != 256) return -1;
    if (!tables_ready) make_tables();
    c->rounds = nk + 6;
    total = 16 * (c->rounds + 1);
    memcpy(c->rk, key, (size_t) (4 * nk));
    for (int i = 4 * nk; i < total; i += 4) {
        uint8_t t[4];
        memcpy(t, c->rk + i - 4, 4);
        if ((i / 4) % nk == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t) (sbox[t[1]] ^ rcon); t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[u];
            rcon = xtime(rcon);
        } else if (nk > 6 && (i / 4) % nk == 4) {
            for (int k = 0; k < 4; k++) t[k] = sbox[t[k]];
        }
        for (int k = 0; k < 4; k++) c->rk[i + k] = (uint8_t) (c->rk[i - 4 * nk + k] ^ t[k]);
    }
    return 0;
}

void aes_wipe(aes_ctx *c) { secure_zero(c, sizeof *c); }

static void add_key(uint8_t s[16], const uint8_t *rk) { for (int i = 0; i < 16; i++) s[i] ^= rk[i]; }

static void sub_shift(uint8_t s[16], const uint8_t *box)
{
    uint8_t t[16];
    for (int col = 0; col < 4; col++)
        for (int r = 0; r < 4; r++) t[4 * col + r] = box[s[4 * ((col + r) & 3) + r]];
    memcpy(s, t, 16);
}

static void inv_shift_sub(uint8_t s[16])
{
    uint8_t t[16];
    for (int col = 0; col < 4; col++)
        for (int r = 0; r < 4; r++) t[4 * ((col + r) & 3) + r] = isbox[s[4 * col + r]];
    memcpy(s, t, 16);
}

static void mix(uint8_t s[16])
{
    for (int col = 0; col < 16; col += 4) {
        uint8_t a0 = s[col], a1 = s[col + 1], a2 = s[col + 2], a3 = s[col + 3], x = (uint8_t) (a0 ^ a1 ^ a2 ^ a3);
        s[col]     ^= (uint8_t) (x ^ xtime((uint8_t) (a0 ^ a1)));
        s[col + 1] ^= (uint8_t) (x ^ xtime((uint8_t) (a1 ^ a2)));
        s[col + 2] ^= (uint8_t) (x ^ xtime((uint8_t) (a2 ^ a3)));
        s[col + 3] ^= (uint8_t) (x ^ xtime((uint8_t) (a3 ^ a0)));
    }
}

static void inv_mix(uint8_t s[16])
{
    for (int col = 0; col < 16; col += 4) {
        uint8_t a0 = s[col], a1 = s[col + 1], a2 = s[col + 2], a3 = s[col + 3];
        s[col]     = (uint8_t) (gmul8(a0, 14) ^ gmul8(a1, 11) ^ gmul8(a2, 13) ^ gmul8(a3, 9));
        s[col + 1] = (uint8_t) (gmul8(a0, 9) ^ gmul8(a1, 14) ^ gmul8(a2, 11) ^ gmul8(a3, 13));
        s[col + 2] = (uint8_t) (gmul8(a0, 13) ^ gmul8(a1, 9) ^ gmul8(a2, 14) ^ gmul8(a3, 11));
        s[col + 3] = (uint8_t) (gmul8(a0, 11) ^ gmul8(a1, 13) ^ gmul8(a2, 9) ^ gmul8(a3, 14));
    }
}

void aes_encrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];

    memcpy(s, in, 16);
    add_key(s, c->rk);
    for (int r = 1; r < c->rounds; r++) {
        sub_shift(s, sbox);
        mix(s);
        add_key(s, c->rk + 16 * r);
    }
    sub_shift(s, sbox);
    add_key(s, c->rk + 16 * c->rounds);
    memcpy(out, s, 16);
    secure_zero(s, sizeof s);
}

void aes_decrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];

    memcpy(s, in, 16);
    add_key(s, c->rk + 16 * c->rounds);
    for (int r = c->rounds - 1; r > 0; r--) {
        inv_shift_sub(s);
        add_key(s, c->rk + 16 * r);
        inv_mix(s);
    }
    inv_shift_sub(s);
    add_key(s, c->rk);
    memcpy(out, s, 16);
    secure_zero(s, sizeof s);
}

void aes_cbc_encrypt(const aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16];

    memcpy(prev, iv, 16);
    for (size_t o = 0; o + 16 <= len; o += 16) {
        uint8_t b[16];
        for (int i = 0; i < 16; i++) b[i] = (uint8_t) (in[o + i] ^ prev[i]);
        aes_encrypt_block(c, b, prev);
        memcpy(out + o, prev, 16);
    }
}

void aes_cbc_decrypt(const aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[16], cur[16], b[16];

    memcpy(prev, iv, 16);
    for (size_t o = 0; o + 16 <= len; o += 16) {
        memcpy(cur, in + o, 16);
        aes_decrypt_block(c, cur, b);
        for (int i = 0; i < 16; i++) out[o + i] = (uint8_t) (b[i] ^ prev[i]);
        memcpy(prev, cur, 16);
    }
}

static void inc32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) break;
}

void aes_ctr_xor(const aes_ctx *c, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t o = 0; o < len; o += 16) {
        uint8_t ks[16];
        size_t n = len - o < 16 ? len - o : 16;
        aes_encrypt_block(c, ctr, ks);
        for (size_t i = 0; i < n; i++) out[o + i] = (uint8_t) (in[o + i] ^ ks[i]);
        inc32(ctr);
    }
}

/* x = x * h in GF(2^128), the GCM way (bit reflected), bit by bit: small and constant time */
static void ghash_mul(uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = {0}, v[16];

    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        uint8_t m = (uint8_t) (0u - ((x[i >> 3] >> (7 - (i & 7))) & 1)), lsb = (uint8_t) (0u - (v[15] & 1));
        for (int k = 0; k < 16; k++) z[k] ^= (uint8_t) (v[k] & m);
        for (int k = 15; k > 0; k--) v[k] = (uint8_t) ((v[k] >> 1) | (v[k - 1] << 7));
        v[0] = (uint8_t) ((v[0] >> 1) ^ (0xE1 & lsb));
    }
    memcpy(x, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len)
{
    for (size_t o = 0; o < len; o += 16) {
        size_t n = len - o < 16 ? len - o : 16;
        for (size_t i = 0; i < n; i++) y[i] ^= data[o + i];
        ghash_mul(y, h);
    }
}

static void gcm_tag(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, uint8_t tag[16])
{
    uint8_t h[16] = {0}, y[16] = {0}, lens[16] = {0}, j0[16], e[16];
    uint64_t abits = (uint64_t) aad_len * 8, cbits = (uint64_t) len * 8;

    aes_encrypt_block(c, h, h);
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, ct, len);
    for (int i = 0; i < 8; i++) { lens[7 - i] = (uint8_t) (abits >> (8 * i)); lens[15 - i] = (uint8_t) (cbits >> (8 * i)); }
    ghash_update(y, h, lens, 16);
    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0; j0[15] = 1;
    aes_encrypt_block(c, j0, e);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t) (y[i] ^ e[i]);
    secure_zero(h, sizeof h);
}

static void gcm_ctr(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ctr[16];

    memcpy(ctr, nonce, 12);
    ctr[12] = ctr[13] = ctr[14] = 0; ctr[15] = 2;         /* J0 + 1: counter 1 is used for the tag */
    aes_ctr_xor(c, ctr, in, out, len);
}

void aes_gcm_encrypt(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16])
{
    gcm_ctr(c, nonce, pt, ct, len);
    gcm_tag(c, nonce, aad, aad_len, ct, len, tag);
}

int aes_gcm_decrypt(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
    uint8_t t[16], diff = 0;

    gcm_tag(c, nonce, aad, aad_len, ct, len, t);
    for (int i = 0; i < 16; i++) diff |= (uint8_t) (t[i] ^ tag[i]);
    if (diff) { memset(pt, 0, len); return -1; }
    gcm_ctr(c, nonce, ct, pt, len);
    return 0;
}
