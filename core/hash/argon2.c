#include "hash/argon2.h"
#include <string.h>
#include "hash/blake2b.h"

#define SYNC_POINTS 4
#define VERSION 0x13
#define TYPE_ID 2

static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
static uint64_t fb(uint64_t x, uint64_t y) { return x + y + 2 * (uint64_t) (uint32_t) x * (uint32_t) y; }

#define G(a, b, c, d) do { \
    a = fb(a, b); d = rotr64(d ^ a, 32); \
    c = fb(c, d); b = rotr64(b ^ c, 24); \
    a = fb(a, b); d = rotr64(d ^ a, 16); \
    c = fb(c, d); b = rotr64(b ^ c, 63); } while (0)

#define ROUND(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) do { \
    G(v0, v4, v8, v12); G(v1, v5, v9, v13); G(v2, v6, v10, v14); G(v3, v7, v11, v15); \
    G(v0, v5, v10, v15); G(v1, v6, v11, v12); G(v2, v7, v8, v13); G(v3, v4, v9, v14); } while (0)

void argon2_fill_block(uint64_t next[ARGON2_QWORDS], const uint64_t prev[ARGON2_QWORDS], const uint64_t ref[ARGON2_QWORDS], int with_xor)
{
    uint64_t r[ARGON2_QWORDS];

    for (int i = 0; i < ARGON2_QWORDS; i++) r[i] = ref[i] ^ prev[i];
    if (with_xor) for (int i = 0; i < ARGON2_QWORDS; i++) next[i] ^= r[i];
    else memcpy(next, r, sizeof r);
    for (int i = 0; i < 8; i++) {                                     /* the 16 word rows */
        uint64_t *v = r + 16 * i;
        ROUND(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
    }
    for (int i = 0; i < 8; i++) {                                     /* the columns of 2 words */
        uint64_t *v = r + 2 * i;
        ROUND(v[0], v[1], v[16], v[17], v[32], v[33], v[48], v[49], v[64], v[65], v[80], v[81], v[96], v[97], v[112], v[113]);
    }
    for (int i = 0; i < ARGON2_QWORDS; i++) next[i] ^= r[i];
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24); }

/* H': a hash of any length up to 1024 bytes out of BLAKE2b */
static void hash_long(uint8_t *out, uint32_t outlen, const uint8_t *in, size_t inlen)
{
    uint8_t lenb[4], v[64], w[64];
    blake2b_ctx c;

    put32(lenb, outlen);
    blake2b_init(&c, outlen <= 64 ? outlen : 64, NULL, 0, NULL, NULL);
    blake2b_update(&c, lenb, 4);
    blake2b_update(&c, in, inlen);
    blake2b_final(&c, v);
    if (outlen <= 64) { memcpy(out, v, outlen); return; }
    memcpy(out, v, 32);
    out += 32;
    outlen -= 32;
    while (outlen > 64) {
        memcpy(w, v, 64);
        blake2b(v, 64, w, 64);
        memcpy(out, v, 32);
        out += 32;
        outlen -= 32;
    }
    memcpy(w, v, 64);
    blake2b(v, outlen, w, 64);
    memcpy(out, v, outlen);
}

uint32_t argon2_blocks(const argon2_params *p)
{
    uint32_t unit;

    if (p->lanes < 1 || p->lanes > 255 || p->t_cost < 1 || p->taglen < 4 || p->taglen > 1024) return 0;
    unit = 4 * p->lanes;
    if (p->m_cost_kib < 2 * SYNC_POINTS * p->lanes) return 0;
    return p->m_cost_kib / unit * unit;
}

typedef struct {
    uint64_t a[ARGON2_QWORDS], b[ARGON2_QWORDS], ref[ARGON2_QWORDS], addr[ARGON2_QWORDS], in[ARGON2_QWORDS], zero[ARGON2_QWORDS];
} work;
static work W;

static void next_addresses(void)
{
    W.in[6]++;
    argon2_fill_block(W.addr, W.zero, W.in, 0);
    argon2_fill_block(W.addr, W.zero, W.addr, 0);
}

static void segment(const argon2_params *p, const argon2_mem *m, uint32_t blocks, uint32_t pass, uint32_t slice, uint32_t lane)
{
    uint32_t q = blocks / p->lanes, seg = q / SYNC_POINTS;
    int indep = pass == 0 && slice < SYNC_POINTS / 2;
    uint32_t start = (pass == 0 && slice == 0) ? 2 : 0, cur = lane * q + slice * seg + start, prev_idx;
    uint64_t *prev = W.a, *out = W.b;

    if (indep) {
        memset(W.in, 0, sizeof W.in);
        memset(W.zero, 0, sizeof W.zero);
        W.in[0] = pass; W.in[1] = lane; W.in[2] = slice; W.in[3] = blocks; W.in[4] = p->t_cost; W.in[5] = TYPE_ID;
        if (pass == 0 && slice == 0) next_addresses();
    }
    prev_idx = cur % q == 0 ? cur + q - 1 : cur - 1;
    m->get(m->ctx, prev_idx, prev);
    for (uint32_t i = start; i < seg; i++, cur++) {
        uint64_t pr;
        uint32_t ref_lane, area, ref_index, j1;
        uint64_t rel;
        int same;

        if (indep) {
            if (i % ARGON2_QWORDS == 0) next_addresses();
            pr = W.addr[i % ARGON2_QWORDS];
        } else pr = prev[0];
        ref_lane = (uint32_t) (pr >> 32) % p->lanes;
        if (pass == 0 && slice == 0) ref_lane = lane;
        same = ref_lane == lane;
        j1 = (uint32_t) pr;
        if (pass == 0) {
            if (slice == 0) area = i - 1;
            else if (same) area = slice * seg + i - 1;
            else area = slice * seg + (i == 0 ? (uint32_t) -1 : 0);
        } else {
            if (same) area = q - seg + i - 1;
            else area = q - seg + (i == 0 ? (uint32_t) -1 : 0);
        }
        rel = (uint64_t) j1 * j1 >> 32;
        rel = area - 1 - ((uint64_t) area * rel >> 32);
        ref_index = (uint32_t) (((pass == 0 ? 0 : (slice == SYNC_POINTS - 1 ? 0 : (slice + 1) * seg)) + rel) % q);
        m->get(m->ctx, ref_lane * q + ref_index, W.ref);
        if (pass > 0) m->get(m->ctx, cur, out);                        /* the old content is XORed in */
        argon2_fill_block(out, prev, W.ref, pass > 0);
        m->put(m->ctx, cur, out);
        { uint64_t *t = prev; prev = out; out = t; }
    }
}

int argon2id(const argon2_params *p, const argon2_mem *m, uint8_t *tag)
{
    uint32_t blocks = argon2_blocks(p), q, lanes = p->lanes;
    uint8_t h0[72], blk[ARGON2_BLOCK_BYTES], fourb[4];
    blake2b_ctx c;
    static uint64_t acc[ARGON2_QWORDS];

    if (!blocks) return -1;
    q = blocks / lanes;
    blake2b_init(&c, 64, NULL, 0, NULL, NULL);
    put32(fourb, lanes); blake2b_update(&c, fourb, 4);
    put32(fourb, p->taglen); blake2b_update(&c, fourb, 4);
    put32(fourb, p->m_cost_kib); blake2b_update(&c, fourb, 4);
    put32(fourb, p->t_cost); blake2b_update(&c, fourb, 4);
    put32(fourb, VERSION); blake2b_update(&c, fourb, 4);
    put32(fourb, TYPE_ID); blake2b_update(&c, fourb, 4);
    put32(fourb, (uint32_t) p->pwdlen); blake2b_update(&c, fourb, 4); if (p->pwdlen) blake2b_update(&c, p->pwd, p->pwdlen);
    put32(fourb, (uint32_t) p->saltlen); blake2b_update(&c, fourb, 4); if (p->saltlen) blake2b_update(&c, p->salt, p->saltlen);
    put32(fourb, (uint32_t) p->secretlen); blake2b_update(&c, fourb, 4); if (p->secretlen) blake2b_update(&c, p->secret, p->secretlen);
    put32(fourb, (uint32_t) p->adlen); blake2b_update(&c, fourb, 4); if (p->adlen) blake2b_update(&c, p->ad, p->adlen);
    blake2b_final(&c, h0);

    for (uint32_t l = 0; l < lanes; l++)
        for (uint32_t j = 0; j < 2; j++) {
            put32(h0 + 64, j);
            put32(h0 + 68, l);
            hash_long(blk, ARGON2_BLOCK_BYTES, h0, 72);
            memcpy(W.a, blk, ARGON2_BLOCK_BYTES);
            m->put(m->ctx, l * q + j, W.a);
        }
    for (uint32_t pass = 0; pass < p->t_cost; pass++)
        for (uint32_t slice = 0; slice < SYNC_POINTS; slice++) {
            for (uint32_t l = 0; l < lanes; l++) segment(p, m, blocks, pass, slice, l);
            if (m->progress) m->progress(m->ctx, pass, slice);
        }
    memset(acc, 0, sizeof acc);
    for (uint32_t l = 0; l < lanes; l++) {
        m->get(m->ctx, l * q + q - 1, W.a);
        for (int i = 0; i < ARGON2_QWORDS; i++) acc[i] ^= W.a[i];
    }
    memcpy(blk, acc, ARGON2_BLOCK_BYTES);
    hash_long(tag, p->taglen, blk, ARGON2_BLOCK_BYTES);
    return 0;
}
