#include "qr.h"
#include <string.h>

/* ---- tables (versions 1..10) ---- */

static const uint8_t ECC_PER_BLOCK[4][11] = {
    {0,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18},     /* L */
    {0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26},     /* M */
    {0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24},     /* Q */
    {0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28}};    /* H */
static const uint8_t NUM_BLOCKS[4][11] = {
    {0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4},
    {0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5},
    {0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8},
    {0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8}};
static const uint8_t FORMAT_BITS[4] = {1, 0, 3, 2};  /* L, M, Q, H */

#define MAX_CODEWORDS 346                            /* version 10 */

static int num_align(int ver) { return ver == 1 ? 0 : ver / 7 + 2; }

static int raw_modules(int ver)
{
    int r = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int n = num_align(ver);
        r -= (25 * n - 10) * n - 55;
        if (ver >= 7) r -= 36;
    }
    return r;
}

static int data_codewords(int ver, qr_ecc ecc)
{
    return raw_modules(ver) / 8 - ECC_PER_BLOCK[ecc][ver] * NUM_BLOCKS[ecc][ver];
}

/* ---- GF(256) and Reed-Solomon ---- */

static uint8_t gmul(uint8_t x, uint8_t y)
{
    int z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * x;
    }
    return (uint8_t)z;
}

static void rs_generator(uint8_t *gen, int degree)
{
    uint8_t root = 1;
    memset(gen, 0, (size_t)degree);
    gen[degree - 1] = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            gen[j] = gmul(gen[j], root);
            if (j + 1 < degree) gen[j] ^= gen[j + 1];
        }
        root = gmul(root, 0x02);
    }
}

static void rs_remainder(const uint8_t *data, int len, const uint8_t *gen, int degree, uint8_t *res)
{
    memset(res, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        uint8_t factor = data[i] ^ res[0];
        memmove(res, res + 1, (size_t)degree - 1);
        res[degree - 1] = 0;
        for (int j = 0; j < degree; j++) res[j] ^= gmul(gen[j], factor);
    }
}

/* ---- matrix ---- */

typedef struct {
    qr_code *q;
    uint8_t  fn[QR_MAX_SIZE][(QR_MAX_SIZE + 7) / 8];   /* function patterns (not data) */
} ctx_t;

static int  get(const qr_code *q, int x, int y) { return (q->m[y][x >> 3] >> (x & 7)) & 1; }
static void put(qr_code *q, int x, int y, int v)
{
    if (v) q->m[y][x >> 3] |= (uint8_t)(1 << (x & 7)); else q->m[y][x >> 3] &= (uint8_t)~(1 << (x & 7));
}
static int  isfn(const ctx_t *c, int x, int y) { return (c->fn[y][x >> 3] >> (x & 7)) & 1; }
static void setfn(ctx_t *c, int x, int y, int v)
{
    put(c->q, x, y, v);
    c->fn[y][x >> 3] |= (uint8_t)(1 << (x & 7));
}

int qr_module(const qr_code *qr, int x, int y)
{
    if (x < 0 || y < 0 || x >= qr->size || y >= qr->size) return 0;
    return get(qr, x, y);
}

static void draw_finder(ctx_t *c, int cx, int cy)
{
    int size = c->q->size;
    for (int dy = -4; dy <= 4; dy++)
        for (int dx = -4; dx <= 4; dx++) {
            int d = (dx < 0 ? -dx : dx) > (dy < 0 ? -dy : dy) ? (dx < 0 ? -dx : dx) : (dy < 0 ? -dy : dy);
            int x = cx + dx, y = cy + dy;
            if (x >= 0 && x < size && y >= 0 && y < size) setfn(c, x, y, d != 2 && d != 4);
        }
}

static void draw_alignment(ctx_t *c, int cx, int cy)
{
    for (int dy = -2; dy <= 2; dy++)
        for (int dx = -2; dx <= 2; dx++) {
            int d = (dx < 0 ? -dx : dx) > (dy < 0 ? -dy : dy) ? (dx < 0 ? -dx : dx) : (dy < 0 ? -dy : dy);
            setfn(c, cx + dx, cy + dy, d != 1);
        }
}

static void draw_format(ctx_t *c, qr_ecc ecc, int mask)
{
    int size = c->q->size;
    unsigned data = (unsigned)(FORMAT_BITS[ecc] << 3 | mask), rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    unsigned bits = (data << 10 | rem) ^ 0x5412;
    for (int i = 0; i <= 5; i++) setfn(c, 8, i, (bits >> i) & 1);
    setfn(c, 8, 7, (bits >> 6) & 1);
    setfn(c, 8, 8, (bits >> 7) & 1);
    setfn(c, 7, 8, (bits >> 8) & 1);
    for (int i = 9; i < 15; i++) setfn(c, 14 - i, 8, (bits >> i) & 1);
    for (int i = 0; i < 8; i++) setfn(c, size - 1 - i, 8, (bits >> i) & 1);
    for (int i = 8; i < 15; i++) setfn(c, 8, size - 15 + i, (bits >> i) & 1);
    setfn(c, 8, size - 8, 1);                          /* always dark */
}

static void draw_function_patterns(ctx_t *c, int ver, qr_ecc ecc)
{
    int size = c->q->size;
    for (int i = 0; i < size; i++) { setfn(c, 6, i, i % 2 == 0); setfn(c, i, 6, i % 2 == 0); }
    draw_finder(c, 3, 3);
    draw_finder(c, size - 4, 3);
    draw_finder(c, 3, size - 4);

    int n = num_align(ver);
    if (n) {
        int pos[8], step = (ver * 4 + n * 2 + 1) / (n * 2 - 2) * 2;
        pos[0] = 6;
        for (int i = n - 1, p = size - 7; i >= 1; i--, p -= step) pos[i] = p;
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                if (!((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)))
                    draw_alignment(c, pos[i], pos[j]);
    }
    draw_format(c, ecc, 0);                            /* reserves the area; redrawn with the real mask later */
    if (ver >= 7) {
        unsigned rem = (unsigned)ver;
        for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        unsigned bits = (unsigned)ver << 12 | rem;
        for (int i = 0; i < 18; i++) {
            int a = size - 11 + i % 3, b = i / 3, v = (bits >> i) & 1;
            setfn(c, a, b, v);
            setfn(c, b, a, v);
        }
    }
}

static void draw_codewords(ctx_t *c, const uint8_t *cw, int ncw)
{
    int size = c->q->size;
    unsigned i = 0, total = (unsigned)ncw * 8;
    for (int right = size - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int vert = 0; vert < size; vert++)
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                int upward = ((right + 1) & 2) == 0;
                int y = upward ? size - 1 - vert : vert;
                if (!isfn(c, x, y) && i < total) {
                    put(c->q, x, y, (cw[i >> 3] >> (7 - (i & 7))) & 1);
                    i++;
                }
            }
    }
}

static void apply_mask(ctx_t *c, int mask)
{
    int size = c->q->size;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++) {
            int inv;
            switch (mask) {
            case 0: inv = (x + y) % 2 == 0; break;
            case 1: inv = y % 2 == 0; break;
            case 2: inv = x % 3 == 0; break;
            case 3: inv = (x + y) % 3 == 0; break;
            case 4: inv = (x / 3 + y / 2) % 2 == 0; break;
            case 5: inv = x * y % 2 + x * y % 3 == 0; break;
            case 6: inv = (x * y % 2 + x * y % 3) % 2 == 0; break;
            default: inv = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
            }
            if (inv && !isfn(c, x, y)) put(c->q, x, y, !get(c->q, x, y));
        }
}

/* ---- mask penalty (ISO 18004 section 7.8.3) ---- */

static int penalty(const qr_code *q)
{
    int size = q->size, result = 0, dark = 0;

    for (int dir = 0; dir < 2; dir++)                  /* rows, then columns */
        for (int a = 0; a < size; a++) {
            int run = 1, last = dir ? get(q, a, 0) : get(q, 0, a);
            unsigned win = 0;
            for (int b = 0; b < size; b++) {
                int v = dir ? get(q, a, b) : get(q, b, a);
                if (b > 0) {
                    if (v == last) { run++; if (run == 5) result += 3; else if (run > 5) result++; }
                    else { run = 1; last = v; }
                }
                win = ((win << 1) | (unsigned)v) & 0x7FF;
                /* 1 0 1 1 1 0 1 with 4 light modules on either side */
                if (b >= 10 && (win == 0x05D || win == 0x5D0)) result += 40;
            }
        }
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++) {
            int v = get(q, x, y);
            dark += v;
            if (x < size - 1 && y < size - 1 && v == get(q, x + 1, y) && v == get(q, x, y + 1) && v == get(q, x + 1, y + 1))
                result += 3;
        }
    int total = size * size;
    int k = ((dark * 20 - total * 10 < 0 ? total * 10 - dark * 20 : dark * 20 - total * 10) + total - 1) / total - 1;
    return result + k * 10;
}

/* ---- encoding ---- */

int qr_encode(qr_code *qr, const uint8_t *data, size_t len, qr_ecc ecc)
{
    int ver;
    for (ver = 1; ver <= QR_MAX_VERSION; ver++) {
        int cc = ver < 10 ? 8 : 16;
        if (4 + cc + 8 * (long) len <= 8L * data_codewords(ver, ecc)) break;
    }
    if (ver > QR_MAX_VERSION || ecc > QR_ECC_H) return -1;

    /* bit stream: mode 0100, character count, bytes, terminator, padding */
    uint8_t cw[MAX_CODEWORDS];
    int cap = data_codewords(ver, ecc), nbits = 0, cc = ver < 10 ? 8 : 16;
    memset(cw, 0, sizeof cw);
#define PUSH(val, n) do { for (int b_ = (n) - 1; b_ >= 0; b_--, nbits++) \
        cw[nbits >> 3] |= (uint8_t)((((val) >> b_) & 1) << (7 - (nbits & 7))); } while (0)
    PUSH(4, 4);
    PUSH((unsigned) len, cc);
    for (size_t i = 0; i < len; i++) PUSH(data[i], 8);
    int term = 8 * cap - nbits < 4 ? 8 * cap - nbits : 4;
    nbits += term;
    nbits = (nbits + 7) & ~7;
    for (uint8_t pad = 0xEC; nbits < 8 * cap; pad ^= 0xEC ^ 0x11, nbits += 8) cw[nbits >> 3] = pad;
#undef PUSH

    /* Reed-Solomon per block, interleaved */
    int nblocks = NUM_BLOCKS[ecc][ver], elen = ECC_PER_BLOCK[ecc][ver], raw = raw_modules(ver) / 8;
    int nshort = nblocks - raw % nblocks, shortlen = raw / nblocks;
    uint8_t gen[30], ecc_buf[8][30], out[MAX_CODEWORDS];
    int starts[8], dlens[8], k = 0, o = 0, maxd = 0;
    rs_generator(gen, elen);
    for (int b = 0; b < nblocks; b++) {
        dlens[b] = shortlen - elen + (b < nshort ? 0 : 1);
        starts[b] = k;
        rs_remainder(cw + k, dlens[b], gen, elen, ecc_buf[b]);
        k += dlens[b];
        if (dlens[b] > maxd) maxd = dlens[b];
    }
    for (int i = 0; i < maxd; i++)
        for (int b = 0; b < nblocks; b++)
            if (i < dlens[b]) out[o++] = cw[starts[b] + i];
    for (int i = 0; i < elen; i++)
        for (int b = 0; b < nblocks; b++) out[o++] = ecc_buf[b][i];

    /* matrix */
    ctx_t c;
    memset(qr, 0, sizeof *qr);
    memset(c.fn, 0, sizeof c.fn);
    c.q = qr;
    qr->version = (uint8_t) ver;
    qr->size = (uint8_t) (17 + 4 * ver);
    draw_function_patterns(&c, ver, ecc);
    draw_codewords(&c, out, o);

    int best = 0, best_score = 0x7FFFFFFF;
    for (int m = 0; m < 8; m++) {
        apply_mask(&c, m);
        draw_format(&c, ecc, m);
        int s = penalty(qr);
        if (s < best_score) { best_score = s; best = m; }
        apply_mask(&c, m);                             /* XOR again: undo */
    }
    qr->mask = (uint8_t) best;
    apply_mask(&c, best);
    draw_format(&c, ecc, best);
    return ver;
}
