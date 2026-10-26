#include "wl.h"
#include <string.h>

#define NCTX1 128
#define NCTX2 8192
#define ROWSYM 64
#define SCALE 65536u
#define TOP (1u << 24)
#define HDR 10
#define WORD_MAX 32

typedef struct {
    uint16_t n0, nrows;
    uint16_t n1[NCTX1];
    uint16_t rowidx[NCTX2];
    uint8_t c0[ROWSYM];
    uint8_t c1[NCTX1][ROWSYM];
} base_t;                                       /* followed by the rows of order 2: uint8_t c[rows][64], uint16_t n[rows] */

typedef struct {
    base_t *b;
    uint8_t (*rc)[ROWSYM];
    uint16_t *rn;
    unsigned rows, nsym, pos, h1, h2;
} model_t;

static unsigned rd16(const uint8_t *p) { return p[0] | ((unsigned) p[1] << 8); }

size_t wl_work_size(const uint8_t *blob, size_t len)
{
    if (len < HDR || blob[2] < 3 || blob[2] > ROWSYM) return 0;
    return sizeof(base_t) + (size_t) rd16(blob + 6) * (ROWSYM + 2);
}

static unsigned ctx1(const model_t *m) { return m->pos == 1 ? 64 + m->h1 : m->h1; }

/* blend the counts of one context into the probability p below it; w is the weight of p (tools/wl_pack.py: 4 + 3 or 6 times the symbols the context has seen) */
static uint32_t bl(uint32_t p, unsigned c, unsigned n, unsigned w)
{
    return (c * 2 * SCALE + w * p) / (2 * n + w);
}

static unsigned seen(const uint8_t *row, unsigned n)
{
    unsigned d = 0;
    for (unsigned s = 0; s < n; s++) d += row[s] != 0;
    return d;
}

static uint32_t freqs(const model_t *m, uint32_t *f)
{
    unsigned k1 = ctx1(m), k2 = m->h2 * NCTX1 + k1, r2 = m->b->rowidx[k2], n = m->nsym;
    const uint8_t *c1 = m->b->n1[k1] ? m->b->c1[k1] : 0;
    const uint8_t *c2 = r2 != 0xFFFF ? m->rc[r2] : 0;
    unsigned w1 = c1 ? 4 + 3 * seen(c1, n) : 0, w2 = c2 ? 4 + 6 * seen(c2, n) : 0;
    uint32_t total = 0;

    for (unsigned s = 0; s < n; s++) {
        uint32_t p = ((m->b->c0[s] + 1u) * SCALE) / (m->b->n0 + n);
        if (c1) p = bl(p, c1[s], m->b->n1[k1], w1);
        if (c2) p = bl(p, c2[s], m->rn[r2], w2);
        f[s] = (p >> 2) + 1;
        total += f[s];
    }
    return total;
}

static void bump(uint8_t *row, uint16_t *n, unsigned s, unsigned nsym)
{
    row[s]++;
    (*n)++;
    if (row[s] > 254) {
        unsigned sum = 0;
        for (unsigned i = 0; i < nsym; i++) { row[i] >>= 1; sum += row[i]; }
        *n = (uint16_t) sum;
    }
}

static int update(model_t *m, unsigned s)
{
    unsigned k1 = ctx1(m), k2 = m->h2 * NCTX1 + k1, r = m->b->rowidx[k2];

    bump(m->b->c1[k1], &m->b->n1[k1], s, m->nsym);
    if (r == 0xFFFF) {
        if (m->b->nrows >= m->rows) return -1;
        r = m->b->nrows++;
        m->b->rowidx[k2] = (uint16_t) r;
    }
    bump(m->rc[r], &m->rn[r], s, m->nsym);
    bump(m->b->c0, &m->b->n0, s, m->nsym);
    m->pos = s == m->nsym - 1 ? 0 : m->pos + 1;
    m->h2 = m->h1;
    m->h1 = s;
    return 0;
}

static unsigned next_byte(wl_rc *r) { return r->p < r->end ? *r->p++ : 0; }

void wl_rc_init(wl_rc *r, const uint8_t *src, size_t len)
{
    r->p = src;
    r->end = src + len;
    r->code = 0;
    for (int i = 0; i < 4; i++) r->code = (r->code << 8) | next_byte(r);
    r->range = 0xFFFFFFFFu;
}

/* where the code is, as a count below total; the range is left divided by total for rc_take */
static uint32_t rc_value(wl_rc *r, uint32_t total)
{
    uint32_t v;

    r->range /= total;
    v = r->code / r->range;
    return v < total ? v : total - 1;
}

/* takes the symbol of the counts [cum, cum + f) */
static void rc_take(wl_rc *r, uint32_t cum, uint32_t f)
{
    r->code -= cum * r->range;
    r->range *= f;
    while (r->range < TOP) {
        r->code = (r->code << 8) | next_byte(r);
        r->range <<= 8;
    }
}

static unsigned decode_sym(wl_rc *r, const uint32_t *f, uint32_t total, unsigned nsym)
{
    uint32_t v = rc_value(r, total), cum = 0;
    unsigned s = 0;

    while (s + 1 < nsym && cum + f[s] <= v) cum += f[s++];
    rc_take(r, cum, f[s]);
    return s;
}

int wl_rc_bit(wl_rc *r, unsigned c[2])
{
    uint32_t f0 = 2 * c[0] + 1, total = 2 * (c[0] + c[1]) + 2;
    int b = rc_value(r, total) >= f0;

    rc_take(r, b ? f0 : 0, b ? total - f0 : f0);
    c[b]++;
    return b;
}

void wl_rc_shuffle(wl_rc *r, uint16_t *a, unsigned n)
{
    for (unsigned k = n; k-- > 1;) {
        unsigned j = rc_value(r, k + 1);
        uint16_t t = a[k];
        rc_take(r, j, 1);
        a[k] = a[j];
        a[j] = t;
    }
}

unsigned wl_mask_decode(const uint8_t *src, size_t len, unsigned n, uint8_t *mask)
{
    wl_rc r;
    unsigned c[2] = {0, 0};

    wl_rc_init(&r, src, len);
    memset(mask, 0, (n + 7) / 8);
    for (unsigned i = 0; i < n; i++)
        if (wl_rc_bit(&r, c)) mask[i >> 3] |= (uint8_t) (1u << (i & 7));
    return c[1];
}

static size_t put_utf8(char *o, size_t cap, size_t at, unsigned c)
{
    size_t n = c < 0x80 ? 1 : c < 0x800 ? 2 : 3;

    if (at + n > cap) return 0;
    if (n == 1) o[at] = (char) c;
    else if (n == 2) { o[at] = (char) (0xC0 | (c >> 6)); o[at + 1] = (char) (0x80 | (c & 63)); }
    else { o[at] = (char) (0xE0 | (c >> 12)); o[at + 1] = (char) (0x80 | ((c >> 6) & 63)); o[at + 2] = (char) (0x80 | (c & 63)); }
    return n;
}

/* the decomposed word w[0..n) as composed code points in c; returns how many */
static unsigned compose(const uint16_t *w, unsigned n, int hangul, const uint8_t *comp, unsigned ncomp, uint16_t *c)
{
    unsigned i = 0, k = 0;

    while (i < n) {
        unsigned x = w[i];
        if (hangul && x >= 0x1100 && x <= 0x1112 && i + 1 < n && w[i + 1] >= 0x1161 && w[i + 1] <= 0x1175) {
            unsigned s = 0xAC00 + ((x - 0x1100) * 21 + w[i + 1] - 0x1161) * 28;
            i += 2;
            if (i < n && w[i] >= 0x11A8 && w[i] <= 0x11C2) s += w[i++] - 0x11A7;
            c[k++] = (uint16_t) s;
            continue;
        }
        c[k++] = (uint16_t) x;
        i++;
    }
    n = k;
    k = 0;
    for (i = 0; i < n; i++) {
        int done = 0;
        if (k) {
            for (unsigned j = 0; j < ncomp && !done; j++) {
                if (rd16(comp + 6 * j) == c[k - 1] && rd16(comp + 6 * j + 2) == c[i]) { c[k - 1] = (uint16_t) rd16(comp + 6 * j + 4); done = 1; }
            }
        }
        if (!done) c[k++] = c[i];
    }
    return k;
}

int wl_decode(const uint8_t *blob, size_t len, void *work, size_t worksize, char *out, size_t outcap, uint16_t *off, size_t offcap)
{
    unsigned nwords, nsym, nalpha, ncomp, hangul;
    const uint8_t *alpha, *comp;
    size_t need = wl_work_size(blob, len), o = 0, at = 0;
    model_t m;
    wl_rc rc;
    uint32_t f[ROWSYM];
    uint16_t prev[WORD_MAX], cur[WORD_MAX], tmp[WORD_MAX];
    unsigned plen = 0;

    if (!need || worksize < need || ((uintptr_t) work & 3)) return -1;
    nwords = rd16(blob);
    nsym = blob[2];
    hangul = blob[3] & 1;
    nalpha = blob[4];
    ncomp = blob[5];
    if (nalpha + 2 > nsym || offcap < (size_t) nwords + 1) return -1;
    alpha = blob + HDR;
    comp = alpha + 2 * nalpha;
    o = HDR + 2 * (size_t) nalpha + 6 * (size_t) ncomp;
    if (o > len || len - o < rd16(blob + 8)) return -1;
    wl_rc_init(&rc, blob + o, rd16(blob + 8));

    memset(work, 0, need);
    m.b = (base_t *) work;
    memset(m.b->rowidx, 0xFF, sizeof m.b->rowidx);
    m.rows = rd16(blob + 6);
    m.rc = (uint8_t (*)[ROWSYM]) (m.b + 1);
    m.rn = (uint16_t *) (m.rc + m.rows);
    m.nsym = nsym;
    m.pos = 0;
    m.h1 = m.h2 = nsym - 1;

    for (unsigned w = 0; w < nwords; w++) {
        unsigned s, lcp, clen;
        uint32_t total = freqs(&m, f);

        s = decode_sym(&rc, f, total, nsym);
        if (s >= nsym - 1 || s > plen || update(&m, s)) return -1;
        lcp = s;
        memcpy(cur, prev, lcp * sizeof cur[0]);
        clen = lcp;
        for (;;) {
            total = freqs(&m, f);
            s = decode_sym(&rc, f, total, nsym);
            if (update(&m, s)) return -1;
            if (s == nsym - 1) break;
            if (s == 0 || s > nalpha || clen >= WORD_MAX) return -1;
            cur[clen++] = (uint16_t) rd16(alpha + 2 * (s - 1));
        }
        memcpy(prev, cur, clen * sizeof cur[0]);
        plen = clen;
        if (at > 0xFFFF) return -1;
        off[w] = (uint16_t) at;
        clen = compose(cur, clen, hangul, comp, ncomp, tmp);
        for (unsigned i = 0; i < clen; i++) {
            size_t n = put_utf8(out, outcap, at, tmp[i]);
            if (!n) return -1;
            at += n;
        }
        if (at >= outcap) return -1;
        out[at++] = 0;
    }
    off[nwords] = (uint16_t) at;
    return (int) nwords;
}

int wl_merge(const char *atext, const uint16_t *aoff, int an, const uint8_t *mask, size_t masklen, const char *btext, const uint16_t *boff, int bn,
             char *out, size_t outcap, uint16_t *off, size_t offcap)
{
    int i = 0, j = 0, n = 0;
    size_t o = 0;
    const char *last = 0;

    if (an < 1 || bn < 0 || masklen < ((size_t) an + 7) / 8) return -1;
    for (;;) {
        const char *w;
        size_t l;
        while (i < an && !((mask[i >> 3] >> (i & 7)) & 1)) i++;
        if (i < an && (j >= bn || strcmp(atext + aoff[i], btext + boff[j]) < 0)) { w = atext + aoff[i]; l = (size_t) (aoff[i + 1] - aoff[i]); i++; }
        else if (j < bn) { w = btext + boff[j]; l = (size_t) (boff[j + 1] - boff[j]); j++; }
        else break;
        if ((last && strcmp(last, w) >= 0) || o + l > outcap || (size_t) n + 1 >= offcap || o > 0xFFFF) return -1;
        off[n++] = (uint16_t) o;
        memcpy(out + o, w, l);                                   /* the word and its 0 */
        last = out + o;
        o += l;
    }
    if (!n || o > 0xFFFF) return -1;
    off[n] = (uint16_t) o;
    return n;
}
