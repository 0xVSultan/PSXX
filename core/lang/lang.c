#include "lang/lang.h"
#include "wordlist/wl.h"
#include <string.h>

static uint16_t le16(const uint8_t *p) { return (uint16_t) (p[0] | p[1] << 8); }

int lang_index(const uint8_t *raw, size_t len, lang_info *out, int max)
{
    int n;

    if (len < 1) return -1;
    n = raw[0];
    if (n > max || len < 1 + (size_t) n * 32) return -1;
    for (int i = 0; i < n; i++) {
        const uint8_t *r = raw + 1 + 32 * i;
        out[i].id = r[0]; out[i].flags = r[1]; out[i].glyphs = r[2]; out[i].xmr_prefix = r[3];
        out[i].bip_group = le16(r + 4); out[i].xmr_group = le16(r + 6);
        out[i].separator = r[8];
        out[i].ui_group = le16(r + 9);
        memcpy(out[i].name, r + 12, 16);
        out[i].name[16] = 0;
    }
    return n;
}

/* ---- glyph sets ---- */

unsigned glyphset_count(const uint8_t *raw, size_t len)
{
    return len >= 6 ? le16(raw + 4) : 0;
}

int glyphset_open(glyphset *g, const uint8_t *raw, size_t len, uint16_t *cps)
{
    size_t o = 6, per;
    unsigned n;

    if (len < 8 || raw[3] != 0) return -1;
    g->w = raw[0]; g->h = raw[1]; g->fmt = raw[2];
    n = le16(raw + 4);
    if (!n || g->h > 18 || g->w > 16 || (g->fmt > 1) || (g->fmt == 1 && (g->w != 16 || g->h != 16))) return -1;
    g->n = (uint16_t) n;
    g->cps = cps;
    cps[0] = le16(raw + o);
    o += 2;
    for (unsigned i = 1; i < n; i++) {
        unsigned d;
        if (o >= len) return -1;
        d = raw[o++];
        if (d == 255) { if (o + 2 > len) return -1; d = le16(raw + o); o += 2; }
        if (!d || cps[i - 1] + d > 0xFFFF) return -1;
        cps[i] = (uint16_t) (cps[i - 1] + d);
    }
    per = g->fmt ? 32u : (size_t) g->h * 2;
    if (len < o + per * n) return -1;
    g->bits = raw + o;
    return 0;
}

int glyphset_find(const glyphset *g, unsigned cp)
{
    int lo = 0, hi = (int) g->n - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g->cps[mid] == cp) return mid;
        if (g->cps[mid] < cp) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}

void glyphset_rows(const glyphset *g, int idx, uint16_t rows[18])
{
    if (g->fmt == 0) {
        const uint8_t *b = g->bits + (size_t) idx * g->h * 2;
        for (int y = 0; y < g->h; y++) rows[y] = le16(b + 2 * y);
    } else {
        const uint8_t *b = g->bits + (size_t) idx * 32;                    /* 16 upper bytes, 16 lower bytes, one per column */
        for (int y = 0; y < 16; y++) {
            uint16_t r = 0;
            for (int x = 0; x < 16; x++) {
                unsigned col = (unsigned) b[x] << 8 | b[16 + x];
                r = (uint16_t) (r | (((col >> (15 - y)) & 1u) << (15 - x)));
            }
            rows[y] = r;
        }
    }
}

/* ---- the Chinese lists ---- */

static size_t put_utf8(char *o, unsigned cp)
{
    if (cp < 0x80) { o[0] = (char) cp; return 1; }
    if (cp < 0x800) { o[0] = (char) (0xC0 | cp >> 6); o[1] = (char) (0x80 | (cp & 63)); return 2; }
    o[0] = (char) (0xE0 | cp >> 12); o[1] = (char) (0x80 | ((cp >> 6) & 63)); o[2] = (char) (0x80 | (cp & 63));
    return 3;
}

static int bit_of(const uint8_t *m, unsigned i) { return (m[i >> 3] >> (i & 7)) & 1; }

int lang_zh_simplified(const glyphset *hanzi, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap, uint16_t *sel)
{
    wl_rc r;
    unsigned c[2] = {0, 0}, nsel = 0;
    size_t o = 0;

    if (offcap < 2049 || cap < 2048 * 4) return -1;
    wl_rc_init(&r, map, len);
    for (unsigned i = 0; i < hanzi->n; i++)                                 /* the glyphs the list uses, ascending */
        if (wl_rc_bit(&r, c)) { if (nsel >= 2048) return -1; sel[nsel++] = (uint16_t) i; }
    if (nsel != 2048) return -1;
    wl_rc_shuffle(&r, sel, 2048);                                           /* now in the order of the words */
    for (int w = 0; w < 2048; w++) {
        off[w] = (uint16_t) o;
        o += put_utf8(out + o, hanzi->cps[sel[w]]);
        out[o++] = 0;
    }
    off[2048] = (uint16_t) o;
    return 2048;
}

int lang_zh_traditional(const glyphset *hanzi, const char *stext, const uint16_t *soff, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap,
                        uint16_t *work)
{
    uint8_t *used = (uint8_t *) (work + hanzi->n);
    unsigned k = 0, j = 0, c[2] = {0, 0};
    size_t o = 0;
    wl_rc r;

    if (offcap < 2049 || cap < 2048 * 4) return -1;
    memset(used, 0, ((size_t) hanzi->n + 7) / 8);
    for (int w = 0; w < 2048; w++) {                                        /* the glyphs of the simplified words (one character each) */
        const unsigned char *u = (const unsigned char *) stext + soff[w];
        int gi = glyphset_find(hanzi, (u[0] & 15u) << 12 | (u[1] & 63u) << 6 | (u[2] & 63u));
        if (gi < 0) return -1;
        used[gi >> 3] |= (uint8_t) (1u << (gi & 7));
    }
    for (unsigned i = 0; i < hanzi->n; i++) if (!bit_of(used, i)) work[k++] = (uint16_t) i;
    wl_rc_init(&r, map, len);
    wl_rc_shuffle(&r, work, k);                                             /* the others, in the order of the words that differ */
    for (int w = 0; w < 2048; w++) {
        off[w] = (uint16_t) o;
        if (wl_rc_bit(&r, c)) {
            if (j >= k) return -1;
            o += put_utf8(out + o, hanzi->cps[work[j++]]);
            out[o++] = 0;
        } else {
            size_t l = (size_t) (soff[w + 1] - soff[w]);
            memcpy(out + o, stext + soff[w], l);
            o += l;
        }
    }
    if (j != k) return -1;
    off[2048] = (uint16_t) o;
    return 2048;
}

int lang_zh_monero(const char *stext, const uint16_t *soff, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap)
{
    wl_rc r;
    unsigned c[2] = {0, 0};
    size_t o = 0;
    int n = 0;

    if (cap < 2048 * 4 || offcap < 2049) return -1;
    wl_rc_init(&r, map, len);
    for (int w = 0; w < 2048; w++) {
        size_t l;
        if (!wl_rc_bit(&r, c)) continue;
        l = (size_t) (soff[w + 1] - soff[w]);
        off[n++] = (uint16_t) o;
        memcpy(out + o, stext + soff[w], l);
        o += l;
    }
    off[n] = (uint16_t) o;
    return n;
}

size_t lang_xmr_subset_size(const uint16_t *soff, int sn, const uint8_t *map, size_t len)
{
    size_t o = 0;

    if (sn < 1 || len < ((size_t) sn + 7) / 8) return 0;
    for (int w = 0; w < sn; w++) if (bit_of(map, (unsigned) w)) o += (size_t) (soff[w + 1] - soff[w]);
    return o;
}

int lang_xmr_subset(const char *stext, const uint16_t *soff, int sn, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap)
{
    size_t o = 0;
    int n = 0;

    if (sn < 1 || len < ((size_t) sn + 7) / 8) return -1;
    for (int w = 0; w < sn; w++) {
        size_t l;
        if (!bit_of(map, (unsigned) w)) continue;
        l = (size_t) (soff[w + 1] - soff[w]);
        if (o + l > cap || (size_t) n + 1 >= offcap) return -1;
        off[n++] = (uint16_t) o;
        memcpy(out + o, stext + soff[w], l);
        o += l;
    }
    if (!n) return -1;
    off[n] = (uint16_t) o;
    return n;
}

/* ---- mnemonics ---- */

#include "hash/sha256.h"
#include "hash/crc32.h"

int lang_bip39_indexes(const uint8_t *entropy, size_t len, uint16_t idx[24])
{
    uint8_t buf[33], h[32];
    unsigned bits = (unsigned) len * 8, cs = bits / 32, total = bits + cs;

    if (len < 16 || len > 32 || len % 4) return -1;
    sha256(entropy, len, h);
    memcpy(buf, entropy, len);
    buf[len] = h[0];                                                       /* the checksum has at most 8 bits */
    for (unsigned w = 0; w < total / 11; w++) {
        unsigned v = 0;
        for (unsigned b = 0; b < 11; b++) {
            unsigned at = w * 11 + b;
            v = v << 1 | ((buf[at >> 3] >> (7 - (at & 7))) & 1u);
        }
        idx[w] = (uint16_t) v;
    }
    return (int) (total / 11);
}

int lang_xmr_indexes(const words_list *wl, int prefix, const uint8_t key[32], uint16_t idx[25])
{
    uint32_t n = (uint32_t) wl->n;
    uint8_t cat[24 * 4 * 3];
    size_t o = 0;

    if (n < 2 || n > 4096 || prefix < 1 || prefix > 4) return -1;
    for (int g = 0; g < 8; g++) {
        uint32_t v = (uint32_t) key[4 * g] | (uint32_t) key[4 * g + 1] << 8 | (uint32_t) key[4 * g + 2] << 16 | (uint32_t) key[4 * g + 3] << 24;
        uint32_t w1 = v % n, w2 = (v / n + w1) % n, w3 = (v / n / n + w2) % n;
        idx[3 * g] = (uint16_t) w1; idx[3 * g + 1] = (uint16_t) w2; idx[3 * g + 2] = (uint16_t) w3;
    }
    for (int i = 0; i < 24; i++) {                                         /* the first `prefix` characters (UTF-8) of every word */
        const uint8_t *w = (const uint8_t *) wl->text + wl->off[idx[i]];
        for (int c = 0; c < prefix && *w; c++) {
            cat[o++] = *w++;
            while ((*w & 0xC0) == 0x80) cat[o++] = *w++;
        }
    }
    idx[24] = idx[crc32(cat, o) % 24];
    return 25;
}

int lang_xmr_decode(const words_list *wl, int prefix, const uint16_t idx[25], uint8_t key[32])
{
    uint64_t n = (uint64_t) wl->n;
    uint8_t cat[24 * 4 * 3], k[32];
    size_t o = 0;

    if (n < 2 || n > 4096 || prefix < 1 || prefix > 4) return -1;
    for (int i = 0; i < 25; i++) if (idx[i] >= n) return -1;
    for (int g = 0; g < 8; g++) {
        uint64_t w1 = idx[3 * g], w2 = idx[3 * g + 1], w3 = idx[3 * g + 2];
        uint64_t v = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n);
        if (v > 0xFFFFFFFFu) return -1;                                    /* not the encoding of four bytes */
        k[4 * g] = (uint8_t) v; k[4 * g + 1] = (uint8_t) (v >> 8); k[4 * g + 2] = (uint8_t) (v >> 16); k[4 * g + 3] = (uint8_t) (v >> 24);
    }
    for (int i = 0; i < 24; i++) {
        const uint8_t *w = (const uint8_t *) wl->text + wl->off[idx[i]];
        for (int c = 0; c < prefix && *w; c++) {
            cat[o++] = *w++;
            while ((*w & 0xC0) == 0x80) cat[o++] = *w++;
        }
    }
    if (idx[24] != idx[crc32(cat, o) % 24]) return -1;                      /* the checksum word */
    memcpy(key, k, 32);
    return 0;
}

int lang_join(const words_list *wl, const uint16_t *idx, int n, int separator, char *out, size_t cap)
{
    size_t o = 0;

    for (int i = 0; i < n; i++) {
        size_t l = (size_t) (wl->off[idx[i] + 1] - wl->off[idx[i]]) - 1;
        if (o + l + 4 > cap) return -1;
        if (i) { if (separator) { out[o++] = (char) 0xE3; out[o++] = (char) 0x80; out[o++] = (char) 0x80; } else out[o++] = ' '; }
        memcpy(out + o, wl->text + wl->off[idx[i]], l);
        o += l;
    }
    out[o] = 0;
    return (int) o;
}
