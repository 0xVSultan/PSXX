#include "langin.h"
#include <string.h>
#include "nfkd.h"
#include "hash/sha256.h"

/* the compatibility jamo of the lead (19) and the trail (27, from 1) consonants of a Hangul syllable; the vowels are U+314F + their number */
static const uint16_t LEAD[19] = {0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145, 0x3146, 0x3147, 0x3148, 0x3149, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};
static const uint16_t TRAIL[27] = {0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313A, 0x313B, 0x313C, 0x313D, 0x313E, 0x313F, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145, 0x3146,
                                   0x3147, 0x3148, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};

static int next(const unsigned char **s, unsigned *cp)
{
    unsigned c = **s;

    if (c < 0x80) { *cp = c; *s += 1; return 0; }
    if ((c & 0xE0) == 0xC0 && ((*s)[1] & 0xC0) == 0x80) { *cp = (c & 31) << 6 | ((*s)[1] & 63); *s += 2; return 0; }
    if ((c & 0xF0) == 0xE0 && ((*s)[1] & 0xC0) == 0x80 && ((*s)[2] & 0xC0) == 0x80) { *cp = (c & 15) << 12 | ((*s)[1] & 63) << 6 | ((*s)[2] & 63); *s += 3; return 0; }
    return -1;
}

int langin_key(int mode, const char *word, uint8_t *out, int cap)
{
    const unsigned char *s = (const unsigned char *) word;
    unsigned cp;
    int n = 0;

    memset(out, 0, (size_t) cap);
    if (mode == LANGIN_LATIN) {
        char d[64];
        const unsigned char *t = (const unsigned char *) d;

        if (lang_nfkd(word, d, sizeof d) == (size_t) -1) return -1;
        while (*t && n < LANGIN_KEYMAX) {
            if (next(&t, &cp)) return -1;
            if (cp >= 0x300 && cp < 0x370) continue;                       /* the accents */
            if (cp == '\'') continue;                                       /* Lojban's apostrophe: not on the keyboard of the words, not part of the key */
            if (cp >= 'A' && cp <= 'Z') cp += 32;
            if (cp < 0x80) out[n++] = (uint8_t) cp;
            else { char u[4]; int k = (int) (cp < 0x800 ? 2 : 3); u[0] = (char) (cp < 0x800 ? 0xC0 | cp >> 6 : 0xE0 | cp >> 12);
                   if (cp < 0x800) u[1] = (char) (0x80 | (cp & 63)); else { u[1] = (char) (0x80 | ((cp >> 6) & 63)); u[2] = (char) (0x80 | (cp & 63)); }
                   if (n + k > LANGIN_KEYMAX) break;
                   for (int i = 0; i < k; i++) out[n++] = (uint8_t) u[i]; }
        }
        return n;
    }
    if (mode == LANGIN_KANA) {
        for (int c = 0; *s && c < 6; c++) {
            const unsigned char *b = s;
            if (next(&s, &cp)) return -1;
            while (b < s && n < LANGIN_KEYMAX) out[n++] = *b++;
        }
        return n;
    }
    while (*s && n < 12) {                                                 /* Hangul */
        if (next(&s, &cp)) return -1;
        if (cp >= 0xAC00 && cp <= 0xD7A3) {
            unsigned si = cp - 0xAC00;
            out[n++] = (uint8_t) (LEAD[si / 588] - 0x3131 + 1);
            if (n < 12) out[n++] = (uint8_t) (0x314F + si % 588 / 28 - 0x3131 + 1);
            if (si % 28 && n < 12) out[n++] = (uint8_t) (TRAIL[si % 28 - 1] - 0x3131 + 1);
        } else if (cp >= 0x3131 && cp <= 0x3163) {
            out[n++] = (uint8_t) (cp - 0x3131 + 1);
        } else return -1;
    }
    return n;
}

int langin_jamo_utf8(int code, char out[4])
{
    unsigned cp = 0x3131u + (unsigned) code - 1;

    if (code < 1 || code > 51) return -1;
    out[0] = (char) (0xE0 | cp >> 12); out[1] = (char) (0x80 | ((cp >> 6) & 63)); out[2] = (char) (0x80 | (cp & 63)); out[3] = 0;
    return 3;
}

int langin_find(const uint8_t *keys, int stride, int n, const uint8_t *typed, int tl, int from, int max, uint16_t *out)
{
    int total = 0;

    if (tl < 1 || tl > stride) return 0;
    for (int i = 0; i < n; i++) {
        if (memcmp(keys + (size_t) i * (size_t) stride, typed, (size_t) tl)) continue;
        if (total >= from && total - from < max) out[total - from] = (uint16_t) i;
        total++;
    }
    return total;
}

int langin_bip39_entropy(const uint16_t *idx, int n, uint8_t ent[32])
{
    uint8_t buf[33], h[32];
    int bits = n * 11, el;

    if (n < 12 || n > 24 || n % 3) return -1;
    el = bits * 32 / 33 / 8;                                               /* 12 -> 16, 15 -> 20, ... 24 -> 32 */
    memset(buf, 0, sizeof buf);
    for (int w = 0; w < n; w++) {
        if (idx[w] > 2047) return -1;
        for (int b = 0; b < 11; b++) {
            int at = w * 11 + b;
            if ((idx[w] >> (10 - b)) & 1) buf[at >> 3] |= (uint8_t) (0x80 >> (at & 7));
        }
    }
    sha256(buf, (size_t) el, h);
    {
        int cs = bits - el * 8;
        uint8_t mask = (uint8_t) (0xFF00u >> cs);
        if ((buf[el] & mask) != (h[0] & mask)) return -1;
    }
    memcpy(ent, buf, (size_t) el);
    return el;
}

int langin_sentence(const words_list *wl, const uint16_t *idx, int n, char *out, size_t cap)
{
    size_t o = 0;
    char w[96];

    for (int i = 0; i < n; i++) {
        size_t l = (size_t) (wl->off[idx[i] + 1] - wl->off[idx[i]]) - 1, d;
        if (idx[i] >= wl->n || l >= sizeof w) return -1;
        memcpy(w, wl->text + wl->off[idx[i]], l);
        w[l] = 0;
        if (i && o + 1 < cap) out[o++] = ' ';
        d = lang_nfkd(w, out + o, cap - o);
        if (d == (size_t) -1) return -1;
        o += d;
    }
    if (n == 0 && cap) out[0] = 0;
    return (int) o;
}
