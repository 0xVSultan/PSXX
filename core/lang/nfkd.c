#include "nfkd.h"
#include "nfkd_tab.h"

static size_t put(char *o, unsigned cp)
{
    if (cp < 0x80) { o[0] = (char) cp; return 1; }
    if (cp < 0x800) { o[0] = (char) (0xC0 | cp >> 6); o[1] = (char) (0x80 | (cp & 63)); return 2; }
    o[0] = (char) (0xE0 | cp >> 12); o[1] = (char) (0x80 | ((cp >> 6) & 63)); o[2] = (char) (0x80 | (cp & 63));
    return 3;
}

static int get(const unsigned char **s, unsigned *cp)
{
    unsigned c = **s;

    if (c < 0x80) { *cp = c; *s += 1; return 0; }
    if ((c & 0xE0) == 0xC0 && ((*s)[1] & 0xC0) == 0x80) { *cp = (c & 31) << 6 | ((*s)[1] & 63); *s += 2; return 0; }
    if ((c & 0xF0) == 0xE0 && ((*s)[1] & 0xC0) == 0x80 && ((*s)[2] & 0xC0) == 0x80) { *cp = (c & 15) << 12 | ((*s)[1] & 63) << 6 | ((*s)[2] & 63); *s += 3; return 0; }
    return -1;                                                          /* not UTF-8, or beyond the BMP: the lists have neither */
}

size_t lang_nfkd(const char *in, char *out, size_t cap)
{
    const unsigned char *s = (const unsigned char *) in;
    size_t o = 0;
    unsigned cp;

    while (*s) {
        unsigned d[3];
        int n = 1;

        if (get(&s, &cp)) return (size_t) -1;
        d[0] = cp;
        if (cp >= 0xAC00 && cp <= 0xD7A3) {                             /* a Hangul syllable: lead, vowel, and a trail if there is one */
            unsigned si = cp - 0xAC00;
            d[0] = 0x1100 + si / 588;
            d[1] = 0x1161 + si % 588 / 28;
            n = 2;
            if (si % 28) d[n++] = 0x11A7 + si % 28;
        } else if (cp == 0x3000) {
            d[0] = ' ';
        } else if (cp >= 0xC0) {
            int lo = 0, hi = NFKD_N - 1;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (NFKD_CP[mid] == cp) {
                    n = NFKD_OFF[mid + 1] - NFKD_OFF[mid];
                    for (int i = 0; i < n; i++) d[i] = NFKD_SEQ[NFKD_OFF[mid] + i];
                    break;
                }
                if (NFKD_CP[mid] < cp) lo = mid + 1; else hi = mid - 1;
            }
        }
        for (int i = 0; i < n; i++) {
            if (o + 4 > cap) return (size_t) -1;
            o += put(out + o, d[i]);
        }
    }
    if (o + 1 > cap) return (size_t) -1;
    out[o] = 0;
    return o;
}
