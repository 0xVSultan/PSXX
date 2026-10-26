#include "lz4.h"

int lz4_decompress(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap)
{
    const uint8_t *s = src, *end = src + srclen;
    uint8_t *d = dst, *dend = dst + dstcap;

    if (srclen == 0) return -1;
    for (;;) {
        if (s >= end) return -1;
        unsigned token = *s++;
        size_t n = token >> 4;
        if (n == 15) {
            unsigned b;
            do {
                if (s >= end) return -1;
                b = *s++;
                n += b;
            } while (b == 255);
        }
        if (n > (size_t)(end - s) || n > (size_t)(dend - d)) return -1;
        while (n--) *d++ = *s++;
        if (s == end) return (int)(d - dst);          /* last sequence: literals only */

        if (end - s < 2) return -1;
        size_t off = (size_t)s[0] | (size_t)s[1] << 8;
        s += 2;
        if (off == 0 || off > (size_t)(d - dst)) return -1;
        n = token & 15;
        if (n == 15) {
            unsigned b;
            do {
                if (s >= end) return -1;
                b = *s++;
                n += b;
            } while (b == 255);
        }
        n += 4;
        if (n > (size_t)(dend - d)) return -1;
        const uint8_t *m = d - off;
        while (n--) *d++ = *m++;
    }
}
