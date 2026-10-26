#pragma once
/* LZ4 block decoder without any checks, for trusted data: the self-extracting stub (tools/stub/lz4stub.c) and the
 * checked decoder's tests share this exact loop. Header only, no libc.
 *
 * Copies run forward byte by byte, so the compressed stream may overlap the end of the output ("in place"
 * decompression) as long as the packer has verified the margin (tools/packexe.py does). */
#include <stdint.h>

/* Decode the sequences in [s, end) to d. Returns a pointer past the last output byte. */
static inline uint8_t *lz4_unpack_unchecked(const uint8_t *s, const uint8_t *end, uint8_t *d)
{
    for (;;) {
        unsigned token = *s++;
        unsigned n = token >> 4;
        if (n == 15) {
            unsigned b;
            do { b = *s++; n += b; } while (b == 255);
        }
        while (n--) *d++ = *s++;
        if (s >= end) return d;                       /* the last sequence only has literals */
        unsigned off = (unsigned)s[0] | (unsigned)s[1] << 8;
        s += 2;
        n = token & 15;
        if (n == 15) {
            unsigned b;
            do { b = *s++; n += b; } while (b == 255);
        }
        n += 4;
        const uint8_t *m = d - off;
        while (n--) *d++ = *m++;
    }
}
