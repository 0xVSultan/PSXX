/* The loading of an overlay (core/pkg/ovl.c) against tests/ovl_vectors.txt (tools/gen_ovl_vectors.py): the good ones come out in the region exactly as packed (the hash of the unpacked
 * image, the bss cleared, the bytes between left alone), the refused ones give the answer in the line and have not touched the region below the staged bytes. The vectors with ranges
 * (slots and pockets) are checked for the same, and for nothing at all having been written outside the image, the bss and the staged bytes. A vector with a dictionary gives it
 * to the loader as the image of the base (codec 2, packed against it with liblzma: the test of the decoder's preset dictionary).
 * Usage: test_ovl <ovl_vectors.txt> */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash/sha256.h"
#include "pkg/ovl.h"

typedef struct { const uint8_t *d; uint32_t n; } mem;

static int mem_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t len)
{
    const mem *m = ctx;
    if ((uint64_t) off + len > m->n) return -1;
    memcpy(buf, m->d + off, len);
    return 0;
}

static int code_of(const char *s)
{
    static const struct { const char *n; int c; } T[] = {{"OK", OVL_OK}, {"PKG", OVL_ERR_PKG}, {"BASE", OVL_ERR_BASE}, {"GROUP", OVL_ERR_GROUP}, {"CODEC", OVL_ERR_CODEC},
        {"OVERLAY", OVL_ERR_OVERLAY}, {"LAYOUT", OVL_ERR_LAYOUT}};
    for (unsigned i = 0; i < sizeof T / sizeof T[0]; i++) if (!strcmp(T[i].n, s)) return T[i].c;
    return 99;
}

static int unhex(const char *s, uint8_t *out, size_t max)
{
    size_t n = 0;
    while (isxdigit((unsigned char) s[0]) && isxdigit((unsigned char) s[1])) {
        char t[3] = {s[0], s[1], 0};
        if (n >= max) return -1;
        out[n++] = (uint8_t) strtoul(t, NULL, 16);
        s += 2;
    }
    return (int) n;
}

static int all_is(const uint8_t *p, size_t n, uint8_t v) { for (size_t i = 0; i < n; i++) if (p[i] != v) return 0; return 1; }

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/ovl_vectors.txt", "r");
    static char *line;
    static uint16_t probs[OVL_PROBS];
    int total = 0, fails = 0;
    size_t cap = 1 << 20;

    if (!f) { printf("cannot read the vectors\n"); return 2; }
    line = malloc(cap);
    while (fgets(line, (int) cap, f)) {
        char *fld[9], *s = line;
        unsigned rg[6] = {0, 0, 0, 0, 0, 0};
        int ranged = 0;
        uint8_t base[32], pin[32], *pk, *dict = NULL;
        char *dhex = NULL;
        uint32_t lo, hi, span;
        int group, want, n, rc, detail = 0;
        pkg p;
        mem m;
        ovl_region r;
        ovl_info ov;
        uint8_t *region;
        uint32_t stage_virt = 0;

        if (line[0] == '#' || line[0] == '\n') continue;
        for (int i = 0; i < 9; i++) { fld[i] = s; s = strchr(s, '|'); if (s) *s++ = 0; else if (i < 8) { printf("bad line\n"); return 2; } }
        lo = (uint32_t) strtoul(fld[1], NULL, 10);
        hi = (uint32_t) strtoul(fld[2], NULL, 10);
        group = atoi(fld[5]);
        want = code_of(fld[6]);
        if (unhex(fld[3], base, 32) != 32 || unhex(fld[4], pin, 32) != 32) { printf("bad hex in %s\n", fld[0]); return 2; }
        pk = malloc(strlen(fld[8]) / 2 + 1);
        n = unhex(fld[8], pk, strlen(fld[8]) / 2 + 1);
        m = (mem) {pk, (uint32_t) n};
        total++;
        rc = pkg_open(&p, mem_read, &m, m.n, PKG_KIND_OVERLAY, pin);
        if (rc) { printf("FAIL %s: the package does not open: %d\n", fld[0], rc); fails++; free(pk); continue; }

        span = hi - lo;
        region = malloc(span);
        memset(region, 0xAA, span);
        if (s && (dhex = strchr(s, '|')) != NULL) *dhex++ = 0;                        /* the ranges (or -), then the dictionary */
        if (s && *s != '-' && sscanf(s, "%u,%u,%u,%u,%u,%u", rg, rg + 1, rg + 2, rg + 3, rg + 4, rg + 5) == 6) ranged = 1;
        r = (ovl_region) {.virt_lo = lo, .virt_hi = hi, .mem = region};
        if (ranged) { r.code_lo = rg[0]; r.code_hi = rg[1]; r.bss_lo = rg[2]; r.bss_hi = rg[3]; r.stage_lo = rg[4]; r.stage_hi = rg[5]; }
        if (dhex) {
            dict = malloc(strlen(dhex) / 2 + 1);
            r.dict = dict;
            r.dict_len = (uint32_t) unhex(dhex, dict, strlen(dhex) / 2 + 1);
        }
        rc = ovl_load(&p, (uint16_t) group, base, &r, probs, &ov, &detail);
        if (rc != want) printf("FAIL %s: gave %d (detail %d), wanted %s\n", fld[0], rc, detail, fld[6]), fails++;
        else {
            const pkg_group *g = pkg_find(&p, (uint16_t) group);
            if (g) stage_virt = (ranged ? rg[5] : hi) - ((g->len + 15) & ~15u);
            if (ranged) {                                                               /* only the image, the bss and the staged bytes may have been written */
                uint32_t sv_end = rg[5], il = 0, ie = 0, bl = 0, be = 0;
                if (rc == OVL_OK) {
                    uint8_t h[32], expect[32];
                    sha256(region + (ov.load - lo), ov.size, h);
                    unhex(fld[7], expect, 32);
                    if (memcmp(h, expect, 32)) { printf("FAIL %s: the unpacked image is not the packed one\n", fld[0]); fails++; }
                    if (!all_is(region + (ov.bss - lo), ov.bss_size, 0)) { printf("FAIL %s: the bss is not cleared\n", fld[0]); fails++; }
                    il = ov.load; ie = ov.load + ov.size; bl = ov.bss; be = ov.bss + ov.bss_size;
                }
                for (uint32_t a = lo; a < hi; a++) {
                    int allowed = (a >= il && a < ie) || (a >= bl && a < be) || (g && a >= stage_virt && a < sv_end);
                    if (!allowed && region[a - lo] != 0xAA) { printf("FAIL %s: byte %08x outside the image, the bss and the staged bytes was written\n", fld[0], (unsigned) a); fails++; break; }
                }
            } else if (rc == OVL_OK) {
                uint8_t h[32], expect[32];
                uint32_t gap_end = ov.bss < stage_virt ? ov.bss : stage_virt;
                sha256(region + (ov.load - lo), ov.size, h);
                unhex(fld[7], expect, 32);
                if (memcmp(h, expect, 32)) { printf("FAIL %s: the unpacked image is not the packed one\n", fld[0]); fails++; }
                if (!all_is(region + (ov.bss - lo), ov.bss_size, 0)) { printf("FAIL %s: the bss is not cleared\n", fld[0]); fails++; }
                if (ov.load + ov.size < gap_end && !all_is(region + (ov.load + ov.size - lo), gap_end - (ov.load + ov.size), 0xAA)) { printf("FAIL %s: bytes between the image and the bss were changed\n", fld[0]); fails++; }
                if (ov.load > lo && !all_is(region, ov.load - lo, 0xAA)) { printf("FAIL %s: bytes below the image were changed\n", fld[0]); fails++; }
            } else {
                size_t below = g && rc != OVL_ERR_GROUP && rc != OVL_ERR_BASE ? stage_virt - lo : span;     /* a refused overlay leaves everything below the staged bytes alone */
                if (g && stage_virt < lo) below = 0;
                if (!all_is(region, below, 0xAA)) { printf("FAIL %s: a refused overlay changed the region below the staged bytes\n", fld[0]); fails++; }
            }
        }
        free(region);
        free(pk);
        free(dict);
    }
    fclose(f);
    free(line);
    printf("overlay loader: %d vectors, %d wrong\n", total, fails);
    return fails != 0;
}
