/* The packed word lists (tools/wl_pack.py) decoded by core/wordlist/wl.c against the SHA-256 of the words that were packed (tests/wordlists.bin),
 * then the decoder fed with damaged blobs (it has to refuse or decode something, never write outside its buffers). Usage: test_wl <wordlists.bin> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash/sha256.h"
#include "wordlist/wl.h"

static uint8_t *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *b;

    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    *n = (size_t) ftell(f);
    fseek(f, 0, SEEK_SET);
    b = malloc(*n);
    if (b && fread(b, 1, *n, f) != *n) { free(b); b = 0; }
    fclose(f);
    return b;
}

int main(int argc, char **argv)
{
    size_t n, o = 0;
    uint8_t *all = slurp(argc > 1 ? argv[1] : "tests/wordlists.bin", &n);
    int lists = 0, fails = 0;
    static char out[1 << 17];
    static uint16_t off[4096];

    if (!all) { printf("cannot read the file\n"); return 2; }
    while (o < n) {
        unsigned nl = all[o++];
        char name[256];
        uint32_t bl;
        const uint8_t *blob;
        size_t wsz;
        void *work;
        int nw;
        uint8_t h[32];

        memcpy(name, all + o, nl); name[nl] = 0; o += nl;
        memcpy(&bl, all + o, 4); o += 4;
        blob = all + o; o += bl;
        wsz = wl_work_size(blob, bl);
        work = malloc(wsz + 4);
        nw = wl_decode(blob, bl, work, wsz, out, sizeof out, off, 4096);
        if (nw < 0) { printf("FAIL %s: decode error\n", name); fails++; }
        else {
            sha256((const uint8_t *) out, off[nw], h);
            if (memcmp(h, all + o, 32)) { printf("FAIL %s: the words differ (%d words)\n", name, nw); fails++; }
            else if (lists % 5 == 0) printf("ok %-20s %d words, first \"%s\", last \"%s\", work memory %u bytes\n", name, nw, out + off[0], out + off[nw - 1], (unsigned) wsz);
        }
        o += 32;
        lists++;
        if (nw > 0) {                                  /* damaged copies of the blob */
            uint8_t *bad = malloc(bl);
            unsigned seed = 12345;
            for (int i = 0; i < 300; i++) {
                size_t l = bl;
                memcpy(bad, blob, bl);
                seed = seed * 1103515245u + 12345u;
                if (i % 3 == 0) l = (seed >> 8) % bl;                                  /* cut short */
                else for (int k = 0; k < 1 + i % 4; k++) { seed = seed * 1103515245u + 12345u; bad[(seed >> 8) % bl] ^= (uint8_t) (1u << (seed % 8)); }
                {
                    size_t w2 = wl_work_size(bad, l);
                    void *wk = malloc(w2 + 4);
                    if (w2 && wk) (void) wl_decode(bad, l, wk, w2, out, sizeof out, off, 4096);
                    free(wk);
                }
            }
            free(bad);
        }
        free(work);
    }
    printf("word lists: %d decoded, %d wrong, damaged blobs survived\n", lists, fails);
    free(all);
    return fails != 0 || lists == 0;
}
