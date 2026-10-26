/* The Sinsemilla table built in small steps (pl_stable_step) against the reference table (tests/sinsemilla_table.bin, made with the
 * reference code of the Zcash foundation by tools/gen_sinsemilla_table.py). The steps are taken with different sizes of work, to check that
 * stopping and going on anywhere does not change a point. Usage: test_stable <table.bin> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/pallas.h"

int main(int argc, char **argv)
{
    static uint8_t ref[65536];
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/sinsemilla_table.bin", "rb");
    int steps = 0, fails = 0, sizes[] = {1, 7, 50, 333}, si = 0;

    if (!f || fread(ref, 1, sizeof ref, f) != sizeof ref) { printf("cannot read the table\n"); return 2; }
    fclose(f);
    pl_stable_reset();
    while (pl_stable_built() < 1024) { pl_stable_step(sizes[si++ & 3]); steps++; }
    for (unsigned j = 0; j < 1024; j++) {
        uint8_t xy[64];
        if (pl_stable_get(j, xy) || memcmp(xy, ref + 64 * j, 64)) { fails++; if (fails < 5) printf("FAIL point %u\n", j); }
    }
    printf("sinsemilla table in steps: 1024 points, %d steps, %d wrong\n", steps, fails);
    {   /* points put in from outside first (as a note commitment does): the builder skips the complete groups and the result is the same */
        int before, steps2 = 0, fails2 = 0;
        unsigned seed = 99;
        pl_stable_reset();
        for (int round = 0; round < 40; round++) {
            unsigned ids[16];
            pl_pt pts[16];
            size_t n = 1 + (size_t) (round % 16);
            for (size_t i = 0; i < n; i++) {
                seed = seed * 1103515245u + 12345u;
                ids[i] = (seed >> 8) & 1023u;
                pl_from_affine(&pts[i], ref + 64 * ids[i], ref + 64 * ids[i] + 32);
            }
            pl_stable_add(ids, pts, n);
        }
        before = pl_stable_built();
        while (pl_stable_built() < 1024) { pl_stable_step(sizes[si++ & 3]); steps2++; }
        for (unsigned j = 0; j < 1024; j++) {
            uint8_t xy[64];
            if (pl_stable_get(j, xy) || memcmp(xy, ref + 64 * j, 64)) fails2++;
        }
        printf("with %d points put in first: %d steps (against %d), %d wrong\n", before, steps2, steps, fails2);
        fails += fails2;
    }
    return fails != 0;
}
