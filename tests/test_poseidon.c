/* Poseidon (Pallas, width 3): the fixed test vector of the pasta-hadeshash reference and random hashes from the Zcash reference
 * (tests/poseidon_vectors.txt, tools/gen_poseidon_vectors.py) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/poseidon.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/poseidon_vectors.txt", "r");
    char line[600];
    int total = 0, fails = 0;
    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[8];
        int nt = 0;
        for (char *s = strtok(line, " \r\n"); s && nt < 8; s = strtok(NULL, " \r\n")) tok[nt++] = s;
        if (nt == 7 && !strcmp(tok[0], "perm")) {
            uint8_t st[3][32], want[3][32];
            for (int i = 0; i < 3; i++) { unhex(tok[1 + i], st[i], 32); unhex(tok[4 + i], want[i], 32); }
            poseidon_perm(st);
            total++;
            if (memcmp(st, want, sizeof st)) { fails++; printf("FAIL perm\n"); }
        } else if (nt == 4 && !strcmp(tok[0], "hash")) {
            uint8_t x[32], y[32], want[32], got[32];
            unhex(tok[1], x, 32); unhex(tok[2], y, 32); unhex(tok[3], want, 32);
            poseidon_hash2(got, x, y);
            total++;
            if (memcmp(got, want, 32)) { fails++; printf("FAIL hash\n"); }
        }
    }
    fclose(f);
    printf("poseidon: %d checks, %d failed\n", total, fails);
    return fails != 0;
}
