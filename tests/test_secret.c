/* Known-answer tests for chain_secret(): tests/secret_vectors.txt (tools/gen_secret_vectors.py, references: bip_utils).
 * Usage: test_secret <path to secret_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/chains.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t) v;
    }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/secret_vectors.txt", "r");
    char line[1024];
    int ln = 0, fails = 0, total = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[8];
        int nt = 0;
        uint8_t b[64];
        hd_secret s;
        hd_path p;
        char out[400];
        const char *label;
        const chain_def *c;
        int r;

        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 8; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt != 5 && nt != 6) continue;
        total++;
        memset(&s, 0, sizeof s);
        memset(&p, 0, sizeof p);
        c = chain_find(tok[1]);
        if (!c) { fails++; printf("FAIL unknown chain %s (line %d)\n", tok[1], ln); continue; }
        if (!strcmp(tok[0], "secret") && nt == 5) {
            unhex(tok[2], b, 64);
            memcpy(s.seed, b, 64);
            if (path_parse(&p, tok[3])) { fails++; printf("FAIL path (line %d)\n", ln); continue; }
            r = chain_secret(out, sizeof out, &label, c, &s, &p, NULL);
            if (r < 0 || strcmp(out, tok[4])) { fails++; printf("FAIL %s (line %d) r=%d\n  got  %s\n  want %s\n", tok[1], ln, r, r < 0 ? "-" : out, tok[4]); }
        } else if (!strcmp(tok[0], "secrete") && nt == 6) {
            s.entlen = (int) unhex(tok[2], s.entropy, 32);
            s.passphrase = strcmp(tok[3], "-") ? tok[3] : "";
            if (c->curve == CV_SR25519) {
                r = chain_secret(out, sizeof out, &label, c, &s, &p, strcmp(tok[4], "_") ? tok[4] : "");
            } else {
                if (path_parse(&p, tok[4])) { fails++; printf("FAIL path (line %d)\n", ln); continue; }
                r = chain_secret(out, sizeof out, &label, c, &s, &p, NULL);
            }
            if (r < 0 || strcmp(out, tok[5])) { fails++; printf("FAIL %s (line %d) r=%d\n  got  %s\n  want %s\n", tok[1], ln, r, r < 0 ? "-" : out, tok[5]); }
        } else {
            total--;
        }
    }
    printf("secret keys: %d vectors, %d failures\n", total, fails);
    return fails != 0;
}
