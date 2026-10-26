/* ChaCha20-Poly1305 against tests/chacha_vectors.txt (tools/gen_chacha_vectors.py, from the cryptography package) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash/chacha20poly1305.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (!strcmp(s, "-")) return 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/chacha_vectors.txt", "r");
    static char line[4000];
    int total = 0, fails = 0, ln = 0;
    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[6];
        int nt = 0;
        uint8_t key[32], nonce[12], pt[700], ct[720], got[720], back[700];
        size_t pl, cl;
        ln++;
        for (char *s = strtok(line, " \r\n"); s && nt < 6; s = strtok(NULL, " \r\n")) tok[nt++] = s;
        if (nt != 5) continue;
        unhex(tok[1], key, 32); unhex(tok[2], nonce, 12);
        pl = unhex(tok[3], pt, sizeof pt);
        cl = unhex(tok[4], ct, sizeof ct);
        chacha20poly1305_encrypt(got, key, nonce, pt, pl);
        total++;
        if (cl != pl + 16 || memcmp(got, ct, cl)) { fails++; printf("FAIL encrypt (line %d)\n", ln); }
        total++;
        if (chacha20poly1305_decrypt(back, key, nonce, ct, cl) || memcmp(back, pt, pl)) { fails++; printf("FAIL decrypt (line %d)\n", ln); }
        ct[cl - 1] ^= 1;
        total++;
        if (!chacha20poly1305_decrypt(back, key, nonce, ct, cl)) { fails++; printf("FAIL tag check (line %d)\n", ln); }
    }
    fclose(f);
    printf("chacha20poly1305: %d checks, %d failed\n", total, fails);
    return fails != 0;
}
