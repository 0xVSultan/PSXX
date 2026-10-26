/* Known-answer tests of the signature code: tests/sign_vectors.txt (tools/gen_sign_vectors.py, references: python-ecdsa and the
 * BIP340 reference algorithm). Usage: test_sign <path to sign_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "ec/ed25519.h"
#include "coin/substrate.h"

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
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/sign_vectors.txt", "r");
    static char line[8192];
    static uint8_t msg[2048];
    int ln = 0, fails = 0, total = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[8];
        size_t ml;
        int nt = 0;
        uint8_t a[64], b[64], c[64], d[64], got[80];

        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 8; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 2) continue;
        total++;
        if (!strcmp(tok[0], "ecdsa") && nt == 5) {
            int rec = -1;
            unhex(tok[1], a, 32); unhex(tok[2], b, 32); unhex(tok[3], c, 64);
            if (secp256k1_ecdsa_sign(got, &rec, a, b) || memcmp(got, c, 64) || rec != atoi(tok[4])) {
                fails++;
                printf("FAIL ecdsa line %d (recid %d, want %s)\n", ln, rec, tok[4]);
            } else {                                    /* the DER form: starts like a sequence and its length is right */
                int dl = secp256k1_sig_to_der(d, got);
                if (d[0] != 0x30 || d[1] != dl - 2 || dl < 8 || dl > 72) { fails++; printf("FAIL der line %d\n", ln); }
            }
        } else if (!strcmp(tok[0], "schnorr") && nt == 5) {
            unhex(tok[1], a, 32); unhex(tok[2], b, 32); unhex(tok[3], c, 32); unhex(tok[4], d, 64);
            if (secp256k1_schnorr_sign(got, a, c, b) || memcmp(got, d, 64)) { fails++; printf("FAIL schnorr line %d\n", ln); }
        } else if (!strcmp(tok[0], "tweak") && nt == 4) {
            ml = 0;
            unhex(tok[1], a, 32);
            if (strcmp(tok[2], "-")) ml = unhex(tok[2], b, 32);
            unhex(tok[3], c, 32);
            if (secp256k1_taproot_tweak_seckey(got, a, b, ml) || memcmp(got, c, 32)) { fails++; printf("FAIL tweak line %d\n", ln); }
        } else if (!strcmp(tok[0], "ed25519") && nt == 4) {
            unhex(tok[1], a, 32);
            ml = strcmp(tok[2], "-") ? unhex(tok[2], msg, sizeof msg) : 0;
            unhex(tok[3], d, 64);
            ed25519_sign(got, a, msg, ml);
            if (memcmp(got, d, 64)) { fails++; printf("FAIL ed25519 line %d\n", ln); }
        } else if (!strcmp(tok[0], "edext") && nt == 5) {
            unhex(tok[1], a, 32); unhex(tok[2], b, 32);
            ml = strcmp(tok[3], "-") ? unhex(tok[3], msg, sizeof msg) : 0;
            unhex(tok[4], d, 64);
            ed25519_scalarmult_base(c, a);
            ed25519_sign_scalar(got, a, b, c, msg, ml);
            if (memcmp(got, d, 64)) { fails++; printf("FAIL edext line %d\n", ln); }
        } else if (!strcmp(tok[0], "sr25519") && nt == 4) {
            unhex(tok[1], a, 32);
            ml = strcmp(tok[2], "-") ? unhex(tok[2], msg, sizeof msg) : 0;
            unhex(tok[3], d, 64);
            sr25519_expand(b, a);
            sr25519_sign(got, b, msg, ml);
            if (memcmp(got, d, 64)) { fails++; printf("FAIL sr25519 line %d\n", ln); }
        } else {
            total--;
        }
    }
    fclose(f);
    printf("SIGN %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
