/* The BIP340 verifier (core/ec/secp256k1.c): the vectors of tools/gen_schnorr_vectors.py (made with an independent Python implementation), and the signatures of our own signer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/secp256k1.h"

static int hexv(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t) v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/schnorr_vectors.txt", "r");
    char line[400], kind[8], a[80], b[80], c[140];
    int n = 0, bad = 0;

    if (!f) { printf("FAIL no vectors\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        uint8_t pub[32], msg[32], sig[64];
        int ok, rc;
        if (sscanf(line, "%7s %79s %79s %139s", kind, a, b, c) != 4) continue;
        if (hexv(a, pub, 32) || hexv(b, msg, 32) || hexv(c, sig, 64)) { printf("FAIL bad line %d\n", n); return 1; }
        ok = !strcmp(kind, "ok");
        rc = secp256k1_schnorr_verify(sig, msg, pub);
        if ((rc == 0) != ok) { printf("FAIL vector %d: wanted %s, got %d\n", n, kind, rc); bad++; }
        n++;
    }
    fclose(f);
    /* our own signer against our own verifier */
    for (int i = 0; i < 4; i++) {
        uint8_t sk[32], msg[32], pub[32], sig[64];
        memset(sk, 0, 32); sk[31] = (uint8_t) (i + 7); sk[0] = (uint8_t) (0x10 * i);
        memset(msg, i, 32);
        if (secp256k1_xonly_pubkey(pub, NULL, sk) || secp256k1_schnorr_sign(sig, sk, msg, NULL)) { printf("FAIL sign %d\n", i); bad++; continue; }
        if (secp256k1_schnorr_verify(sig, msg, pub)) { printf("FAIL own signature %d\n", i); bad++; }
        sig[5] ^= 0x40;
        if (!secp256k1_schnorr_verify(sig, msg, pub)) { printf("FAIL own signature %d with a flipped bit\n", i); bad++; }
        n += 2;
    }
    printf("schnorr verify: %d checks, %d bad\n", n, bad);
    return bad ? 1 : 0;
}
