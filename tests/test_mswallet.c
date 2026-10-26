/* Multisig wallet policies (core/sign/mswallet.c, core/ec/secp_pub.c): the child of a public key, the descriptors and the scripts of their addresses against the
 * reference (tests/ms_vectors.txt, tools/gen_ms_vectors.py), the refusals, the card record and its MAC.
 * Usage: test_mswallet <path to ms_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/mswallet.h"
#include "ec/secp_pub.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (!strcmp(s, "-")) return 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t) v;
    }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/ms_vectors.txt", "r");
    static char line[20000];
    char *tok[200];
    int ln = 0, fails = 0, total = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        int nt = 0;

        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 200; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 2) continue;
        total++;
        if (!strcmp(tok[0], "ckd") && nt == 6) {
            uint8_t pub[33], cc[32], wp[33], wc[32], cp[33], ccc[32];
            unhex(tok[1], pub, 33); unhex(tok[2], cc, 32); unhex(tok[4], wp, 33); unhex(tok[5], wc, 32);
            if (secp256k1_ckd_pub(cp, ccc, pub, cc, (uint32_t) strtoul(tok[3], NULL, 10)) || memcmp(cp, wp, 33) || memcmp(ccc, wc, 32)) {
                printf("FAIL ckd (line %d)\n", ln); fails++;
            }
        } else if (!strcmp(tok[0], "msdesc") && nt >= 9) {
            static ms_policy p;
            static uint8_t seed[64];
            bip32_node master;
            int ours = atoi(tok[3]), m = atoi(tok[4]), n = atoi(tok[5]), typ = atoi(tok[6]), sorted = atoi(tok[7]), k = atoi(tok[8]), e, ok = 1;
            ms_cache cache;

            unhex(tok[1], seed, 64);
            e = ms_parse(&p, tok[2]);
            if (e || p.m != m || p.n != n || p.type != typ || p.sorted != sorted) { printf("FAIL parse (line %d): %d m %d n %d type %d sorted %d\n", ln, e, p.m, p.n, p.type, p.sorted); fails++; continue; }
            bip32_master(&master, seed, 64);
            if (ms_ours(&p, &master) != (ours < 0 ? MSE_NOTOURS : ours)) { printf("FAIL ours (line %d): %d / %d\n", ln, ms_ours(&p, &master), ours); fails++; ok = 0; }
            if (nt != 9 + 4 * k) { printf("FAIL line %d: %d fields\n", ln, nt); fails++; continue; }
            memset(&cache, 0, sizeof cache);
            for (int i = 0; i < k; i++) {
                uint8_t ws[300], wk[40], sc[MS_SCRIPT_MAX], sp[34];
                size_t wsl = unhex(tok[11 + 4 * i], ws, sizeof ws), wkl = unhex(tok[12 + 4 * i], wk, sizeof wk), sl = 0, pl = 0;
                if (ms_script(&p, &cache, (unsigned) atoi(tok[9 + 4 * i]), (unsigned) strtoul(tok[10 + 4 * i], NULL, 10), sc, &sl, sp, &pl) || sl != wsl || memcmp(sc, ws, wsl) || pl != wkl || memcmp(sp, wk, wkl)) {
                    printf("FAIL script (line %d, address %d)\n", ln, i); fails++; ok = 0;
                }
            }
            if (ok && ours >= 0) {                                        /* the record: saved, loaded, and refused when changed or for another seed */
                uint8_t rec[MS_REC_MAX], other[64];
                ms_policy q;
                bip32_node m2;
                size_t rl = ms_save(&p, &master, rec, sizeof rec);
                total++;
                if (!rl || ms_load(&q, rec, rl, &master) || memcmp(&q, &p, sizeof q)) { printf("FAIL record (line %d)\n", ln); fails++; }
                rec[20] ^= 1;
                if (ms_load(&q, rec, rl, &master) != MSE_MAC) { printf("FAIL tamper (line %d)\n", ln); fails++; }
                rec[20] ^= 1;
                memset(other, 0x5a, 64);
                bip32_master(&m2, other, 64);
                if (ms_load(&q, rec, rl, &m2) != MSE_MAC) { printf("FAIL other seed (line %d)\n", ln); fails++; }
                if (ms_load(&q, rec, rl - 1, &master) == MSE_OK) { printf("FAIL short record (line %d)\n", ln); fails++; }
            }
        } else if (!strcmp(tok[0], "mserr") && nt == 3) {
            ms_policy p;
            int e = ms_parse(&p, tok[1]);
            if (e != atoi(tok[2])) { printf("FAIL mserr (line %d): %d / %s\n", ln, e, tok[2]); fails++; }
        } else {
            total--;
        }
    }
    fclose(f);
    printf("multisig wallets %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
