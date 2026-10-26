/* Known-answer tests for Pallas / Orchard: reads tests/orchard_vectors.txt (tools/gen_orchard_vectors.py, official
 * zcash-test-vectors). Usage: test_orchard <path> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/orchard.h"
#include "ec/pallas.h"

static int fails, total;

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

static void hexs(char *o, const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]); o[2 * n] = 0; }

static void check_hex(const char *kind, int ln, const uint8_t *got, size_t gn, const char *want)
{
    char g[1000];
    hexs(g, got, gn);
    total++;
    if (strcmp(g, want)) { fails++; printf("FAIL %s (line %d)\n  got  %s\n  want %s\n", kind, ln, g, want); }
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/orchard_vectors.txt", "r");
    char *line = malloc(65536);
    int ln = 0;
    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, 65536, f)) {
        char *tok[12];
        int nt = 0;
        ln++;
        for (char *p = strtok(line, " \r\n"); p && nt < 12; p = strtok(NULL, " \r\n")) tok[nt++] = p;
        if (!nt) continue;

        if (!strcmp(tok[0], "ogh") && nt == 4) {
            static uint8_t d[200], m[400];
            size_t dl = unhex(tok[1], d, sizeof d), ml = unhex(tok[2], m, sizeof m);
            uint8_t out[32];
            pl_pt p;
            pl_group_hash(&p, d, dl, m, ml);
            pl_encode(out, &p);
            check_hex("group hash", ln, out, 32, tok[3]);
        } else if (!strcmp(tok[0], "osin") && nt == 4) {
            static uint8_t d[200], bits[2000];
            size_t dl = unhex(tok[1], d, sizeof d), nb = strlen(tok[2]);
            uint8_t out[32];
            for (size_t i = 0; i < nb; i++) bits[i] = (uint8_t) (tok[2][i] == '1');
            orchard_sinsemilla_hash(out, d, dl, bits, nb);
            check_hex("sinsemilla", ln, out, 32, tok[3]);
        } else if (!strcmp(tok[0], "of4") && nt == 3) {
            static uint8_t in[400], out[400];
            size_t n = unhex(tok[1], in, sizeof in);
            if (n > 192) continue;                          /* the long vectors are not needed for 61 byte addresses */
            orchard_f4jumble(out, in, n);
            check_hex("f4jumble", ln, out, n, tok[2]);
        } else if (!strcmp(tok[0], "okeys") && nt == 10) {
            uint8_t sk[32], dd[11], j0[11] = {0}, addr[43];
            orchard_fvk fv;
            unhex(tok[1], sk, 32);
            orchard_fvk_from_sk(&fv, sk);
            check_hex("ak", ln, fv.ak, 32, tok[2]);
            check_hex("nk", ln, fv.nk, 32, tok[3]);
            check_hex("rivk", ln, fv.rivk, 32, tok[4]);
            check_hex("ivk", ln, fv.ivk, 32, tok[5]);
            check_hex("dk", ln, fv.dk, 32, tok[6]);
            check_hex("ovk", ln, fv.ovk, 32, tok[7]);
            orchard_diversifier(dd, fv.dk, j0);
            check_hex("diversifier", ln, dd, 11, tok[8]);
            orchard_address(addr, &fv, dd);
            check_hex("pk_d", ln, addr + 11, 32, tok[9]);
        } else if (!strcmp(tok[0], "ozip") && nt == 5) {
            uint8_t seed[32], sk[32], c[32];
            unhex(tok[1], seed, 32);
            orchard_master(sk, c, seed, 32);
            if (strcmp(tok[2], "-")) {
                for (char *s = tok[2]; *s;) {
                    unsigned long v = strtoul(s, &s, 10);
                    orchard_child(sk, c, (uint32_t) v | 0x80000000u);
                    if (*s == ',') s++;
                }
            }
            check_hex("zip32 sk", ln, sk, 32, tok[3]);
            check_hex("zip32 chain", ln, c, 32, tok[4]);
        } else if (!strcmp(tok[0], "oua") && nt == 4) {
            uint8_t sk[32], raw[43], j0[11] = {0}, dd[11], addr[43];
            char ua[160];
            orchard_fvk fv;
            unhex(tok[1], sk, 32);
            unhex(tok[2], raw, 43);
            orchard_fvk_from_sk(&fv, sk);
            orchard_diversifier(dd, fv.dk, j0);
            orchard_address(addr, &fv, dd);
            check_hex("raw address", ln, addr, 43, tok[2]);
            if (orchard_unified_address(ua, sizeof ua, addr) < 0) { fails++; total++; printf("FAIL ua encode (line %d)\n", ln); continue; }
            total++;
            if (strcmp(ua, tok[3])) { fails++; printf("FAIL unified address (line %d)\n  got  %s\n  want %s\n", ln, ua, tok[3]); }
        }
    }
    printf("ORCHARD %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
