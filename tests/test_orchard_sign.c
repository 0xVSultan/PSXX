/* Zcash Orchard signing through the dispatcher: replays tests/orchard_sign_vectors.txt (tools/gen_orchard_sign_vectors.py; the signature
 * hashes and the RedPallas signatures were checked there against the reference code of the Zcash foundation). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/dispatch.h"
#include "coin/orchard.h"

static int fails, total;
static uint8_t pay[16384], want[16384], cont[16500], buf[16384], scratch[10240];

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

static uint8_t *tab;
static int tab_get(unsigned j, uint8_t xy[64]) { if (j >= 1024) return -1; memcpy(xy, tab + 64 * j, 64); return 0; }

static int run(const char *path)
{
    FILE *f = fopen(path, "r");
    static char line[40000];
    int ln = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[10];
        int nt = 0;
        hd_secret hs;
        sign_req q;
        sign_result r;
        size_t pl, pathl, wl = 0;
        int e, bad;
        ln++;
        for (char *s = strtok(line, " \r\n"); s && nt < 10; s = strtok(NULL, " \r\n")) tok[nt++] = s;
        bad = !strcmp(tok[0], "zorcbad");
        if (nt != (bad ? 6 : 7) || (!bad && strcmp(tok[0], "zorc"))) continue;
        memset(&hs, 0, sizeof hs);
        unhex(tok[2], hs.seed, 64);
        hs.passphrase = "";
        pl = unhex(tok[4], pay, sizeof pay);
        pathl = strlen(tok[3]);
        memset(cont, 0, 14);
        memcpy(cont, "PSXQ\x01", 5);
        memcpy(cont + 6, "zecu", 4);
        cont[14] = (uint8_t) pathl;
        memcpy(cont + 15, tok[3], pathl);
        for (int i = 0; i < 4; i++) cont[15 + pathl + i] = (uint8_t) (pl >> (8 * i));
        memcpy(cont + 19 + pathl, pay, pl);
        total++;
        e = sign_req_parse(&q, cont, 19 + pathl + pl);
        if (!e) e = sign_summary(&q, &hs, &txv_shared);
        r.buf = buf; r.cap = sizeof buf; r.scratch = scratch; r.scap = sizeof scratch;
        if (bad) {
            if (e != atoi(tok[5])) { fails++; printf("FAIL %s (line %d): summary %d, want %s\n", tok[1], ln, e, tok[5]); }
            if (atoi(tok[5]) == SIGN_ERR_MISMATCH) continue;            /* found by the review of the summary; signing does not repeat it */
            e = sign_req_parse(&q, cont, 19 + pathl + pl);
            if (!e) e = sign_execute(&q, &hs, &r);
            total++;
            if (e != atoi(tok[5])) { fails++; printf("FAIL %s (line %d): sign %d, want %s\n", tok[1], ln, e, tok[5]); }
            continue;
        }
        wl = unhex(tok[5], want, sizeof want);
        if (e || !!(txv_shared.warn & TXW_BLIND) != atoi(tok[6])) { fails++; printf("FAIL %s (line %d): summary %d\n", tok[1], ln, e); }
        e = sign_execute(&q, &hs, &r);
        total++;
        if (e || r.len != wl || memcmp(buf, want, wl)) { fails++; printf("FAIL %s (line %d): sign %d\n", tok[1], ln, e); }
    }
    fclose(f);
    printf("orchard signing%s: %d vectors, %d failed\n", tab ? " (Sinsemilla points from a table)" : "", total, fails);
    return fails != 0;
}

int main(int argc, char **argv)
{
    const char *v = argc > 1 ? argv[1] : "tests/orchard_sign_vectors.txt";
    int r = run(v);
    if (argc > 2) {                                             /* the same with the precomputed points */
        FILE *t = fopen(argv[2], "rb");
        if (!t) { printf("cannot open the table\n"); return 2; }
        tab = malloc(65536);
        if (fread(tab, 1, 65536, t) != 65536) { printf("bad table\n"); return 2; }
        fclose(t);
        orchard_set_sinsemilla_table(tab_get);
        fails = total = 0;
        r |= run(v);
    }
    return r;
}
