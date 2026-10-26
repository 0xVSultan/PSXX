/* Monero signer: replays tests/xmr_vectors.txt (tools/gen_xmr_vectors.py; the signatures were verified there by an independent CLSAG
 * implementation) through the module and through the dispatcher, and checks that tampered requests are refused. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/dispatch.h"
#include "sign/xmr.h"

static int fails, total;
static uint8_t req[16384], want[16384], got[16384], cont[16500], scratch[10240];

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/xmr_vectors.txt", "r");
    static char line[40000];
    int ln = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[16];
        int nt = 0;
        uint8_t seed[32];
        size_t rl, gl = 0;
        ln++;
        for (char *s = strtok(line, " \r\n"); s && nt < 16; s = strtok(NULL, " \r\n")) tok[nt++] = s;
        if (nt < 4) continue;
        if (!strcmp(tok[0], "xmr")) {                                     /* xmr name seed request result */
            tx_view *v = &txv_shared;
            hd_secret hs;
            sign_req q;
            sign_result r;
            size_t wl;
            int e;
            unhex(tok[nt - 3], seed, 32);
            rl = unhex(tok[nt - 2], req, sizeof req);
            wl = unhex(tok[nt - 1], want, sizeof want);
            e = xmr_tx_sign(req, rl, seed, got, sizeof got, &gl);
            total++;
            if (e || gl != wl || memcmp(got, want, wl)) { fails++; printf("FAIL sign %s (line %d): code %d\n", tok[1], ln, e); }
            /* the same through the container and the dispatcher */
            memcpy(cont, "PSXQ\x01\x00xmr\0\0\0\0\0\0", 14);
            cont[14] = 0;
            cont[15] = (uint8_t) rl; cont[16] = (uint8_t) (rl >> 8); cont[17] = (uint8_t) (rl >> 16); cont[18] = (uint8_t) (rl >> 24);
            memcpy(cont + 19, req, rl);
            memset(&hs, 0, sizeof hs);
            memcpy(hs.xmr_seed, seed, 32);
            hs.xmr_ok = 1;
            total++;
            e = sign_req_parse(&q, cont, rl + 19);
            if (!e) e = sign_summary(&q, &hs, v);
            if (e || strcmp(v->title, "Monero transaction") || v->nout < 1) { fails++; printf("FAIL dispatch summary %s: %d\n", tok[1], e); }
            r.buf = got; r.cap = sizeof got; r.scratch = scratch; r.scap = sizeof scratch;
            total++;
            e = sign_execute(&q, &hs, &r);
            if (e || r.len != wl || memcmp(got, want, wl)) { fails++; printf("FAIL dispatch sign %s: %d\n", tok[1], e); }
            hs.xmr_ok = 0;
            total++;
            if (sign_summary(&q, &hs, v) != SIGN_ERR_NOSEED) { fails++; printf("FAIL no seed %s\n", tok[1]); }
        } else if (!strcmp(tok[0], "xmrbad")) {                           /* xmrbad name seed request code */
            int want_code = atoi(tok[nt - 1]), e;
            unhex(tok[nt - 3], seed, 32);
            rl = unhex(tok[nt - 2], req, sizeof req);
            e = xmr_tx_sign(req, rl, seed, got, sizeof got, &gl);
            total++;
            if (e != want_code) { fails++; printf("FAIL bad %s (line %d): %d, want %d\n", tok[1], ln, e, want_code); }
            e = xmr_tx_summary(req, rl, seed, &txv_shared);
            total++;
            if (e != want_code) { fails++; printf("FAIL bad summary %s (line %d): %d, want %d\n", tok[1], ln, e, want_code); }
        }
    }
    fclose(f);
    printf("xmr: %d checks, %d failed\n", total, fails);
    return fails != 0;
}
