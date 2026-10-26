/* Known-answer tests of the Bitcoin family signer: tests/btc_vectors.txt (tools/gen_btc_vectors.py).
 * Usage: test_btc <path to btc_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/btc.h"

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

static const btc_net *net_of(const char *n)
{
    static const char *const ids[] = {"btc84", "ltc84", "doge", "dash", "bch"};
    static const char *const names[] = {"btc", "ltc", "doge", "dash", "bch"};
    for (int i = 0; i < 5; i++) if (!strcmp(n, names[i])) return btc_net_for(chain_find(ids[i]));
    return NULL;
}

static void unscore(char *s) { for (; *s; s++) if (*s == '~') *s = ' '; }

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/btc_vectors.txt", "r");
    static char line[60000];
    static uint8_t buf[30000], want[30000], out[30000], tx[30000], seed[64];
    static tx_view v;
    char *tok[200];
    int ln = 0, fails = 0, total = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        int nt = 0;
        const btc_net *net;
        bip32_node m;
        psbt p;
        size_t bl;

        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 200; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 5) continue;
        psbt_set_wallets(NULL, 0);
        if (!strcmp(tok[0], "pview") || !strcmp(tok[0], "pnote")) {            /* with registered multisig wallets: the descriptors come before the fields of view / note */
            static ms_policy wal[4];
            static char view_s[] = "view", note_s[] = "note";
            int nd = atoi(tok[4]), e = 0;
            if (nd < 1 || nd > 4 || nt < 6 + nd) { printf("FAIL %s line %d: %d descriptors\n", tok[0], ln, nd); fails++; continue; }
            for (int i = 0; i < nd && !e; i++) e = ms_parse(&wal[i], tok[5 + i]);
            if (e) { printf("FAIL descriptor (line %d): %d\n", ln, e); fails++; continue; }
            tok[0] = tok[0][1] == 'v' ? view_s : note_s;
            memmove(&tok[4], &tok[5 + nd], (size_t) (nt - 5 - nd) * sizeof tok[0]);
            nt -= 1 + nd;
            psbt_set_wallets(wal, nd);
        }
        net = net_of(tok[1]);
        if (!net) { printf("FAIL unknown network %s (line %d)\n", tok[1], ln); fails++; continue; }
        unhex(tok[2], seed, 64);
        if (bip32_master(&m, seed, 64)) { printf("FAIL master (line %d)\n", ln); fails++; continue; }
        bl = unhex(tok[3], buf, sizeof buf);
        total++;
        if (!strcmp(tok[0], "psbt") && nt == 7) {
            size_t ol = 0, tl = 0, wl;
            int ns = 0, r, wantn = atoi(tok[6]);
            if (psbt_parse(&p, buf, bl)) { printf("FAIL parse (line %d)\n", ln); fails++; continue; }
            r = psbt_sign(&p, net, &m, out, sizeof out, &ol, tx, sizeof tx, &tl, &ns);
            if (wantn == 0) {
                if (r != BTC_ERR_NOKEY) { printf("FAIL line %d: expected NOKEY, got %d\n", ln, r); fails++; }
                continue;
            }
            wl = unhex(tok[4], want, sizeof want);
            if (r || ns != wantn || ol != wl || memcmp(out, want, wl)) {
                size_t k = 0;
                while (k < ol && k < wl && out[k] == want[k]) k++;
                printf("FAIL psbt line %d: r=%d sigs %d/%d len %zu/%zu first difference at %zu\n", ln, r, ns, wantn, ol, wl, k);
                fails++;
                continue;
            }
            wl = unhex(tok[5], want, sizeof want);
            if (tl != wl || (wl && memcmp(tx, want, wl))) { printf("FAIL final tx line %d: len %zu/%zu\n", ln, tl, wl); fails++; }
        } else if (!strcmp(tok[0], "view") && nt >= 8) {
            int nout = atoi(tok[7]), ok = 1;
            if (psbt_parse(&p, buf, bl) || psbt_summary(&p, net, &m, &v)) { printf("FAIL view parse (line %d)\n", ln); fails++; continue; }
            unscore(tok[4]); unscore(tok[5]);
            if (strcmp(v.fee, strcmp(tok[4], "-") ? tok[4] : "")) { ok = 0; printf("  fee %s / %s\n", v.fee, tok[4]); }
            if (strcmp(v.total, tok[5])) { ok = 0; printf("  total %s / %s\n", v.total, tok[5]); }
            if ((int) v.warn != atoi(tok[6])) { ok = 0; printf("  warn %u / %s\n", v.warn, tok[6]); }
            if (v.nout != nout || nt != 8 + 3 * nout) { ok = 0; printf("  nout %d / %d\n", v.nout, nout); }
            else for (int i = 0; i < nout; i++) {
                unscore(tok[8 + 3 * i]); unscore(tok[9 + 3 * i]);
                if (strcmp(v.out[i].to, tok[8 + 3 * i]) || strcmp(v.out[i].amount, tok[9 + 3 * i]) || v.out[i].mine != atoi(tok[10 + 3 * i])) {
                    ok = 0;
                    printf("  out %d: %s %s %d / %s %s %s\n", i, v.out[i].to, v.out[i].amount, v.out[i].mine, tok[8 + 3 * i], tok[9 + 3 * i], tok[10 + 3 * i]);
                }
            }
            if (!ok) { printf("FAIL view line %d\n", ln); fails++; }
        } else if (!strcmp(tok[0], "note") && nt >= 5) {                      /* the extra lines of the summary */
            int nn = atoi(tok[4]), ok = 1;
            if (psbt_parse(&p, buf, bl) || psbt_summary(&p, net, &m, &v)) { printf("FAIL note parse (line %d)\n", ln); fails++; continue; }
            if (v.nnote != nn || nt != 5 + nn) { ok = 0; printf("  %d notes / %d\n", v.nnote, nn); }
            for (int i = 0; ok && i < nn; i++) {
                unscore(tok[5 + i]);
                if (strcmp(v.note[i], tok[5 + i])) { ok = 0; printf("  note %d: \"%s\" / \"%s\"\n", i, v.note[i], tok[5 + i]); }
            }
            if (!ok) { printf("FAIL note line %d\n", ln); fails++; }
        } else if (!strcmp(tok[0], "perr") && nt == 5) {
            size_t ol = 0;
            int r;
            if (psbt_parse(&p, buf, bl)) { printf("FAIL perr parse (line %d)\n", ln); fails++; continue; }
            r = psbt_sign(&p, net, &m, out, sizeof out, &ol, NULL, 0, NULL, NULL);
            if (r != atoi(tok[4])) { printf("FAIL perr line %d: got %d want %s\n", ln, r, tok[4]); fails++; }
        } else {
            total--;
        }
    }
    fclose(f);
    printf("BTC %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
