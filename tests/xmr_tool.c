/* Command line Monero signer for the vector generator (tools/gen_xmr_vectors.py), which checks the output with an independent
 * implementation:   xmr_tool <spend seed hex> <request hex>
 * Prints "summary ..." lines, then "result <hex>" or "error <code>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/xmr.h"
#include "coin/xmr_seed.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

int main(int argc, char **argv)
{
    static uint8_t req[16384], out[16384];
    static tx_view v;
    uint8_t seed[32];
    size_t rl, ol = 0;
    int e;

    if (argc == 3 && !strcmp(argv[1], "words")) {              /* the 25 words of a spend seed */
        char m[XMR_MAX_MNEMONIC];
        unhex(argv[2], seed, 32);
        if (xmr_seed_encode(seed, m, sizeof m) < 0) return 1;
        printf("%s\n", m);
        return 0;
    }
    if (argc != 3) { fprintf(stderr, "usage: xmr_tool <seed hex> <request hex>\n"); return 2; }
    unhex(argv[1], seed, 32);
    rl = unhex(argv[2], req, sizeof req);
    e = xmr_tx_summary(req, rl, seed, &v);
    if (e) { printf("error %d\n", e); return 0; }
    printf("summary %s | fee %s | sends %s | warn %x\n", v.title, v.fee, v.total, (unsigned) v.warn);
    for (int i = 0; i < v.nout; i++) printf("summary out %s %s%s\n", v.out[i].to, v.out[i].amount, v.out[i].mine ? " change" : "");
    for (int i = 0; i < v.nnote; i++) printf("summary note %s\n", v.note[i]);
    e = xmr_tx_sign(req, rl, seed, out, sizeof out, &ol);
    if (e) { printf("error %d\n", e); return 0; }
    printf("result ");
    for (size_t i = 0; i < ol; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
