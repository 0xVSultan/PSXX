/* not a test: the mean number of candidates of searches against the estimate of the screen.   vanity_rate <prefix> [runs] [kind: kaspa|bc|npub|eth|p2pkh|p2sh] [suffix] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vanity/vanity.h"
#include "ec/secp256k1.h"
static van_ctx kctx;
int main(int argc, char **argv)
{
    static vanity v;
    vanity_cfg c;
    uint8_t seed[32];
    int runs = argc > 2 ? atoi(argv[2]) : 20;
    const char *kind = argc > 3 ? argv[3] : "kaspa";
    double sum = 0, rej = 0;
    uint64_t exp_median;
    memset(&c, 0, sizeof c);
    if (!strcmp(kind, "kaspa")) { c.kind = VK_KASPA; c.hrp = "kaspa"; }
    else if (!strcmp(kind, "bc")) { c.kind = VK_BECH32; c.hrp = "bc"; }
    else if (!strcmp(kind, "npub")) c.kind = VK_NPUB;
    else if (!strcmp(kind, "eth")) c.kind = VK_ETH;
    else if (!strcmp(kind, "p2pkh")) c.kind = VK_P2PKH;
    else if (!strcmp(kind, "p2sh")) { c.kind = VK_P2SH; c.version = 5; }
    snprintf(c.prefix, sizeof c.prefix, "%s", argv[1]);
    if (argc > 4) snprintf(c.suffix, sizeof c.suffix, "%s", argv[4]);
    if (vanity_check(&c, &exp_median)) { puts("not possible"); return 1; }
    for (int r = 0; r < runs; r++) {
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 13 + r * 71 + 5 + (r >> 3) * 17);
        if (vanity_start(&v, &c, &kctx, seed)) { puts("start error"); return 1; }
        while (!vanity_step(&v, 256)) {}
        sum += (double) v.tried; rej += v.rejected;
    }
    printf("rejected hits: %.0f   ", rej);
    printf("%s %s: mean %.0f tried over %d runs; the screen's median %llu = %.0f as a mean (ln 2); ratio %.2f\n", kind, argv[1], sum / runs, runs, (unsigned long long) exp_median, exp_median / 0.693, sum / runs / (exp_median / 0.693));
    return 0;
}
