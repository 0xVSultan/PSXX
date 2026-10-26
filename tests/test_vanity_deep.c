/* The quick condition of the vanity search at every depth: for keys of a batch the prefix is taken from the real address text, 1 .. 11 characters of it, and the condition
 * must say yes for that key (tests/test_vanity_search.c only asks about prefixes of one or two characters, where a mistake in a later 5 bit group would not show). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vanity/vanity.h"
#include "ec/secp256k1.h"
#include "coin/addr.h"
#include "coin/chains.h"

static van_ctx kctx;
static int bad, total;
#define CHECK(c, ...) do { total++; if (!(c)) { bad++; if (bad < 20) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static int address_of(const vanity_cfg *c, const uint8_t key[32], char *out, size_t cap)
{
    uint8_t pub[33];
    switch (c->kind) {
    case VK_BECH32: secp256k1_pubkey_create(pub, key); return addr_p2wpkh(out, cap, c->hrp, pub);
    case VK_NPUB: return addr_npub(out, cap, key);
    case VK_KASPA: secp256k1_pubkey_create(pub, key); return kaspa_address(out, cap, c->hrp, pub + 1);
    }
    return -1;
}

static vanity_cfg mk(int kind, const char *hrp, const char *pre)
{
    vanity_cfg c;
    memset(&c, 0, sizeof c);
    c.kind = kind; c.hrp = hrp;
    snprintf(c.prefix, sizeof c.prefix, "%s", pre);
    return c;
}

static void deep(int kind, const char *hrp, const char *head, int maxlen)
{
    static vanity v, w;
    uint8_t seed[32];
    int checked = 0, miss = 0;

    for (int round = 0; round < 6; round++) {
        vanity_cfg c = mk(kind, hrp, head);
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 37 + round * 11 + kind);
        if (vanity_start(&v, &c, &kctx, seed)) { CHECK(0, "start"); return; }
        secp256k1_van_prepare(&kctx);
        for (int i = 0; i < VAN_N; i += 61) for (int neg = 0; neg < 2; neg++) {
            uint8_t key[32];
            char text[VAN_ADDR];
            secp256k1_van_key(&kctx, i, neg, key);
            if (address_of(&c, key, text, sizeof text) <= 0) { CHECK(0, "no address"); return; }
            for (int L = (int) strlen(head); L <= (int) strlen(head) + maxlen; L++) {
                vanity_cfg d = mk(kind, hrp, "");
                snprintf(d.prefix, (size_t) L + 1, "%s", text);
                if (vanity_start(&w, &d, &kctx, seed)) { CHECK(0, "start %s", d.prefix); continue; }
                secp256k1_van_prepare(&kctx);
                checked++;
                if (!vanity_probe(&w, i, neg)) { miss++; CHECK(0, "kind %d: the key of candidate %d/%d has the address %s, the condition for the prefix %s says no", kind, i, neg, text, d.prefix); }
            }
        }
    }
    printf("  kind %d: %d prefixes of real addresses, %d missed\n", kind, checked, miss);
}

/* the mean number of candidates of a search against the estimate (vanity_check): a candidate that repeats an address (the key and its negative, for the addresses made of an x
 * coordinate alone) counted as a try and made a search take twice as long as the screen said */
static void rate(int kind, const char *hrp, const char *prefix, int runs)
{
    static vanity v;
    vanity_cfg c = mk(kind, hrp, prefix);
    uint64_t median = 0;
    double sum = 0, mean;
    uint8_t seed[32];

    vanity_check(&c, &median);
    mean = (double) median / 0.693;
    for (int r = 0; r < runs; r++) {
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 13 + r * 71 + 5 + (r >> 3) * 17);
        if (vanity_start(&v, &c, &kctx, seed)) { CHECK(0, "start %s", prefix); return; }
        while (!vanity_step(&v, 256)) {}
        sum += (double) v.tried;
        if (r < 3) {                                                    /* the address of the key found, as the screen of the loaded key shows it (signer_app.c) */
            char t[VAN_ADDR];
            CHECK(vanity_address(&c, v.key, t, sizeof t) > 0 && (kind == VK_ETH || !strcmp(t, v.addr)), "%s: vanity_address of the key gives %s, the search found %s", prefix, t, v.addr);
        }
    }
    printf("  %s: mean %.0f tried over %d searches, estimate %.0f (ratio %.2f)\n", prefix, sum / runs, runs, mean, sum / runs / mean);
    CHECK(sum / runs > 0.8 * mean && sum / runs < 1.25 * mean, "%s: the mean of %.0f candidates is far from the estimate %.0f", prefix, sum / runs, mean);
}

int main(void)
{
    deep(VK_KASPA, "kaspa", "kaspa:q", 9);
    deep(VK_BECH32, "bc", "bc1q", 9);
    deep(VK_NPUB, NULL, "npub1", 9);
    rate(VK_ETH, NULL, "0x123", 300);                    /* 4096: several batches of 512 */
    rate(VK_KASPA, "kaspa", "kaspa:qqwe", 300);
    rate(VK_NPUB, NULL, "npub1qa", 300);
    rate(VK_BECH32, "bc", "bc1qqz", 400);
    printf("%d failures\n", bad);
    return bad ? 1 : 0;
}
