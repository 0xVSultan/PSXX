/* The vanity search (core/vanity/vanity.c): the heads of the address kinds, the quick conditions (hex nibbles, 5 bit groups, Base58 ranges) against the real
 * address text of the same keys, whole searches whose result is checked from the key alone, and the CREATE2 vector of EIP-1014. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vanity/vanity.h"
#include "ec/secp256k1.h"
#include "hash/keccak.h"
#include "hash/ripemd160.h"
#include "coin/addr.h"
#include "coin/base58.h"
#include "coin/chains.h"

static van_ctx kctx;                                   /* the kernel tables */
static int bad, total;

#define CHECK(c, ...) do { total++; if (!(c)) { bad++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int address_of(const vanity_cfg *c, const uint8_t key[32], char *out, size_t cap)
{
    uint8_t pub[33];
    switch (c->kind) {
    case VK_ETH: return addr_eth(out, cap, key);
    case VK_BECH32: secp256k1_pubkey_create(pub, key); return addr_p2wpkh(out, cap, c->hrp, pub);
    case VK_P2PKH: secp256k1_pubkey_create(pub, key); return addr_p2pkh(out, cap, c->version, pub);
    case VK_P2SH: {
        uint8_t red[22] = {0, 20}, h[20], raw[21];
        secp256k1_pubkey_create(pub, key);
        hash160(pub, 33, red + 2);
        hash160(red, 22, h);
        raw[0] = c->version; memcpy(raw + 1, h, 20);
        return base58check_encode(raw, 21, out, cap);
    }
    case VK_NPUB: return addr_npub(out, cap, key);
    case VK_KASPA: secp256k1_pubkey_create(pub, key); return kaspa_address(out, cap, c->hrp, pub + 1);
    }
    return -1;
}

static void lower(char *s) { for (; *s; s++) if (*s >= 'A' && *s <= 'F') *s = (char) (*s + 32); }

static vanity_cfg mk(int kind, uint8_t version, const char *hrp, const char *pre, const char *suf)
{
    vanity_cfg c;
    memset(&c, 0, sizeof c);
    c.kind = kind; c.version = version; c.hrp = hrp;
    snprintf(c.prefix, sizeof c.prefix, "%s", pre);
    snprintf(c.suffix, sizeof c.suffix, "%s", suf);
    return c;
}

static const char *KN[] = {"eth", "bech32", "p2pkh", "p2sh", "npub", "kaspa", "create2"};

static void heads(void)
{
    static const struct { vanity_cfg c; const char *head; } T[] = {
        {{VK_ETH, 0, NULL, "", "", {0}, {0}}, "0x"},
        {{VK_BECH32, 0, "bc", "", "", {0}, {0}}, "bc1q"},
        {{VK_BECH32, 0, "ltc", "", "", {0}, {0}}, "ltc1q"},
        {{VK_P2PKH, 0x00, NULL, "", "", {0}, {0}}, "1"},
        {{VK_P2PKH, 0x30, NULL, "", "", {0}, {0}}, "L"},
        {{VK_P2PKH, 0x1e, NULL, "", "", {0}, {0}}, "D"},
        {{VK_P2PKH, 0x4c, NULL, "", "", {0}, {0}}, "X"},
        {{VK_P2SH, 0x05, NULL, "", "", {0}, {0}}, "3"},
        {{VK_P2SH, 0x32, NULL, "", "", {0}, {0}}, "M"},
        {{VK_NPUB, 0, NULL, "", "", {0}, {0}}, "npub1"},
        {{VK_KASPA, 0, "kaspa", "", "", {0}, {0}}, "kaspa:q"},
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        char h[24];
        int n = vanity_head(&T[i].c, h, sizeof h);
        CHECK(n > 0 && !strcmp(h, T[i].head), "head %zu: got '%s', want '%s'", i, n > 0 ? h : "-", T[i].head);
    }
}

/* every candidate of the first batch: the quick condition must be exactly "the text of the address starts as asked" */
static void probes(const vanity_cfg *c, const char *label)
{
    static vanity v;
    uint8_t seed[32];
    int pos = 0, mism = 0;

    for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 53 + 7 + c->kind);
    if (vanity_start(&v, c, &kctx, seed)) { CHECK(0, "%s: start failed", label); return; }
    secp256k1_van_prepare(&kctx);
    for (int i = 0; i < VAN_N; i++) for (int neg = 0; neg < 2; neg++) {
        uint8_t key[32];
        char text[VAN_ADDR];
        int got, want;
        secp256k1_van_key(&kctx, i, neg, key);
        if (address_of(c, key, text, sizeof text) <= 0) { CHECK(0, "%s: no address", label); return; }
        if (c->kind == VK_ETH) lower(text);
        want = !strncmp(text, c->prefix, strlen(c->prefix));
        got = vanity_probe(&v, i, neg);
        pos += want;
        if (got != want) { mism++; if (mism < 4) printf("  %s: candidate %d/%d %s said %d, text %s\n", label, i, neg, c->prefix, got, text); }
    }
    CHECK(mism == 0 && pos > 0, "%s: %d positives, %d disagreements with the text", label, pos, mism);
}

static void search(const vanity_cfg *c, const char *label)
{
    static vanity v;
    static van_ctx *k = &kctx;
    uint8_t seed[32];
    char text[VAN_ADDR];
    int steps = 0;

    for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 29 + 3 + c->kind * 5 + (int) strlen(c->suffix));
    {
        int e = vanity_start(&v, c, k, seed);
        if (e) { CHECK(0, "%s: start error %d", label, e); return; }
    }
    while (!vanity_step(&v, 256) && steps++ < 20000) {}
    CHECK(v.found, "%s: nothing found in %llu candidates (%d rejected)", label, (unsigned long long) v.tried, v.rejected);
    if (!v.found) return;
    CHECK(v.rejected == 0, "%s: %d hits failed the check from the key", label, v.rejected);
    if (c->kind == VK_CREATE2) return;
    CHECK(address_of(c, v.key, text, sizeof text) > 0, "%s: no address of the result", label);
    {
        char want_pre[24], want_suf[24], t2[VAN_ADDR];
        snprintf(want_pre, sizeof want_pre, "%s", c->prefix);
        snprintf(want_suf, sizeof want_suf, "%s", c->suffix);
        snprintf(t2, sizeof t2, "%s", text);
        if (c->kind == VK_ETH) { lower(t2); lower(want_suf); lower(want_pre); }
        CHECK(!strncmp(t2, want_pre, strlen(want_pre)), "%s: %s does not start with %s", label, text, c->prefix);
        CHECK(strlen(t2) >= strlen(want_suf) && !strcmp(t2 + strlen(t2) - strlen(want_suf), want_suf), "%s: %s does not end with %s", label, text, c->suffix);
        CHECK(!strcmp(text, v.addr) || c->kind == VK_ETH, "%s: the reported address %s differs from %s", label, v.addr, text);
    }
    printf("  %-24s %6llu candidates -> %s\n", label, (unsigned long long) v.tried, v.addr);
}

static void errors(void)
{
    static vanity v;
    uint8_t seed[32];
    vanity_cfg c;

    for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i + 100);
    c = mk(VK_ETH, 0, NULL, "ab", "");                       CHECK(vanity_start(&v, &c, &kctx, seed) == VE_HEAD, "no head");
    c = mk(VK_ETH, 0, NULL, "0xzz", "");                     CHECK(vanity_start(&v, &c, &kctx, seed) == VE_CHAR, "bad hex");
    c = mk(VK_BECH32, 0, "bc", "bc1qb", "");                 CHECK(vanity_start(&v, &c, &kctx, seed) == VE_CHAR, "b is not in the bech32 alphabet");
    c = mk(VK_P2PKH, 0, NULL, "1O", "");                     CHECK(vanity_start(&v, &c, &kctx, seed) == VE_CHAR, "O is not in the Base58 alphabet");
    c = mk(VK_P2PKH, 0, NULL, "2a", "");                     CHECK(vanity_start(&v, &c, &kctx, seed) == VE_HEAD, "a Bitcoin address does not start with 2");
    c = mk(VK_P2PKH, 0x30, NULL, "1a", "");                  CHECK(vanity_start(&v, &c, &kctx, seed) == VE_HEAD, "a Litecoin address does not start with 1");
    c = mk(VK_ETH, 0, NULL, "0x000000000000000000000", "00000000000000000000000");   CHECK(vanity_start(&v, &c, &kctx, seed) == VE_LONG, "too long");
    c = mk(VK_KASPA, 0, "kaspa", "kaspa:qx", "");           CHECK(vanity_start(&v, &c, &kctx, seed) == VE_RANGE, "no Kaspa address has x as its second character");
    c = mk(VK_ETH, 0, NULL, "0xab", "");
    memset(seed, 0, 32); seed[31] = 5;
    CHECK(vanity_start(&v, &c, &kctx, seed) == VE_SEED, "a tiny start key");
}

static void create2(void)
{
    static vanity v;
    vanity_cfg c = mk(VK_CREATE2, 0, NULL, "0x", "");
    uint8_t seed[32], h[32], buf[85], init[1] = {0};
    char text[VAN_ADDR];

    /* EIP-1014: from 0x00..00, salt 0, init code 0x00 -> 0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38 */
    keccak256(init, 1, c.init_hash);
    memset(c.deployer, 0, 20);
    memset(seed, 0, 32);
    buf[0] = 0xff; memcpy(buf + 1, c.deployer, 20); memset(buf + 21, 0, 32); memcpy(buf + 53, c.init_hash, 32);
    keccak256(buf, 85, h);
    addr_eth20(text, sizeof text, h + 12);
    CHECK(!strcmp(text, "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38"), "EIP-1014 example 0: %s", text);

    /* a search: the salt must give an address that starts with 0xbe and ends with 7 */
    memset(c.deployer, 0xAB, 20);
    snprintf(c.prefix, sizeof c.prefix, "0xbe");
    snprintf(c.suffix, sizeof c.suffix, "7");
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 11 + 1);
    CHECK(vanity_start(&v, &c, &kctx, seed) == VE_OK, "create2 start");
    for (int i = 0; i < 100 && !vanity_step(&v, 1000); i++) {}
    CHECK(v.found, "create2: not found");
    if (v.found) {
        buf[0] = 0xff; memcpy(buf + 1, c.deployer, 20); memcpy(buf + 21, v.key, 32); memcpy(buf + 53, c.init_hash, 32);
        keccak256(buf, 85, h);
        CHECK(!memcmp(h + 12, v.a20, 20), "create2: the salt does not give the address");
        CHECK(h[12] == 0xbe && (h[31] & 15) == 7, "create2: the address %02x...%02x is not 0xbe..7", h[12], h[31]);
        printf("  %-24s %6llu candidates -> %s\n", "create2", (unsigned long long) v.tried, v.addr);
    }
}

int main(void)
{
    heads();
    errors();
    {   /* the quick conditions against the text */
        vanity_cfg c;
        c = mk(VK_ETH, 0, NULL, "0xa", "");                       probes(&c, "eth 0xa");
        c = mk(VK_ETH, 0, NULL, "0x3f", "");                      probes(&c, "eth 0x3f");
        c = mk(VK_BECH32, 0, "bc", "bc1qq", "");                  probes(&c, "bech32 q");
        c = mk(VK_BECH32, 0, "bc", "bc1qz", "");                  probes(&c, "bech32 z");
        c = mk(VK_BECH32, 0, "ltc", "ltc1qp", "");                probes(&c, "bech32 ltc p");
        c = mk(VK_P2PKH, 0, NULL, "1A", "");                      probes(&c, "p2pkh 1A");
        c = mk(VK_P2PKH, 0, NULL, "1Q", "");                      probes(&c, "p2pkh 1Q");
        c = mk(VK_P2PKH, 0, NULL, "1M", "");                      probes(&c, "p2pkh 1M");
        c = mk(VK_P2PKH, 0x30, NULL, "L", "");                    probes(&c, "ltc legacy L");
        c = mk(VK_P2PKH, 0x30, NULL, "LU", "");                   probes(&c, "ltc legacy LU");
        c = mk(VK_P2PKH, 0x1e, NULL, "DH", "");                   probes(&c, "doge DH");
        c = mk(VK_P2PKH, 0x4c, NULL, "Xp", "");                   probes(&c, "dash Xp");
        c = mk(VK_P2SH, 0x05, NULL, "3F", "");                    probes(&c, "p2sh 3F");
        c = mk(VK_P2SH, 0x32, NULL, "MQ", "");                    probes(&c, "ltc p2sh MQ");
        c = mk(VK_NPUB, 0, NULL, "npub1q", "");                   probes(&c, "npub q");
        c = mk(VK_NPUB, 0, NULL, "npub1z", "");                   probes(&c, "npub z");
        c = mk(VK_KASPA, 0, "kaspa", "kaspa:qp", "");             probes(&c, "kaspa p");
        c = mk(VK_KASPA, 0, "kaspa", "kaspa:qz", "");             probes(&c, "kaspa z");
    }
    {   /* whole searches */
        vanity_cfg c;
        c = mk(VK_ETH, 0, NULL, "0xab", "");                      search(&c, "eth 0xab");
        c = mk(VK_ETH, 0, NULL, "0xA", "BC");                     search(&c, "eth 0xA..BC");
        c = mk(VK_ETH, 0, NULL, "0x", "dead");                    search(&c, "eth ..dead");
        c = mk(VK_BECH32, 0, "bc", "bc1qqz", "");                 search(&c, "bech32 qz");
        c = mk(VK_BECH32, 0, "bc", "bc1qp", "k");                 search(&c, "bech32 p..k");
        c = mk(VK_BECH32, 0, "ltc", "ltc1q", "h");                search(&c, "ltc bech32 ..h");
        c = mk(VK_P2PKH, 0, NULL, "1Z", "");                      search(&c, "p2pkh 1Z");
        c = mk(VK_P2PKH, 0, NULL, "1B", "z");                     search(&c, "p2pkh 1B..z");
        c = mk(VK_P2PKH, 0x30, NULL, "LP", "");                   search(&c, "ltc legacy LP");
        c = mk(VK_P2PKH, 0x1e, NULL, "DK", "");                   search(&c, "doge DK");
        c = mk(VK_P2SH, 0x05, NULL, "3Q", "");                    search(&c, "p2sh 3Q");
        c = mk(VK_NPUB, 0, NULL, "npub1q0", "");                  search(&c, "npub q0");
        c = mk(VK_NPUB, 0, NULL, "npub1z", "9");                  search(&c, "npub z..9");
        c = mk(VK_KASPA, 0, "kaspa", "kaspa:qp", "");             search(&c, "kaspa qp");
        c = mk(VK_KASPA, 0, "kaspa", "kaspa:qz", "e");            search(&c, "kaspa qz..e");
    }
    create2();
    (void) KN;
    {   /* the difficulty estimates: the number of candidates after which a hit is as likely as not */
        static vanity v;
        uint8_t seed[32];
        vanity_cfg c;
        struct { vanity_cfg c; uint64_t lo, hi; } E[] = {
            {mk(VK_ETH, 0, NULL, "0x1234", ""), 45000, 46000},                     /* 16^4 * 0.693 = 45 426 */
            {mk(VK_BECH32, 0, "bc", "bc1qqz", ""), 700, 720},                      /* 32^2 * 0.693 = 709 */
            {mk(VK_P2PKH, 0, NULL, "1Z", ""), 900, 1000},                        /* about 58 * 0.693 * (a bit more: the second character is limited to 1..Q mostly) */
            {mk(VK_P2PKH, 0x1e, NULL, "DK", ""), 10, 25},                         /* few: the second character of Dogecoin addresses has 22 values */
        };
        (void) c;
        for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i + 40);
        for (size_t i = 0; i < sizeof E / sizeof E[0]; i++) {
            if (vanity_start(&v, &E[i].c, &kctx, seed)) { CHECK(0, "expected %zu: start", i); continue; }
            printf("  expected[%zu] = %llu\n", i, (unsigned long long) v.expected);
            CHECK(v.expected >= E[i].lo && v.expected <= E[i].hi, "expected[%zu] = %llu, not in %llu..%llu", i, (unsigned long long) v.expected, (unsigned long long) E[i].lo, (unsigned long long) E[i].hi);
        }
    }
    printf("vanity search: %d checks, %d bad\n", total, bad);
    return bad != 0;
}
