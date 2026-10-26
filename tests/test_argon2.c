/* Argon2id (core/hash/argon2.c) against the test vector of RFC 9106 section 5.3, then the parameter sets of the PSX probe (hal/psx/mempool_probe.c): their tags, computed in
 * flat RAM and through memory tiers that copy every block (so a wrong tier would show), are printed with --print for the probe's constants. Usage: test_argon2 [--print] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash/argon2.h"

static uint64_t *mem;

static void get(void *ctx, uint32_t i, uint64_t b[ARGON2_QWORDS]) { (void) ctx; memcpy(b, mem + (size_t) i * ARGON2_QWORDS, ARGON2_BLOCK_BYTES); }
static void put(void *ctx, uint32_t i, const uint64_t b[ARGON2_QWORDS]) { (void) ctx; memcpy(mem + (size_t) i * ARGON2_QWORDS, b, ARGON2_BLOCK_BYTES); }

/* three tiers with their own storage, the blocks sit in them by index ranges (as the probe puts them in RAM, VRAM and SPU RAM) */
static uint64_t *tier[3];
static uint32_t tier_end[3];
static void tget(void *ctx, uint32_t i, uint64_t b[ARGON2_QWORDS])
{
    uint32_t base = 0;
    (void) ctx;
    for (int t = 0; t < 3; t++) { if (i < tier_end[t]) { memcpy(b, tier[t] + (size_t) (i - base) * ARGON2_QWORDS, ARGON2_BLOCK_BYTES); return; } base = tier_end[t]; }
    abort();
}
static void tput(void *ctx, uint32_t i, const uint64_t b[ARGON2_QWORDS])
{
    uint32_t base = 0;
    (void) ctx;
    for (int t = 0; t < 3; t++) { if (i < tier_end[t]) { memcpy(tier[t] + (size_t) (i - base) * ARGON2_QWORDS, b, ARGON2_BLOCK_BYTES); return; } base = tier_end[t]; }
    abort();
}

static int run(const argon2_params *p, uint8_t *tag, int tiered)
{
    uint32_t n = argon2_blocks(p);
    argon2_mem m = {NULL, get, put, NULL};
    int r;

    if (!n) return -1;
    if (!tiered) {
        mem = calloc(n, ARGON2_BLOCK_BYTES);
        r = argon2id(p, &m, tag);
        free(mem);
    } else {
        uint32_t a = n / 4, b = n / 2;                                  /* RAM, VRAM, SPU: a quarter, a half, the rest */
        tier[0] = calloc(a, ARGON2_BLOCK_BYTES);
        tier[1] = calloc(b, ARGON2_BLOCK_BYTES);
        tier[2] = calloc(n - a - b, ARGON2_BLOCK_BYTES);
        tier_end[0] = a; tier_end[1] = a + b; tier_end[2] = n;
        m.get = tget; m.put = tput;
        r = argon2id(p, &m, tag);
        for (int t = 0; t < 3; t++) free(tier[t]);
    }
    return r;
}

static void hex(const uint8_t *d, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", d[i]); }

int main(int argc, char **argv)
{
    int print = argc > 1 && !strcmp(argv[1], "--print"), fails = 0;
    uint8_t pwd[32], salt[16], secret[8], ad[12], tag[32];
    static const uint8_t RFC[32] = {0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
                                    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59};
    argon2_params p;

    memset(pwd, 1, sizeof pwd); memset(salt, 2, sizeof salt); memset(secret, 3, sizeof secret); memset(ad, 4, sizeof ad);
    memset(&p, 0, sizeof p);
    p.t_cost = 3; p.m_cost_kib = 32; p.lanes = 4; p.taglen = 32;
    p.pwd = pwd; p.pwdlen = sizeof pwd; p.salt = salt; p.saltlen = sizeof salt; p.secret = secret; p.secretlen = sizeof secret; p.ad = ad; p.adlen = sizeof ad;
    if (run(&p, tag, 0) || memcmp(tag, RFC, 32)) { printf("FAIL RFC 9106 Argon2id vector: "); hex(tag, 32); printf("\n"); fails++; }
    else printf("RFC 9106 Argon2id vector: ok\n");
    if (run(&p, tag, 1) || memcmp(tag, RFC, 32)) { printf("FAIL RFC vector through tiers\n"); fails++; }

    {   /* the sets of the PSX probe */
        static const uint8_t PW[] = "psx-mempool-probe";
        static const struct { uint32_t t, m, p; } SET[] = {{1, 128, 1}, {2, 512, 1}, {3, 256, 2}};
        uint8_t s16[16], t2[32];

        memset(s16, 0x5a, sizeof s16);
        for (unsigned i = 0; i < sizeof SET / sizeof SET[0]; i++) {
            memset(&p, 0, sizeof p);
            p.t_cost = SET[i].t; p.m_cost_kib = SET[i].m; p.lanes = SET[i].p; p.taglen = 32;
            p.pwd = PW; p.pwdlen = sizeof PW - 1; p.salt = s16; p.saltlen = sizeof s16;
            if (run(&p, tag, 0) || run(&p, t2, 1) || memcmp(tag, t2, 32)) { printf("FAIL set %u: the tiers change the tag\n", i); fails++; }
            if (print) { printf("t=%u m=%u p=%u: ", SET[i].t, SET[i].m, SET[i].p); hex(tag, 32); printf("\n"); }
        }
    }
    /* bad parameters */
    memset(&p, 0, sizeof p);
    p.t_cost = 1; p.m_cost_kib = 4; p.lanes = 1; p.taglen = 32;
    if (argon2_blocks(&p) != 0) { printf("FAIL: memory below 8 blocks per lane\n"); fails++; }
    p.m_cost_kib = 10; p.lanes = 0;
    if (argon2_blocks(&p) != 0) { printf("FAIL: no lanes\n"); fails++; }
    p.lanes = 1;
    if (argon2_blocks(&p) != 8) { printf("FAIL: m rounds down to a multiple of 4 * lanes (%u)\n", argon2_blocks(&p)); fails++; }
    printf("%s\n", fails ? "FAILED" : "all ok");
    return fails != 0;
}
