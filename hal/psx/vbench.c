/* How fast a PSX can search for vanity addresses: the field operations, the hashes and the whole candidate loops of the kinds of address (output on the
 * TTY). The candidates are real: the kernel of core/ec/secp256k1.c (batches of VAN_N points around a start point, one inversion per batch), then the
 * address hash and a compare of the first two bytes. The big tests run for VB_SECONDS seconds of the frame counter. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <psxgpu.h>
#include "timer.h"
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include "hash/keccak.h"
#include "ec/secp256k1.h"
#include "ec/secp_van.h"
#include "vb_keccak23.h"
#include "vb_keccak23g.h"

/* the same hashes compiled with -O2 and unrolled (vb_fast_*.c) */
void vf_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);
void vf_ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vf_hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vf_keccak256(const uint8_t *msg, size_t len, uint8_t out[32]);
void vf_keccak_f1600(uint64_t st[25]);
/* -O2 without unrolling (vb_g_*.c) */
void vg_hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vg_keccak256(const uint8_t *msg, size_t len, uint8_t out[32]);
/* -O1 (vo1_) and -Os (vos_) copies, generated in the CMake file */
void vo1_hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vo1_keccak256(const uint8_t *msg, size_t len, uint8_t out[32]);
void vo1_eth_address(const uint8_t pub64[64], uint8_t out20[20]);
void vos_hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vos_keccak256(const uint8_t *msg, size_t len, uint8_t out[32]);
void vos_eth_address(const uint8_t pub64[64], uint8_t out20[20]);

#ifndef VB_SECONDS
#define VB_SECONDS 6
#endif

static int hz;
static volatile uint32_t sink;
static van_ctx ctx;

/* micro tests: `n` operations per run of the body, repeated until about 20 million cycles have passed (ticks_cycles is called often enough) */
#define MICRO(label, n, ...) do {                                                       \
    uint32_t acc = 0, ops = 0, t0, t1;                                                  \
    while (acc < 20000000u) {                                                           \
        t0 = ticks_cycles();                                                            \
        { __VA_ARGS__; }                                                                \
        t1 = ticks_cycles();                                                            \
        acc += t1 - t0; ops += (n);                                                     \
    }                                                                                   \
    printf("%-36s %7u cycles %6u us %8u /s\n", label, (unsigned) (acc / ops), (unsigned) (acc / ops * 100 / 3387), \
           (unsigned) (33868800u / (acc / ops)));                                       \
} while (0)

/* long tests (a body of several milliseconds is longer than the window of ticks_cycles): the frame counter, 3 seconds; `n` operations per run of the body */
#define LONG(label, n, ...) do {                                                        \
    uint32_t ops = 0;                                                                   \
    int f0 = VSync(-1), last = f0;                                                      \
    while (last - f0 < 3 * hz) { { __VA_ARGS__; } ops += (n); last = VSync(-1); }       \
    printf("%-36s %7u cycles %6u us %8u /s\n", label, (unsigned) ((uint64_t) (last - f0) * 33868800u / hz / ops), \
           (unsigned) ((uint64_t) (last - f0) * 1000000u / hz / ops), (unsigned) ((uint64_t) ops * hz / (last - f0))); \
} while (0)

/* a candidate loop: the body runs for one candidate (i, neg) of the current batch, for VB_SECONDS; reports candidates per second */
#define SEARCH(label, ...) do {                                                         \
    uint32_t n = 0, hits = 0;                                                           \
    int f0, last;                                                                       \
    secp256k1_van_init(&ctx, seed);                                                     \
    f0 = last = VSync(-1);                                                              \
    while (last - f0 < VB_SECONDS * hz) {                                               \
        secp256k1_van_prepare(&ctx);                                                    \
        for (int i = 0; i < VAN_N; i++) for (int neg = 0; neg < 2; neg++) { __VA_ARGS__; n++; } \
        secp256k1_van_advance(&ctx);                                                    \
        last = VSync(-1);                                                               \
    }                                                                                   \
    sink += hits;                                                                       \
    printf("%-36s %8u candidates in %d s = %u /s  (hits %u)\n", label, (unsigned) n, (last - f0) / hz, (unsigned) (n * hz / (uint32_t) (last - f0)), (unsigned) hits); \
} while (0)

/* The same search in two phases: a chunk of PH_CHUNK candidate points is made first, then the chunk is hashed, so that the code of the points and the
 * code of the hash do not push each other out of the instruction cache of the CPU (4 KB). ptf stores the key material of candidate (i, neg) in pb
 * (64 bytes: x then y, or 33 bytes of a compressed key), hf returns 1 for a hit. */
#define PH_CHUNK 128
typedef void (*pt_fn)(int i, int neg, uint8_t *pb);
typedef int (*hash_fn)(const uint8_t *pb);
static uint8_t pbuf[PH_CHUNK][64];

static void phased(const char *label, const uint8_t *seed, pt_fn ptf, hash_fn hf)
{
    uint32_t n = 0, hits = 0;
    int f0, last;

    secp256k1_van_init(&ctx, seed);
    f0 = last = VSync(-1);
    while (last - f0 < VB_SECONDS * hz) {
        secp256k1_van_prepare(&ctx);
        for (int c0 = 0; c0 < 2 * VAN_N; c0 += PH_CHUNK) {
            for (int c = 0; c < PH_CHUNK; c++) ptf((c0 + c) >> 1, (c0 + c) & 1, pbuf[c]);
            for (int c = 0; c < PH_CHUNK; c++) hits += (uint32_t) hf(pbuf[c]);
            n += PH_CHUNK;
        }
        secp256k1_van_advance(&ctx);
        last = VSync(-1);
    }
    sink += hits;
    printf("%-36s %8u candidates in %d s = %u /s  (hits %u)\n", label, (unsigned) n, (last - f0) / hz, (unsigned) (n * hz / (uint32_t) (last - f0)), (unsigned) hits);
}

static void pt_xy(int i, int neg, uint8_t *pb) { secp256k1_van_point(&ctx, i, neg, pb, pb + 32); }
static void pt_comp(int i, int neg, uint8_t *pb) { uint8_t y[32]; secp256k1_van_point(&ctx, i, neg, pb + 1, y); pb[0] = (uint8_t) (2 | (y[31] & 1)); }
static int h_eth(const uint8_t *pb) { uint8_t h[32]; keccak256(pb, 64, h); return h[12] == 0x12 && h[13] == 0x34; }
static int h_eth_o2(const uint8_t *pb) { uint8_t h[32]; vf_keccak256(pb, 64, h); return h[12] == 0x12 && h[13] == 0x34; }
static int h_eth_tail(const uint8_t *pb) { uint8_t a[20]; vk_eth_address(pb, a); return a[0] == 0x12 && a[1] == 0x34; }
static int h_eth_g(const uint8_t *pb) { uint8_t h[32]; vg_keccak256(pb, 64, h); return h[12] == 0x12 && h[13] == 0x34; }
static int h_eth_tail_g(const uint8_t *pb) { uint8_t a[20]; vl_eth_address(pb, a); return a[0] == 0x12 && a[1] == 0x34; }
static int h_btc_g(const uint8_t *pb) { uint8_t h[20]; vg_hash160(pb, 33, h); return h[0] == 0x12 && h[1] == 0x34; }
static int h_btc(const uint8_t *pb) { uint8_t h[20]; hash160(pb, 33, h); return h[0] == 0x12 && h[1] == 0x34; }
static int h_btc_o2(const uint8_t *pb) { uint8_t h[20]; vf_hash160(pb, 33, h); return h[0] == 0x12 && h[1] == 0x34; }

static int h_eth_o1(const uint8_t *pb) { uint8_t h[32]; vo1_keccak256(pb, 64, h); return h[12] == 0x12 && h[13] == 0x34; }
static int h_eth_tail_o1(const uint8_t *pb) { uint8_t a[20]; vo1_eth_address(pb, a); return a[0] == 0x12 && a[1] == 0x34; }
static int h_eth_tail_os(const uint8_t *pb) { uint8_t a[20]; vos_eth_address(pb, a); return a[0] == 0x12 && a[1] == 0x34; }
static int h_btc_o1(const uint8_t *pb) { uint8_t h[20]; vo1_hash160(pb, 33, h); return h[0] == 0x12 && h[1] == 0x34; }

int main(void)
{
    uint8_t seed[32], buf[136], h[32], x[32], y[32], pub[33];
    uint64_t st[25] = {0};
    uint32_t fa[8] = {1, 2, 3, 4, 5, 6, 7, 8}, fb[8] = {9, 8, 7, 6, 5, 4, 3, 2};

    ResetGraph(0);
    ticks_init();
    hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
    printf("psxx vanity bench (%d Hz frame counter, %d s per search test)\n", hz, VB_SECONDS);
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t) (i * 37 + 11);
    for (int i = 0; i < 136; i++) buf[i] = (uint8_t) (i * 7 + 1);
    VSync(0);

    MICRO("field multiplication", 16, for (int k = 0; k < 16; k++) { secp_fe_mul(fa, fa, fb); fa[0] ^= 1; });
    MICRO("field squaring", 16, for (int k = 0; k < 16; k++) { secp_fe_sqr(fa, fa); fa[0] ^= 1; });
    MICRO("field addition", 16, for (int k = 0; k < 16; k++) { secp_fe_add(fa, fa, fb); });
    MICRO("field inversion", 1, secp_fe_inv(fa, fb); fb[0] ^= fa[0]);
    MICRO("sha256 (33 B, one block)", 8, for (int k = 0; k < 8; k++) { sha256(buf, 33, h); buf[0] ^= h[0]; });
    MICRO("ripemd160 (32 B, one block)", 8, for (int k = 0; k < 8; k++) { ripemd160(buf, 32, h); buf[0] ^= h[0]; });
    MICRO("hash160 (33 B)", 8, for (int k = 0; k < 8; k++) { hash160(buf, 33, h); buf[0] ^= h[0]; });
    MICRO("keccak256 (64 B)", 8, for (int k = 0; k < 8; k++) { keccak256(buf, 64, h); buf[0] ^= h[0]; });
    MICRO("keccak256 (85 B, CREATE2)", 8, for (int k = 0; k < 8; k++) { keccak256(buf, 85, h); buf[0] ^= h[0]; });
    MICRO("keccak-f[1600]", 8, for (int k = 0; k < 8; k++) { keccak_f1600(st); st[0] ^= 1; });
    LONG("FRAMES keccak256 -Os", 8, for (int k = 0; k < 8; k++) { keccak256(buf, 64, h); buf[0] ^= h[0]; });
    LONG("FRAMES keccak256 -O2", 8, for (int k = 0; k < 8; k++) { vg_keccak256(buf, 64, h); buf[0] ^= h[0]; });
    LONG("FRAMES ETH tail -O2", 8, for (int k = 0; k < 8; k++) { vl_eth_address(buf, h); buf[0] ^= h[0]; });
    LONG("FRAMES hash160 -Os", 8, for (int k = 0; k < 8; k++) { hash160(buf, 33, h); buf[0] ^= h[0]; });
    LONG("FRAMES hash160 -O2", 8, for (int k = 0; k < 8; k++) { vg_hash160(buf, 33, h); buf[0] ^= h[0]; });
    LONG("FRAMES keccak256 -O1", 8, for (int k = 0; k < 8; k++) { vo1_keccak256(buf, 64, h); buf[0] ^= h[0]; });
    LONG("FRAMES ETH tail -O1", 8, for (int k = 0; k < 8; k++) { vo1_eth_address(buf, h); buf[0] ^= h[0]; });
    LONG("FRAMES ETH tail -Os", 8, for (int k = 0; k < 8; k++) { vos_eth_address(buf, h); buf[0] ^= h[0]; });
    LONG("FRAMES hash160 -O1", 8, for (int k = 0; k < 8; k++) { vo1_hash160(buf, 33, h); buf[0] ^= h[0]; });

    secp256k1_van_init(&ctx, seed);
    LONG("batch prepare (VAN_N points)", 1, secp256k1_van_prepare(&ctx));
    LONG("candidate point, x only", VAN_N, for (int i = 0; i < VAN_N; i++) secp256k1_van_point(&ctx, i, 0, x, NULL); sink += x[0]);
    LONG("candidate point, x and y", VAN_N, for (int i = 0; i < VAN_N; i++) secp256k1_van_point(&ctx, i, 0, x, y); sink += x[0]);
    LONG("advance (P0 += VAN_N G)", 1, secp256k1_van_advance(&ctx));

    /* whole candidate loops */
    SEARCH("npub / Kaspa (x only, compare)", { secp256k1_van_point(&ctx, i, neg, x, NULL); hits += (x[0] == 0x12 && x[1] == 0x34); });
    SEARCH("ETH (x,y, keccak256, compare)", { secp256k1_van_point(&ctx, i, neg, buf, buf + 32); keccak256(buf, 64, h); hits += (h[12] == 0x12 && h[13] == 0x34); });
    SEARCH("BTC bech32 / legacy (hash160)", { secp256k1_van_point(&ctx, i, neg, pub + 1, y); pub[0] = (uint8_t) (2 | (y[31] & 1)); hash160(pub, 33, h); hits += (h[0] == 0x12 && h[1] == 0x34); });
    phased("ETH in phases, keccak -Os", seed, pt_xy, h_eth);
    phased("ETH in phases, keccak -O2", seed, pt_xy, h_eth_g);
    phased("ETH in phases, tail -O2", seed, pt_xy, h_eth_tail_g);
    phased("ETH in phases, keccak -O1", seed, pt_xy, h_eth_o1);
    phased("ETH in phases, tail -O1", seed, pt_xy, h_eth_tail_o1);
    phased("ETH in phases, tail -Os", seed, pt_xy, h_eth_tail_os);
    phased("BTC bech32 in phases, hash160 -Os", seed, pt_comp, h_btc);
    phased("BTC bech32 in phases, hash160 -O2", seed, pt_comp, h_btc_g);
    phased("BTC bech32 in phases, hash160 -O1", seed, pt_comp, h_btc_o1);
    SEARCH("BTC nested 3... (two hash160)", { uint8_t s2[22] = {0, 20}; secp256k1_van_point(&ctx, i, neg, pub + 1, y); pub[0] = (uint8_t) (2 | (y[31] & 1)); hash160(pub, 33, h); memcpy(s2 + 2, h, 20); hash160(s2, 22, h); hits += (h[0] == 0x12 && h[1] == 0x34); });
    SEARCH("EVM CREATE (key, keccak x2)", { uint8_t r[23] = {0xd6, 0x94}; secp256k1_van_point(&ctx, i, neg, buf, buf + 32); keccak256(buf, 64, h); memcpy(r + 2, h + 12, 20); r[22] = 0x80; keccak256(r, 23, h); hits += (h[12] == 0x12 && h[13] == 0x34); });
    {   /* CREATE2: no curve at all, a counter in the salt */
        uint32_t n = 0, hits = 0, ctr = 0;
        int f0 = VSync(-1), last = f0;
        buf[0] = 0xff;
        while (last - f0 < VB_SECONDS * hz) {
            for (int k = 0; k < 64; k++) {
                ctr++;
                memcpy(buf + 21, &ctr, 4);                      /* the salt (low bytes) */
                keccak256(buf, 85, h);
                hits += (h[12] == 0x12 && h[13] == 0x34);
                n++;
            }
            last = VSync(-1);
        }
        sink += hits;
        printf("%-36s %8u candidates in %d s = %u /s  (hits %u)\n", "CREATE2 (keccak256 of 85 B)", (unsigned) n, (last - f0) / hz, (unsigned) (n * hz / (uint32_t) (last - f0)), (unsigned) hits);
    }
    printf("vanity bench done\n");
    for (;;) VSync(0);
    return 0;
}
