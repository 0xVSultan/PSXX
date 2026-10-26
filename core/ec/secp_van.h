#pragma once
/* Vanity search kernel of secp256k1. The candidates P0 +- i*G, i = 1..VAN_N, of one start point P0 = (s + base) G share one field inversion (Montgomery's trick),
 * and P0 moves on by 2*VAN_N*G between batches (one more inversion): the batch covers P0 - VAN_N .. P0 + VAN_N (P0 itself not), so the next one starts where it ends. (A step of
 * VAN_N*G made every batch repeat half of the one before it, and every search took twice as many candidates as the estimate said.) The affine point of a candidate costs 4 multiplications (x only) or 6 (x and y) plus the
 * share of the batch inversion (about 5 400 cycles a candidate on a PSX at VAN_N = 256, 4 800 at 384, 4 500 at 512, 3 900 at 1024). The secret key of a candidate is s + base +- i mod n.
 * Built on the field operations of secp256k1.c (secp_fe_*), so it lives in the overlay and the base keeps the arithmetic only once. The tables take 128 bytes a point: 32 KB of RAM at 256 points. */
#include <stdint.h>

#define VAN_N 256

typedef struct {
    uint32_t x0[8], y0[8];                       /* P0 */
    uint32_t dx[8], dy[8];                       /* 2*VAN_N*G, what P0 moves on by */
    uint32_t tx[VAN_N][8], ty[VAN_N][8];         /* i*G for i = 1..VAN_N (entry i - 1) */
    uint32_t dinv[VAN_N][8], pre[VAN_N][8];
    uint8_t  s[32];                              /* the start key, big endian */
    uint64_t base;                               /* P0 = (s + base) G */
    uint32_t pinv[8];                            /* prepare_step: the running inverse */
    int      pphase, pi;                         /* prepare_step: where it is */
} van_ctx;

/* 0, or -1 for a bad start key (or one that puts P0 within VAN_N of the point at infinity: 1 .. VAN_N or n - VAN_N .. n - 1, where two points of a batch would
 * coincide). Builds the table of multiples (VAN_N mixed additions and one inversion). */
int  secp256k1_van_init(van_ctx *c, const uint8_t s[32]);
/* the inverses for the batch of the current P0, all at once (about 0.2 s) */
void secp256k1_van_prepare(van_ctx *c);
/* the same in steps of about `n` points (n * 8 000 cycles, plus one inversion of 12 ms in between); returns 1 when the batch is ready */
int  secp256k1_van_prepare_step(van_ctx *c, int n);
/* candidate i (0 .. VAN_N - 1) of the batch: P0 + (i+1) G, or P0 - (i+1) G when neg; x always, y when y != NULL (big endian, reduced) */
void secp256k1_van_point(const van_ctx *c, int i, int neg, uint8_t x[32], uint8_t *y);
/* P0 += 2 VAN_N G */
void secp256k1_van_advance(van_ctx *c);
/* the secret key of a candidate */
void secp256k1_van_key(const van_ctx *c, int i, int neg, uint8_t key[32]);
