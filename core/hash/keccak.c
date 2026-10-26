#include "hash/keccak.h"
#include "util.h"
#include <string.h>

/* Little endian machines only (like keccak_f1600): a lane is eight message bytes copied as they are, 64 bit XORs instead of
 * byte by byte assembly (about 7000 cycles saved per hash on the PSX). */
void keccak256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    enum { RATE = 136 };
    uint64_t st[25] = {0}, blk[RATE / 8];

    while (len >= RATE) {
        for (int i = 0; i < RATE / 8; i++) {
            uint64_t v;
            memcpy(&v, msg + 8 * i, 8);
            st[i] ^= v;
        }
        keccak_f1600(st);
        msg += RATE; len -= RATE;
    }
    memset(blk, 0, sizeof blk);
    memcpy(blk, msg, len);
    ((uint8_t *) blk)[len] ^= 0x01;
    ((uint8_t *) blk)[RATE - 1] ^= 0x80;
    for (int i = 0; i < RATE / 8; i++) st[i] ^= blk[i];
    keccak_f1600(st);
    memcpy(out, st, 32);
    secure_zero(st, sizeof st);
    secure_zero(blk, sizeof blk);
}
