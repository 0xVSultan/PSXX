/* An Ethereum address from a public key with a shortened last round: the address is bytes 12..31 of the digest, lanes 1 (upper word), 2 and 3 of the
 * state after the 24th round, and those depend on the five lanes of the first row after rho and pi (the diagonal A[i,i] of the state before the round),
 * so 23 rounds of the permutation are followed by theta (the column sums are needed whole), five rotations and three chi lanes. For the vanity bench. */
#include <stdint.h>
#include <string.h>
#include "vb_keccak23.h"

#define KECCAK_ROUNDS 23
#define keccak_f1600 vk_f1600_23
#ifdef __mips__
#define KECCAK_SCRATCH 1
#endif
#include "../../core/hash/keccak_fast.c"

static inline uint64_t rol(uint64_t x, int n) { return n ? (x << n) | (x >> (64 - n)) : x; }

void vk_eth_address(const uint8_t pub64[64], uint8_t out20[20])
{
    uint64_t a[25] = {0}, c[5], d[5], b[5], r[3];
    static const int ROT[5] = {0, 44, 43, 21, 14};       /* the rotation offsets of the diagonal lanes (x, x) */

    memcpy(a, pub64, 64);
    ((uint8_t *) a)[64] ^= 0x01;
    ((uint8_t *) a)[135] ^= 0x80;
    vk_f1600_23(a);                                      /* the first 23 rounds; round 24 follows, only as far as needed */
    for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (int x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
    for (int x = 0; x < 5; x++) b[x] = rol(a[6 * x] ^ d[x], ROT[x]);
    for (int x = 1; x < 4; x++) r[x - 1] = b[x] ^ (~b[x + 1] & b[(x + 2) % 5]);   /* lanes 1, 2, 3 of the new state */
    memcpy(out20, (uint8_t *) &r[0] + 4, 4);             /* bytes 12..15 */
    memcpy(out20 + 4, &r[1], 8);                         /* 16..23 */
    memcpy(out20 + 12, &r[2], 8);                        /* 24..31 */
}
