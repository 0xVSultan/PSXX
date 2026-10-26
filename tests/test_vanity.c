/* The vanity search kernel of secp256k1 (core/ec/secp_van.c): every candidate point of a batch, P0 +- i G, must be the public key of the candidate's secret
 * key, over several batches (P0 moving on by VAN_N G); start keys near 0 and near n are refused or work. */
#include <stdio.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "ec/secp_van.h"
#include "ec/bn.h"
#include "ec/ec_consts.h"

static const uint32_t FN[8] = SECP_N;
static van_ctx c;                                        /* 128 KB at VAN_N 512 */

static int check(int batches, int *total)
{
    int bad = 0;
    for (int b = 0; b < batches; b++) {
        secp256k1_van_prepare(&c);
        for (int i = 0; i < VAN_N; i++) for (int neg = 0; neg < 2; neg++) {
            uint8_t x[32], y[32], key[32], wx[32], wy[32], xo[32];
            secp256k1_van_point(&c, i, neg, x, y);
            secp256k1_van_point(&c, i, neg, xo, NULL);
            secp256k1_van_key(&c, i, neg, key);
            (*total)++;
            if (secp256k1_pubkey_xy(wx, wy, key) || memcmp(wx, x, 32) || memcmp(wy, y, 32) || memcmp(wx, xo, 32)) {
                bad++;
                if (bad < 5) printf("FAIL batch %d i %d neg %d\n", b, i, neg);
            }
        }
        secp256k1_van_advance(&c);
    }
    return bad;
}

static void be_of(uint8_t s[32], uint32_t lo)           /* a small number */
{
    memset(s, 0, 32);
    s[28] = (uint8_t) (lo >> 24); s[29] = (uint8_t) (lo >> 16); s[30] = (uint8_t) (lo >> 8); s[31] = (uint8_t) lo;
}

int main(void)
{
    uint8_t s[32];
    int total = 0, bad = 0;

    for (int i = 0; i < 32; i++) s[i] = (uint8_t) (i * 37 + 11);
    if (secp256k1_van_init(&c, s)) { printf("init failed\n"); return 1; }
    bad += check(3, &total);
    {
        uint32_t k[8], one[8] = {VAN_N + 4000, 0, 0, 0, 0, 0, 0, 0};
        bn_sub(k, FN, one);                              /* n - (VAN_N + 4000): the batches reach past n */
        bn_to_be(s, k);
    }
    if (secp256k1_van_init(&c, s)) { printf("init failed\n"); return 1; }
    bad += check(3, &total);
    be_of(s, VAN_N + 4000);                              /* a small start key */
    if (secp256k1_van_init(&c, s)) { printf("init failed\n"); return 1; }
    bad += check(3, &total);
    be_of(s, VAN_N); if (!secp256k1_van_init(&c, s)) { printf("a start key of %d was accepted\n", VAN_N); bad++; }
    be_of(s, 0); if (!secp256k1_van_init(&c, s)) { printf("a start key of 0 was accepted\n"); bad++; }
    {
        uint32_t k[8], one[8] = {VAN_N, 0, 0, 0, 0, 0, 0, 0};
        bn_sub(k, FN, one);
        bn_to_be(s, k);
        if (!secp256k1_van_init(&c, s)) { printf("a start key of n - %d was accepted\n", VAN_N); bad++; }
    }
    printf("vanity kernel: %d candidates, %d bad\n", total, bad);
    return bad != 0;
}
