/* The copies of the hashes of the vanity bench (hal/psx/vb_fast_*.c) and the Ethereum address with the shortened last round (vb_keccak23.c)
 * against the normal functions. */
#include <stdio.h>
#include <string.h>
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include "hash/keccak.h"
#include "../hal/psx/vb_keccak23.h"

void vf_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);
void vf_ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vf_hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
void vf_keccak256(const uint8_t *msg, size_t len, uint8_t out[32]);

int main(void)
{
    uint8_t m[200], a[32], b[32];
    int bad = 0, n = 0;

    for (int len = 0; len <= 200; len += (len < 140 ? 1 : 20)) {
        for (int i = 0; i < len; i++) m[i] = (uint8_t) (i * 31 + len * 7 + 5);
        sha256(m, len, a); vf_sha256(m, len, b); bad += !!memcmp(a, b, 32);
        ripemd160(m, len, a); vf_ripemd160(m, len, b); bad += !!memcmp(a, b, 20);
        hash160(m, len, a); vf_hash160(m, len, b); bad += !!memcmp(a, b, 20);
        keccak256(m, len, a); vf_keccak256(m, len, b); bad += !!memcmp(a, b, 32);
        n += 4;
    }
    for (int t = 0; t < 2000; t++) {                    /* addresses: the last 20 bytes of keccak256 of 64 bytes */
        uint8_t o[20];
        for (int i = 0; i < 64; i++) m[i] = (uint8_t) (i * 131 + t * 17 + (t >> 3) * 59);
        keccak256(m, 64, a);
        vk_eth_address(m, o);
        bad += !!memcmp(a + 12, o, 20);
        n++;
    }
    printf("vanity bench hashes: %d checks, %d bad\n", n, bad);
    return bad != 0;
}
