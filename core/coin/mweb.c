#include "coin/mweb.h"
#include <string.h>
#include "util.h"
#include "coin/bech32.h"
#include "ec/secp256k1.h"
#include "hash/blake3.h"

/* SecretKey::FromHash of Litecoin Core: the hash itself when it is a valid scalar, else a rehash with a counter */
static void hash_to_scalar(uint8_t k[32])
{
    uint8_t m[19 + 32 + 4];
    uint32_t counter = 0;

    while (!secp256k1_privkey_verify(k)) {
        memcpy(m, "MWEB hash-to-scalar", 19);
        memcpy(m + 19, k, 32);
        m[51] = (uint8_t) counter;
        m[52] = (uint8_t) (counter >> 8);
        m[53] = (uint8_t) (counter >> 16);
        m[54] = (uint8_t) (counter >> 24);
        blake3_hash(k, m, sizeof m);
        counter++;
    }
}

int mweb_keys(uint8_t A[33], uint8_t B[33], const uint8_t scan[32], const uint8_t spend[32], uint32_t index)
{
    uint8_t msg[37], mi[32], bi[32], ai[32];
    int r = -1;

    msg[0] = 'A';
    msg[1] = (uint8_t) index;
    msg[2] = (uint8_t) (index >> 8);
    msg[3] = (uint8_t) (index >> 16);
    msg[4] = (uint8_t) (index >> 24);
    memcpy(msg + 5, scan, 32);
    blake3_hash(mi, msg, sizeof msg);
    hash_to_scalar(mi);
    memcpy(bi, spend, 32);
    if (secp256k1_privkey_tweak_add(bi, mi)) goto out;
    memcpy(ai, scan, 32);
    if (secp256k1_privkey_mul(ai, bi)) goto out;
    if (secp256k1_pubkey_create(B, bi) || secp256k1_pubkey_create(A, ai)) goto out;
    r = 0;
out:
    secure_zero(msg, sizeof msg);
    secure_zero(mi, sizeof mi);
    secure_zero(bi, sizeof bi);
    secure_zero(ai, sizeof ai);
    return r;
}

int mweb_address(char *out, size_t cap, const char *hrp, const uint8_t scan[32], const uint8_t spend[32], uint32_t index)
{
    uint8_t ab[66], d5[1 + 106];
    int n;

    if (mweb_keys(ab, ab + 33, scan, spend, index)) return -1;
    d5[0] = 0;
    n = bech32_convert_bits(d5 + 1, sizeof d5 - 1, ab, sizeof ab, 8, 5, 1);
    if (n < 0) return -1;
    return bech32_encode(out, cap, hrp, d5, (size_t) n + 1, 0);
}
