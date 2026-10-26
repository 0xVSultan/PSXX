#include "coin/cardano.h"
#include <string.h>
#include "util.h"
#include "coin/bech32.h"
#include "ec/ed25519.h"
#include "hash/blake2b.h"
#include "hash/sha512.h"

void cardano_icarus_master(uint8_t node[96], const uint8_t *entropy, size_t entlen, const char *password)
{
    uint8_t t[96];
    /* PBKDF2-HMAC-SHA512 with the password as the key and the entropy as the salt (the opposite of BIP39) */
    pbkdf2_hmac_sha512((const uint8_t *) password, strlen(password), entropy, entlen, 4096, t, 96);
    t[0] &= 0xF8;
    t[31] &= 0x1F;
    t[31] |= 0x40;
    memcpy(node, t, 96);
    secure_zero(t, sizeof t);
}

/* a = a + 8 * z28 (256 bit little endian, z28 = the first 28 bytes of z) and b = b + z[32..64], both mod 2^256 */
static void add_scalars(uint8_t kl[32], uint8_t kr[32], const uint8_t z[64])
{
    uint32_t carry = 0;
    uint8_t mul8[32];
    memset(mul8, 0, sizeof mul8);
    for (int i = 0; i < 28; i++) {                      /* 8 * z28: shift left by 3 over 29 bytes */
        uint32_t v = (uint32_t) z[i] << 3;
        mul8[i] |= (uint8_t) v;
        mul8[i + 1] |= (uint8_t) (v >> 8);
    }
    for (int i = 0; i < 32; i++) {
        uint32_t v = (uint32_t) kl[i] + mul8[i] + carry;
        kl[i] = (uint8_t) v;
        carry = v >> 8;
    }
    carry = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t v = (uint32_t) kr[i] + z[32 + i] + carry;
        kr[i] = (uint8_t) v;
        carry = v >> 8;
    }
}

void cardano_derive(uint8_t node[96], uint32_t index)
{
    uint8_t msg[1 + 64 + 4], z[64], c[64];
    uint8_t *kl = node, *kr = node + 32, *cc = node + 64;
    size_t ml;
    uint8_t ib[4] = {(uint8_t) index, (uint8_t) (index >> 8), (uint8_t) (index >> 16), (uint8_t) (index >> 24)};

    if (index & 0x80000000u) {
        msg[0] = 0x00;
        memcpy(msg + 1, kl, 32);
        memcpy(msg + 33, kr, 32);
        memcpy(msg + 65, ib, 4);
        ml = 69;
        hmac_sha512(cc, 32, msg, ml, z);
        msg[0] = 0x01;
        hmac_sha512(cc, 32, msg, ml, c);
    } else {
        msg[0] = 0x02;
        cardano_pubkey(msg + 1, node);
        memcpy(msg + 33, ib, 4);
        ml = 37;
        hmac_sha512(cc, 32, msg, ml, z);
        msg[0] = 0x03;
        hmac_sha512(cc, 32, msg, ml, c);
    }
    add_scalars(kl, kr, z);
    memcpy(cc, c + 32, 32);
    secure_zero(msg, sizeof msg);
    secure_zero(z, sizeof z);
    secure_zero(c, sizeof c);
}

void cardano_derive_path(uint8_t node[96], const hd_path *p)
{
    for (int i = 0; i < p->n; i++) cardano_derive(node, p->idx[i]);
}

void cardano_pubkey(uint8_t pub[32], const uint8_t node[96]) { ed25519_scalarmult_base(pub, node); }

int cardano_base_address(char *out, size_t cap, const uint8_t pay_pub[32], const uint8_t stake_pub[32])
{
    uint8_t b[57], d5[96];
    int n;
    b[0] = 0x01;
    blake2b(b + 1, 28, pay_pub, 32);
    blake2b(b + 29, 28, stake_pub, 32);
    n = bech32_convert_bits(d5, sizeof d5, b, 57, 8, 5, 1);
    if (n < 0) return -1;
    return bech32_encode(out, cap, "addr", d5, (size_t) n, 0);
}

int cardano_enterprise_address(char *out, size_t cap, const uint8_t pay_pub[32])
{
    uint8_t b[29], d5[48];
    int n;
    b[0] = 0x61;
    blake2b(b + 1, 28, pay_pub, 32);
    n = bech32_convert_bits(d5, sizeof d5, b, 29, 8, 5, 1);
    if (n < 0) return -1;
    return bech32_encode(out, cap, "addr", d5, (size_t) n, 0);
}
