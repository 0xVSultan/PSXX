#include "coin/addr.h"
#include "coin/base58.h"
#include "coin/bech32.h"
#include "ec/secp256k1.h"
#include "hash/keccak.h"
#include "hash/ripemd160.h"
#include "util.h"
#include <string.h>

int addr_p2pkh(char *out, size_t cap, uint8_t version, const uint8_t pub33[33])
{
    uint8_t raw[21];
    raw[0] = version;
    hash160(pub33, 33, raw + 1);
    return base58check_encode(raw, sizeof raw, out, cap);
}

int addr_wif(char *out, size_t cap, uint8_t version, const uint8_t priv[32])
{
    uint8_t raw[34];
    raw[0] = version;
    memcpy(raw + 1, priv, 32);
    raw[33] = 0x01;                      /* compressed public key flag */
    int r = base58check_encode(raw, sizeof raw, out, cap);
    secure_zero(raw, sizeof raw);
    return r;
}

int addr_p2wpkh(char *out, size_t cap, const char *hrp, const uint8_t pub33[33])
{
    uint8_t h[20];
    hash160(pub33, 33, h);
    return segwit_addr_encode(out, cap, hrp, 0, h, sizeof h);
}

int addr_eth20(char *out, size_t cap, const uint8_t a[20])
{
    static const char HEX[] = "0123456789abcdef";
    uint8_t hh[32];
    char lower[40];
    if (cap < 43) return -1;
    for (int i = 0; i < 20; i++) {
        lower[2*i]     = HEX[a[i] >> 4];
        lower[2*i + 1] = HEX[a[i] & 15];
    }
    keccak256((const uint8_t *)lower, 40, hh);            /* EIP-55: hash of the lowercase hex string */
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < 40; i++) {
        uint8_t nib = (hh[i >> 1] >> ((i & 1) ? 0 : 4)) & 15;
        char c = lower[i];
        out[2 + i] = (c >= 'a' && nib >= 8) ? (char)(c - 32) : c;
    }
    out[42] = 0;
    return 42;
}

int addr_eth(char *out, size_t cap, const uint8_t priv[32])
{
    uint8_t pub[65], h[32];
    if (cap < 43 || secp256k1_pubkey_create_uncompressed(pub, priv)) return -1;
    keccak256(pub + 1, 64, h);
    return addr_eth20(out, cap, h + 12);
}

static int bech32_32(char *out, size_t cap, const char *hrp, const uint8_t d[32])
{
    uint8_t v[52];
    int n = bech32_convert_bits(v, sizeof v, d, 32, 8, 5, 1);
    return n < 0 ? -1 : bech32_encode(out, cap, hrp, v, (size_t)n, 0);
}

int addr_npub(char *out, size_t cap, const uint8_t priv[32])
{
    uint8_t pub[33];
    if (secp256k1_pubkey_create(pub, priv)) return -1;
    return bech32_32(out, cap, "npub", pub + 1);
}

int addr_nsec(char *out, size_t cap, const uint8_t priv[32])
{
    return bech32_32(out, cap, "nsec", priv);
}
