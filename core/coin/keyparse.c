#include "coin/keyparse.h"
#include "ec/ed25519.h"
#include "hash/sha256.h"
#include "util.h"
#include <string.h>

extern uint16_t crc16_xmodem(const uint8_t *p, size_t n);          /* core/coin/chains.c */

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const uint8_t ORDER[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                  0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int keyparse_hex32(const char *s, uint8_t out[32])
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;               /* wallets write an Ethereum key with 0x */
    if (strlen(s) != 64) return KP_ERR_FORMAT;
    for (int i = 0; i < 32; i++) {
        int hi = hexv(s[2 * i]), lo = hexv(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return KP_ERR_FORMAT;
        out[i] = (uint8_t) (hi << 4 | lo);
    }
    return KP_OK;
}

static int in_range(const uint8_t k[32])
{
    int zero = 1;
    for (int i = 0; i < 32; i++) if (k[i]) zero = 0;
    return !zero && memcmp(k, ORDER, 32) < 0;
}

/* bech32 (not bech32m): the human readable part (lower case, up to 15 characters) and the bytes of the data (5 bit groups to bytes, the spare bits zero); the length or an error */
static int bech32_data(const char *s, char hrp[16], uint8_t *out, size_t cap)
{
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    size_t n = strlen(s), sep = 0, hl;
    uint8_t v[260];
    uint32_t chk = 1;
    int upper = 0, lower = 0, acc = 0, bits = 0, o = 0;

    if (n < 8 || n > 250) return KP_ERR_FORMAT;
    for (size_t i = 0; i < n; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') lower = 1;
        if (s[i] >= 'A' && s[i] <= 'Z') upper = 1;
        if (s[i] == '1') sep = i;
    }
    if ((upper && lower) || sep < 1 || sep > 15 || n - sep - 1 < 6) return KP_ERR_FORMAT;
    hl = sep;
    for (size_t i = 0; i < hl; i++) hrp[i] = (char) (s[i] >= 'A' && s[i] <= 'Z' ? s[i] + 32 : s[i]);
    hrp[hl] = 0;
    for (size_t i = 0; i < n - sep - 1; i++) {
        char c = s[sep + 1 + i];
        const char *p;

        if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
        p = memchr(B32, c, 32);
        if (!p || !c) return KP_ERR_FORMAT;
        v[i] = (uint8_t) (p - B32);
    }
    {
        size_t nv = n - sep - 1;
        uint8_t h[40];
        size_t nh = 0;

        for (size_t i = 0; i < hl; i++) h[nh++] = (uint8_t) hrp[i] >> 5;
        h[nh++] = 0;
        for (size_t i = 0; i < hl; i++) h[nh++] = (uint8_t) hrp[i] & 31;
        for (size_t i = 0; i < nh + nv; i++) {
            uint32_t b = chk >> 25;

            chk = (chk & 0x1ffffff) << 5 ^ (i < nh ? h[i] : v[i - nh]);
            for (int k = 0; k < 5; k++) if ((b >> k) & 1) chk ^= GEN[k];
        }
        if (chk != 1) return KP_ERR_CHECKSUM;
        for (size_t i = 0; i + 6 < nv; i++) {
            acc = acc << 5 | v[i];
            bits += 5;
            if (bits >= 8) { bits -= 8; if ((size_t) o >= cap) return KP_ERR_FORMAT; out[o++] = (uint8_t) (acc >> bits); acc &= (1 << bits) - 1; }
        }
        if (acc) return KP_ERR_FORMAT;
    }
    return o;
}

/* an nsec: the human readable part "nsec", 32 bytes */
static int nsec_decode(const char *s, uint8_t out[32])
{
    char hrp[16];
    int n = bech32_data(s, hrp, out, 32);

    if (n < 0) return n;
    return n == 32 && !strcmp(hrp, "nsec") ? KP_OK : KP_ERR_FORMAT;
}

/* Base58 to bytes (big endian); the length, or a negative error */
static int b58_decode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s), len = 0, zeros = 0;
    uint8_t buf[80];

    if (cap > sizeof buf) cap = sizeof buf;
    memset(buf, 0, sizeof buf);
    while (zeros < n && s[zeros] == '1') zeros++;
    for (size_t i = 0; i < n; i++) {
        const char *p = memchr(B58, s[i], 58);
        uint32_t carry;

        if (!p || !s[i]) return KP_ERR_FORMAT;
        carry = (uint32_t) (p - B58);
        for (size_t j = 0; j < len || carry; j++) {                      /* buf holds the number little endian */
            if (j >= cap) return KP_ERR_FORMAT;
            carry += (uint32_t) buf[j] * 58;
            buf[j] = (uint8_t) carry;
            carry >>= 8;
            if (j >= len) len = j + 1;
        }
    }
    if (len + zeros > cap) return KP_ERR_FORMAT;
    for (size_t i = 0; i < len; i++) out[zeros + i] = buf[len - 1 - i];
    memset(out, 0, zeros);
    secure_zero(buf, sizeof buf);
    return (int) (len + zeros);
}

/* Base58Check: the payload (version, key, optional 0x01) of a WIF */
static int wif_decode(const char *s, uint8_t out[32])
{
    uint8_t buf[40], h[32];
    size_t n = strlen(s);
    int len;

    if (n < 50 || n > 53) return KP_ERR_FORMAT;
    len = b58_decode(s, buf, sizeof buf);
    if (len != 37 && len != 38) return KP_ERR_FORMAT;                   /* version + 32 (+ flag) + 4 */
    sha256(buf, (size_t) len - 4, h);
    sha256(h, 32, h);
    if (memcmp(h, buf + len - 4, 4)) { secure_zero(buf, sizeof buf); return KP_ERR_CHECKSUM; }
    if (len == 38 && buf[33] != 0x01) { secure_zero(buf, sizeof buf); return KP_ERR_FORMAT; }
    memcpy(out, buf + 1, 32);
    secure_zero(buf, sizeof buf);
    return KP_OK;
}

static int is_hex_form(const char *s)
{
    size_t n = strlen(s);

    return n == 64 || (n == 66 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'));
}

int keyparse_secp256k1(const char *s, uint8_t out[32])
{
    int r;

    if (!strncmp(s, "nsec1", 5) || !strncmp(s, "NSEC1", 5)) r = nsec_decode(s, out);
    else if (is_hex_form(s)) r = keyparse_hex32(s, out);
    else r = wif_decode(s, out);
    if (r == KP_OK && !in_range(out)) { secure_zero(out, 32); return KP_ERR_RANGE; }
    return r;
}

/* Stellar "S...": base32 of 0x90, the 32 byte seed and the CRC-16 (XMODEM, little endian) */
static int stellar_decode(const char *s, uint8_t out[32])
{
    static const char A32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    uint8_t b[35];
    uint32_t acc = 0;
    int bits = 0, o = 0;
    uint16_t crc;

    if (strlen(s) != 56) return KP_ERR_FORMAT;
    for (int i = 0; i < 56; i++) {
        char c = s[i];
        const char *p;

        if (c >= 'a' && c <= 'z') c = (char) (c - 32);
        p = memchr(A32, c, 32);
        if (!p || !c) return KP_ERR_FORMAT;
        acc = acc << 5 | (uint32_t) (p - A32);
        bits += 5;
        if (bits >= 8) { bits -= 8; if (o >= 35) return KP_ERR_FORMAT; b[o++] = (uint8_t) (acc >> bits); acc &= (1u << bits) - 1; }
    }
    if (o != 35 || acc || b[0] != 18 << 3) return KP_ERR_FORMAT;
    crc = crc16_xmodem(b, 33);
    if (b[33] != (uint8_t) crc || b[34] != (uint8_t) (crc >> 8)) return KP_ERR_CHECKSUM;
    memcpy(out, b + 1, 32);
    secure_zero(b, sizeof b);
    return KP_OK;
}

int keyparse_ed25519(const char *s, uint8_t out[32])
{
    uint8_t b[72], pub[32];
    int n;

    if (!strncmp(s, "ed25519:", 8)) s += 8;                              /* NEAR */
    if (strlen(s) == 56 && (s[0] == 'S' || s[0] == 's')) return stellar_decode(s, out);
    if (is_hex_form(s)) return keyparse_hex32(s, out);
    n = b58_decode(s, b, sizeof b);                                     /* Solana, NEAR: the seed, or the keypair (seed and public key) */
    if (n == 32) { memcpy(out, b, 32); secure_zero(b, sizeof b); return KP_OK; }
    if (n != 64) { secure_zero(b, sizeof b); return n < 0 ? n : KP_ERR_FORMAT; }
    ed25519_pubkey_from_seed(pub, b);
    if (memcmp(pub, b + 32, 32)) { secure_zero(b, sizeof b); return KP_ERR_CHECKSUM; }      /* the public key in the keypair is not the key of the seed */
    memcpy(out, b, 32);
    secure_zero(b, sizeof b);
    return KP_OK;
}

/* a Cardano extended key: 128 hex digits (kL | kR), or a bech32 "addr_xsk1..." / "acct_xsk1..." / "root_xsk1..." / "stake_xsk1..." (kL | kR | chain code, 96 bytes: the chain code is
 * not needed to sign); kL has to be a clamped scalar of the BIP32-Ed25519 kind (the low 3 bits clear, the top bit clear) */
int keyparse_cardano(const char *s, uint8_t out[64])
{
    uint8_t b[96];
    char hrp[16];
    int n;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (strlen(s) == 128) {
        for (int i = 0; i < 64; i++) {
            int hi = hexv(s[2 * i]), lo = hexv(s[2 * i + 1]);

            if (hi < 0 || lo < 0) return KP_ERR_FORMAT;
            b[i] = (uint8_t) (hi << 4 | lo);
        }
        n = 64;
    } else {
        n = bech32_data(s, hrp, b, sizeof b);
        if (n < 0) return n;
        if (n != 96 || strlen(hrp) < 5 || strcmp(hrp + strlen(hrp) - 4, "_xsk")) return KP_ERR_FORMAT;
    }
    if ((b[0] & 7) || (b[31] & 0x80)) { secure_zero(b, sizeof b); return KP_ERR_RANGE; }
    memcpy(out, b, 64);
    secure_zero(b, sizeof b);
    return KP_OK;
}
