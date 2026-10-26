#include "coin/xpub.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "coin/bip32.h"
#include "ec/secp256k1.h"
#include "util.h"
#include "tr.h"

static const uint32_t PURPOSE[XPUB_KINDS] = {84, 49, 44, 86, 47};
static const uint32_t VERSION[XPUB_KINDS] = {0x04B24746u, 0x049D7CB2u, 0x0488B21Eu, 0x0488B21Eu, 0};

const char *xpub_name(int kind)
{
    const char *const N[XPUB_KINDS] = {T(TXT_NATIVE_SEGWIT_ZPUB), T(TXT_NESTED_SEGWIT_YPUB), T(TXT_LEGACY_XPUB), T(TXT_TAPROOT_XPUB), T(TXT_BIP47_PAYMENT_CODE)};
    return kind >= 0 && kind < XPUB_KINDS ? N[kind] : "";
}

const char *xpub_path(int kind)
{
    static const char *const P[XPUB_KINDS] = {"m/84'/0'/0'", "m/49'/0'/0'", "m/44'/0'/0'", "m/86'/0'/0'", "m/47'/0'/0'"};
    return kind >= 0 && kind < XPUB_KINDS ? P[kind] : "";
}

/* Bitcoin Core's descriptor checksum (src/script/descriptor.cpp): a BCH code over the characters, three of the groups of a character packed into one more symbol */
static uint64_t polymod(uint64_t c, int val)
{
    uint64_t c0 = c >> 35;
    c = ((c & 0x7ffffffffULL) << 5) ^ (uint64_t) val;
    if (c0 & 1) c ^= 0xf5dee51989ULL;
    if (c0 & 2) c ^= 0xa9fdca3312ULL;
    if (c0 & 4) c ^= 0x1bab10e32dULL;
    if (c0 & 8) c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}

int descriptor_checksum(const char *desc, char out[9])
{
    static const char INPUT[] = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char CS[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint64_t c = 1;
    int cls = 0, clscount = 0;

    for (const char *p = desc; *p; p++) {
        const char *pos = strchr(INPUT, *p);
        int v;
        if (!pos) return -1;
        v = (int) (pos - INPUT);
        c = polymod(c, v & 31);
        cls = cls * 3 + (v >> 5);
        if (++clscount == 3) { c = polymod(c, cls); cls = 0; clscount = 0; }
    }
    if (clscount > 0) c = polymod(c, cls);
    for (int i = 0; i < 8; i++) c = polymod(c, 0);
    c ^= 1;
    for (int i = 0; i < 8; i++) out[i] = CS[(c >> (5 * (7 - i))) & 31];
    out[8] = 0;
    return 0;
}

int xpub_export(char key[XPUB_KEY_MAX], char desc[XPUB_DESC_MAX], const uint8_t seed[64], int kind)
{
    bip32_node n;
    uint8_t mfp[4], pfp[4];
    char xp[XPUB_KEY_MAX], body[XPUB_DESC_MAX - 10], sum[9];
    const char *open, *close;
    int r = -1;

    if (kind < 0 || kind >= XPUB_KINDS) return -1;
    if (kind == XPUB_BIP47) {
        uint8_t pl[81];
        desc[0] = 0;
        if (bip32_master(&n, seed, 64) || bip32_derive(&n, BIP32_HARDENED | 47) || bip32_derive(&n, BIP32_HARDENED | 0) || bip32_derive(&n, BIP32_HARDENED | 0)) goto out;
        memset(pl, 0, sizeof pl);
        pl[0] = 0x47;
        pl[1] = 0x01;                                                   /* version; pl[2] the features: none */
        if (secp256k1_pubkey_create(pl + 3, n.key)) goto out;           /* sign byte and x */
        memcpy(pl + 36, n.chain, 32);
        r = base58check_encode(pl, sizeof pl, key, XPUB_KEY_MAX) < 0 ? -1 : 0;
        goto out;
    }
    if (bip32_master(&n, seed, 64) || bip32_fingerprint(&n, mfp)) goto out;
    if (bip32_derive(&n, BIP32_HARDENED | PURPOSE[kind]) || bip32_derive(&n, BIP32_HARDENED | 0)) goto out;
    if (bip32_fingerprint(&n, pfp) || bip32_derive(&n, BIP32_HARDENED | 0)) goto out;           /* pfp: the parent of the account key */
    if (bip32_serialize_ver(&n, VERSION[kind], 3, pfp, BIP32_HARDENED, key, XPUB_KEY_MAX) < 0) goto out;
    if (bip32_serialize_ver(&n, 0x0488B21Eu, 3, pfp, BIP32_HARDENED, xp, sizeof xp) < 0) goto out;
    switch (kind) {
    case XPUB_BIP84: open = "wpkh("; close = ")"; break;
    case XPUB_BIP49: open = "sh(wpkh("; close = "))"; break;
    case XPUB_BIP44: open = "pkh("; close = ")"; break;
    default: open = "tr("; close = ")"; break;
    }
    snprintf(body, sizeof body, "%s[%02x%02x%02x%02x/%uh/0h/0h]%s/<0;1>/*%s", open, mfp[0], mfp[1], mfp[2], mfp[3], (unsigned) PURPOSE[kind], xp, close);
    if (descriptor_checksum(body, sum)) goto out;
    snprintf(desc, XPUB_DESC_MAX, "%s#%s", body, sum);
    r = 0;
out:
    secure_zero(&n, sizeof n);
    return r;
}
