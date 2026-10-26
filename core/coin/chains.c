#include "coin/chains.h"
#include <string.h>
#include "util.h"
#include "coin/addr.h"
#include "coin/base58.h"
#include "coin/bech32.h"
#include "coin/bip32.h"
#include "coin/cardano.h"
#include "coin/substrate.h"
#include "coin/ton.h"
#include "coin/orchard.h"
#include "coin/mweb.h"
#include "ec/ed25519.h"
#include "ec/secp256k1.h"
#include "hash/blake2b.h"
#include "hash/keccak.h"
#include "hash/ripemd160.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "tr.h"

/* ---- the table ---- */

const chain_def CHAINS[] = {
    /* id       name                           curve          kind          param  hrp           path */
    {"btc84",  TXT_BITCOIN_SEGWIT_BC1Q,       CV_SECP256K1, K_P2WPKH,     0,    "bc",         "m/84'/0'/0'/0/0", 0},
    {"btc86",  TXT_BITCOIN_TAPROOT_BC1P,      CV_SECP256K1, K_P2TR,       0,    "bc",         "m/86'/0'/0'/0/0", 0},
    {"btc49",  TXT_BITCOIN_NESTED_SEGWIT_3, CV_SECP256K1, K_P2SH_WPKH,  0x05, NULL,         "m/49'/0'/0'/0/0", 0},
    {"btc44",  TXT_BITCOIN_LEGACY_1,       CV_SECP256K1, K_P2PKH,      0x00, NULL,         "m/44'/0'/0'/0/0", 0},
    {"ltc84",  TXT_LITECOIN_SEGWIT_LTC1,      CV_SECP256K1, K_P2WPKH,     0,    "ltc",        "m/84'/2'/0'/0/0", 0},
    {"ltc49",  TXT_LITECOIN_NESTED_SEGWIT_M,  CV_SECP256K1, K_P2SH_WPKH,  0x32, NULL,         "m/49'/2'/0'/0/0", 0},
    {"ltc44",  TXT_LITECOIN_LEGACY_L,         CV_SECP256K1, K_P2PKH,      0x30, NULL,         "m/44'/2'/0'/0/0", 0},
    {"ltcmweb", TXT_LITECOIN_MWEB_LTCMWEB1,    CV_SECP256K1, K_MWEB,       0,    "ltcmweb",    "m/0'/100'/0'/2", 0},
    {"doge",   TXT_DOGECOIN,                    CV_SECP256K1, K_P2PKH,      0x1e, NULL,         "m/44'/3'/0'/0/0", 0},
    {"dash",   TXT_DASH,                        CV_SECP256K1, K_P2PKH,      0x4c, NULL,         "m/44'/5'/0'/0/0", 0},
    {"bch",    TXT_BITCOIN_CASH_CASHADDR,     CV_SECP256K1, K_CASHADDR,   0,    "bitcoincash", "m/44'/145'/0'/0/0", 0},
    {"eth",    TXT_ETHEREUM_AND_EVM_CHAINS,     CV_SECP256K1, K_EVM,        0,    NULL,         "m/44'/60'/0'/0/0", 1},
    {"etc",    TXT_ETHEREUM_CLASSIC,            CV_SECP256K1, K_EVM,        0,    NULL,         "m/44'/61'/0'/0/0", 1},
    {"trx",    TXT_TRON,                        CV_SECP256K1, K_TRON,       0,    NULL,         "m/44'/195'/0'/0/0", 1},
    {"xrp",    TXT_XRP,                         CV_SECP256K1, K_XRP,        0,    NULL,         "m/44'/144'/0'/0/0", 1},
    {"atom",   TXT_COSMOS_HUB,                  CV_SECP256K1, K_COSMOS,     0,    "cosmos",     "m/44'/118'/0'/0/0", 1},
    {"osmo",   TXT_OSMOSIS,                     CV_SECP256K1, K_COSMOS,     0,    "osmo",       "m/44'/118'/0'/0/0", 1},
    {"sol",    TXT_SOLANA,                      CV_ED25519,   K_SOLANA,     0,    NULL,         "m/44'/501'/0'/0'", 2},
    {"xlm",    TXT_STELLAR,                     CV_ED25519,   K_STELLAR,    0,    NULL,         "m/44'/148'/0'", 2},
    {"near",   TXT_NEAR_IMPLICIT_ACCOUNT,     CV_ED25519,   K_NEAR,       0,    NULL,         "m/44'/397'/0'", 2},
    {"dot",    TXT_POLKADOT_ED25519_LEDGER,  CV_ED25519,   K_SS58_ED,    0,    NULL,         "m/44'/354'/0'/0'/0'", 2},
    {"ton",    TXT_TON_V4R2_BIP39_WORDS_LEDGER,   CV_ED25519,   K_TON,        TON_V4R2, NULL,     "m/44'/607'/0'", 2},
    {"ton5",   TXT_TON_V5R1_BIP39_WORDS_LEDGER,   CV_ED25519,   K_TON,        TON_V5R1, NULL,     "m/44'/607'/0'", 2},
    {"zec",    TXT_ZCASH_TRANSPARENT_T1,      CV_SECP256K1, K_ZEC_T,      0,    NULL,         "m/44'/133'/0'/0/0", 3},
    {"zecu",   TXT_ZCASH_ORCHARD_UNIFIED_U1,  CV_ORCHARD,   K_ORCHARD,    0,    NULL,         "m/32'/133'/0'", 3},
    {"nostr",  TXT_NOSTR_NPUB,                CV_SECP256K1, K_NOSTR,      0,    NULL,         "m/44'/1237'/0'/0/0", 3},
    {"kas",    TXT_KASPA_SCHNORR_LEDGER,     CV_SECP256K1, K_KASPA,      0,    "kaspa",      "m/44'/111111'/0'/0/0", 3},
    {"ada",    TXT_CARDANO_SHELLEY_ICARUS,   CV_ICARUS,    K_CARDANO,    0,    NULL,         "m/1852'/1815'/0'/0/0", 3},
    {"dotsr",  TXT_POLKADOT_SR25519,          CV_SR25519,   K_SS58_SR,    0,    NULL,         "", 3},
    {"ksm",    TXT_KUSAMA_SR25519,            CV_SR25519,   K_SS58_SR,    2,    NULL,         "", 3},
};
const int NCHAINS = (int) (sizeof CHAINS / sizeof CHAINS[0]);

const uint16_t CHAIN_GROUPS[NCHAIN_GROUPS] = {TXT_BITCOIN_AND_FORKS, TXT_ETHEREUM_AND_SIMILAR, TXT_ED25519_CHAINS, TXT_SPECIAL, TXT_CUSTOM};

int chain_raw_ok(const chain_def *c, const hd_secret *s)
{
    if (!s->raw_curve) return 0;
    switch (c->kind) {
    case K_MONERO: case K_PUBHEX: case K_MWEB: return 0;
    case K_CARDANO: return s->raw_curve == 5;
    case K_SS58_SR: return s->raw_curve == 3;
    case K_ORCHARD: return s->raw_curve == 4;
    default: break;
    }
    return (c->curve == CV_ED25519 && s->raw_curve == 1) || (c->curve == CV_SECP256K1 && s->raw_curve == 2);
}

const chain_def *chain_find(const char *id)
{
    for (int i = 0; i < NCHAINS; i++) if (!strcmp(CHAINS[i].id, id)) return &CHAINS[i];
    return NULL;
}

int chain_default_path(const chain_def *c, hd_path *p) { return path_parse(p, c->path); }

/* ---- small encoders ---- */

int base32_encode(const uint8_t *in, size_t len, char *out, size_t cap)
{
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            if (o + 1 >= cap) return -1;
            out[o++] = A[(acc >> (bits - 5)) & 31];
            bits -= 5;
        }
        acc &= (1u << bits) - 1;
    }
    if (bits) {
        if (o + 1 >= cap) return -1;
        out[o++] = A[(acc << (5 - bits)) & 31];
    }
    if (o >= cap) return -1;
    out[o] = 0;
    return (int) o;
}

uint16_t crc16_xmodem(const uint8_t *p, size_t n)
{
    uint16_t crc = 0;
    while (n--) {
        crc ^= (uint16_t) (*p++ << 8);
        for (int i = 0; i < 8; i++) crc = (uint16_t) ((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1);
    }
    return crc;
}

static uint64_t cash_polymod_step(uint64_t c, uint8_t d)
{
    uint8_t c0 = (uint8_t) (c >> 35);
    c = ((c & 0x07ffffffffULL) << 5) ^ d;
    if (c0 & 0x01) c ^= 0x98f2bc8e61ULL;
    if (c0 & 0x02) c ^= 0x79b76d99e2ULL;
    if (c0 & 0x04) c ^= 0xf33e5fb3c4ULL;
    if (c0 & 0x08) c ^= 0xae2eabe2a8ULL;
    if (c0 & 0x10) c ^= 0x1e4f43e470ULL;
    return c;
}

/* The checksummed base32 form shared by CashAddr and Kaspa: prefix, ':', the payload in 5 bit groups, 40 bit checksum. */
static int cash_style_encode(char *out, size_t cap, const char *prefix, const uint8_t *payload, size_t plen)
{
    static const char CS[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint8_t d5[56];
    uint64_t c = 1;
    size_t pl = strlen(prefix), o = 0;
    int n = bech32_convert_bits(d5, sizeof d5, payload, plen, 8, 5, 1);
    if (n < 0 || pl + 1 + (size_t) n + 8 + 1 > cap) return -1;
    for (size_t i = 0; i < pl; i++) c = cash_polymod_step(c, (uint8_t) (prefix[i] & 31));
    c = cash_polymod_step(c, 0);
    for (int i = 0; i < n; i++) c = cash_polymod_step(c, d5[i]);
    for (int i = 0; i < 8; i++) c = cash_polymod_step(c, 0);
    c ^= 1;
    memcpy(out, prefix, pl);
    o = pl;
    out[o++] = ':';
    for (int i = 0; i < n; i++) out[o++] = CS[d5[i]];
    for (int i = 0; i < 8; i++) out[o++] = CS[(c >> (5 * (7 - i))) & 31];
    out[o] = 0;
    return (int) o;
}

int cashaddr_encode(char *out, size_t cap, const char *prefix, int type, const uint8_t h160[20])
{
    uint8_t payload[21];
    payload[0] = (uint8_t) (type << 3);              /* version: the address type (0 P2PKH, 1 P2SH), 160 bit hash */
    memcpy(payload + 1, h160, 20);
    return cash_style_encode(out, cap, prefix, payload, 21);
}

int kaspa_address_v(char *out, size_t cap, const char *prefix, int version, const uint8_t *data, size_t dlen)
{
    uint8_t payload[34];
    if (dlen > 33) return -1;
    payload[0] = (uint8_t) version;
    memcpy(payload + 1, data, dlen);
    return cash_style_encode(out, cap, prefix, payload, dlen + 1);
}

int kaspa_address(char *out, size_t cap, const char *prefix, const uint8_t xonly[32])
{
    uint8_t payload[33];
    payload[0] = 0;                                  /* version 0: a schnorr public key */
    memcpy(payload + 1, xonly, 32);
    return cash_style_encode(out, cap, prefix, payload, 33);
}

int cashaddr_p2pkh(char *out, size_t cap, const char *prefix, const uint8_t h160[20]) { return cashaddr_encode(out, cap, prefix, 0, h160); }

int ss58_encode(char *out, size_t cap, uint16_t prefix, const uint8_t pub[32])
{
    static const char PRE[] = "SS58PRE";
    uint8_t buf[1 + 32 + 2], h[64];
    blake2b_ctx c;
    if (prefix > 63) return -1;                      /* two byte prefixes are not needed for the usual networks */
    buf[0] = (uint8_t) prefix;
    memcpy(buf + 1, pub, 32);
    blake2b_init(&c, 64, NULL, 0, NULL, NULL);
    blake2b_update(&c, (const uint8_t *) PRE, 7);
    blake2b_update(&c, buf, 33);
    blake2b_final(&c, h);
    buf[33] = h[0];
    buf[34] = h[1];
    return base58_encode(buf, sizeof buf, out, cap);
}

/* secp256k1 order, for the taproot key negation */
static const uint8_t SECP_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static void tagged_hash(uint8_t out[32], const char *tag, const uint8_t *msg, size_t len)
{
    uint8_t th[32];
    sha256_ctx c;
    sha256((const uint8_t *) tag, strlen(tag), th);
    sha256_init(&c);
    sha256_update(&c, th, 32);
    sha256_update(&c, th, 32);
    sha256_update(&c, msg, len);
    sha256_final(&c, out);
}

/* BIP86 key path output key (no script tree): x-only Q = P + H("TapTweak", P.x) * G, P with even y */
static int taproot_output_key(uint8_t q[32], const uint8_t priv[32])
{
    uint8_t k[32], pub[33], t[32], qpub[33];
    int r = -1;
    memcpy(k, priv, 32);
    if (secp256k1_pubkey_create(pub, k)) goto out;
    if (pub[0] == 3) {                                /* odd y: use n - k */
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int v = (int) SECP_N[i] - (int) priv[i] - borrow;
            borrow = v < 0;
            k[i] = (uint8_t) (v + (borrow ? 256 : 0));
        }
    }
    tagged_hash(t, "TapTweak", pub + 1, 32);
    if (secp256k1_privkey_tweak_add(k, t)) goto out;
    if (secp256k1_pubkey_create(qpub, k)) goto out;
    memcpy(q, qpub + 1, 32);
    r = 0;
out:
    secure_zero(k, sizeof k);
    return r;
}

static void to_hex(char *out, const uint8_t *b, size_t n)
{
    static const char D[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = D[b[i] >> 4]; out[2 * i + 1] = D[b[i] & 15]; }
    out[2 * n] = 0;
}

/* a version prefix of one byte, or of two when the value is above 255 (Zcash 0x1cb8): returns its length */
static int ver_bytes(uint8_t *out, uint16_t v)
{
    if (v > 255) { out[0] = (uint8_t) (v >> 8); out[1] = (uint8_t) v; return 2; }
    out[0] = (uint8_t) v;
    return 1;
}

/* XRP uses the Bitcoin Base58Check with its own alphabet: same digits, other letters */
int xrp_address(char *out, size_t cap, const uint8_t h160[20])
{
    static const char BTC[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static const char XRP[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    uint8_t pl[21];
    int n;
    pl[0] = 0;
    memcpy(pl + 1, h160, 20);
    n = base58check_encode(pl, 21, out, cap);
    for (int i = 0; i < n; i++) out[i] = XRP[strchr(BTC, out[i]) - BTC];
    return n;
}

/* ---- SLIP-10 ed25519 ---- */

int slip10_ed25519(uint8_t key[32], const uint8_t *seed, size_t seedlen, const hd_path *p)
{
    static const char K[] = "ed25519 seed";
    uint8_t i64[64], msg[37];
    if (!path_all_hardened(p)) return CHAIN_ERR_PATH;
    hmac_sha512((const uint8_t *) K, sizeof K - 1, seed, seedlen, i64);
    for (int d = 0; d < p->n; d++) {
        msg[0] = 0;
        memcpy(msg + 1, i64, 32);
        msg[33] = (uint8_t) (p->idx[d] >> 24);
        msg[34] = (uint8_t) (p->idx[d] >> 16);
        msg[35] = (uint8_t) (p->idx[d] >> 8);
        msg[36] = (uint8_t) p->idx[d];
        hmac_sha512(i64 + 32, 32, msg, 37, i64);
    }
    memcpy(key, i64, 32);
    secure_zero(i64, sizeof i64);
    secure_zero(msg, sizeof msg);
    return 0;
}

/* ---- addresses ---- */

/* the ed25519 key of a path, or the raw key */
static int ed_key(uint8_t key[32], const hd_secret *s, const hd_path *p)
{
    if (s->raw_curve) {
        if (s->raw_curve != 1) return CHAIN_ERR_UNSUPPORTED;
        memcpy(key, s->raw, 32);
        return 0;
    }
    return slip10_ed25519(key, s->seed, 64, p);
}

/* the secp256k1 key of a path (the node's other fields are not used by the callers), or the raw key */
static int secp_node(bip32_node *n, const hd_secret *s, const hd_path *p)
{
    if (s->raw_curve) {
        if (s->raw_curve != 2) return -1;
        memset(n, 0, sizeof *n);
        memcpy(n->key, s->raw, 32);
        return 0;
    }
    return bip32_master(n, s->seed, 64) || bip32_derive_path(n, p->idx, p->n);
}


/* MWEB: the scan secret is the node of the first levels of the path, the spend secret its next sibling. Litecoin Core keeps them under m/0'/100' (three levels, m/0'/100'/0'
 * is the scan key); Cake Wallet and Electrum-LTC under m/1000' (two levels, m/1000'/0'), and their first receiving index is 1, not 2 */
static int mweb_secrets(uint8_t scan[32], uint8_t spend[32], uint32_t *index, const hd_secret *s, const hd_path *p)
{
    bip32_node n, m;
    uint32_t sib;
    int r = CHAIN_ERR_DERIVE, cake = p->n && p->idx[0] == (MWEB_CAKE_ROOT | PATH_HARD), lv = cake ? 2 : 3;

    if (s->raw_curve || p->n < lv || p->n > lv + 1 || !(p->idx[lv - 1] & PATH_HARD) || (p->n == lv + 1 && (p->idx[lv] & PATH_HARD))) return CHAIN_ERR_PATH;
    sib = p->idx[lv - 1] == 0xffffffffu ? 0 : p->idx[lv - 1] + 1;
    *index = p->n == lv + 1 ? p->idx[lv] : cake ? MWEB_CAKE_FIRST_INDEX : MWEB_FIRST_INDEX;
    if (bip32_master(&n, s->seed, 64) || bip32_derive_path(&n, p->idx, lv - 1)) goto out;     /* m/0'/100' or m/1000' */
    m = n;
    if (bip32_derive_path(&n, &p->idx[lv - 1], 1) || bip32_derive_path(&m, &sib, 1)) goto out;
    memcpy(scan, n.key, 32);
    memcpy(spend, m.key, 32);
    r = 0;
out:
    secure_zero(&n, sizeof n);
    secure_zero(&m, sizeof m);
    return r;
}

static int addr_mweb(char *out, size_t cap, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    uint8_t scan[32], spend[32];
    uint32_t index;
    int r = mweb_secrets(scan, spend, &index, s, p);

    if (!r) {
        r = mweb_address(out, cap, c->hrp, scan, spend, index);
        if (r < 0) r = CHAIN_ERR_SPACE;
    }
    secure_zero(scan, sizeof scan);
    secure_zero(spend, sizeof spend);
    return r;
}

static int addr_secp(char *out, size_t cap, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    bip32_node n;
    uint8_t pub[33], h[20], tmp[32], pl[22];
    int r = CHAIN_ERR_DERIVE;

    if (secp_node(&n, s, p)) goto out;
    switch (c->kind) {
    case K_EVM: r = addr_eth(out, cap, n.key); break;
    case K_NOSTR: r = addr_npub(out, cap, n.key); break;
    case K_KASPA:
        if (secp256k1_pubkey_create(pub, n.key)) goto out;
        r = kaspa_address(out, cap, c->hrp, pub + 1);                  /* the x coordinate: the key is taken with an even y, as BIP340 does */
        break;
    case K_P2TR:
        if (taproot_output_key(tmp, n.key)) goto out;
        r = segwit_addr_encode(out, cap, c->hrp, 1, tmp, 32);
        break;
    case K_TRON: {
        uint8_t u[65], k32[32];
        if (secp256k1_pubkey_create_uncompressed(u, n.key)) goto out;
        keccak256(u + 1, 64, k32);
        pl[0] = 0x41;
        memcpy(pl + 1, k32 + 12, 20);
        r = base58check_encode(pl, 21, out, cap);
        break;
    }
    default:
        if (secp256k1_pubkey_create(pub, n.key)) goto out;
        hash160(pub, 33, h);
        switch (c->kind) {
        case K_P2PKH: {
            int vl = ver_bytes(pl, c->param);
            memcpy(pl + vl, h, 20);
            r = base58check_encode(pl, (size_t) vl + 20, out, cap);
            break;
        }
        case K_P2SH_WPKH: {
            uint8_t rs[22], h2[20];
            rs[0] = 0x00;
            rs[1] = 0x14;
            memcpy(rs + 2, h, 20);
            int vl;
            hash160(rs, 22, h2);
            vl = ver_bytes(pl, c->param);
            memcpy(pl + vl, h2, 20);
            r = base58check_encode(pl, (size_t) vl + 20, out, cap);
            break;
        }
        case K_P2WPKH: r = segwit_addr_encode(out, cap, c->hrp, 0, h, 20); break;
        case K_CASHADDR: r = cashaddr_p2pkh(out, cap, c->hrp, h); break;
        case K_ZEC_T:
            pl[0] = 0x1c;
            pl[1] = 0xb8;
            memcpy(pl + 2, h, 20);
            r = base58check_encode(pl, 22, out, cap);
            break;
        case K_XRP: r = xrp_address(out, cap, h); break;
        case K_PUBHEX:
            if (cap < 67) { r = CHAIN_ERR_SPACE; break; }
            to_hex(out, pub, 33);
            r = 66;
            break;
        case K_COSMOS: {
            uint8_t d5[40];
            int m = bech32_convert_bits(d5, sizeof d5, h, 20, 8, 5, 1);
            r = m < 0 ? CHAIN_ERR_SPACE : bech32_encode(out, cap, c->hrp, d5, (size_t) m, 0);
            break;
        }
        default: r = CHAIN_ERR_UNSUPPORTED;
        }
    }
out:
    secure_zero(&n, sizeof n);
    if (r < 0 && r != CHAIN_ERR_UNSUPPORTED && r != CHAIN_ERR_DERIVE) r = CHAIN_ERR_SPACE;
    return r;
}

static int addr_ed(char *out, size_t cap, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    uint8_t key[32], pub[32];
    int r = ed_key(key, s, p);
    if (r) return r;
    ed25519_pubkey_from_seed(pub, key);
    secure_zero(key, sizeof key);
    switch (c->kind) {
    case K_SOLANA: return base58_encode(pub, 32, out, cap);
    case K_NEAR:
        if (cap < 65) return CHAIN_ERR_SPACE;
        to_hex(out, pub, 32);
        return 64;
    case K_STELLAR: {
        uint8_t b[35];
        uint16_t crc;
        b[0] = 6 << 3;
        memcpy(b + 1, pub, 32);
        crc = crc16_xmodem(b, 33);
        b[33] = (uint8_t) crc;                       /* little endian */
        b[34] = (uint8_t) (crc >> 8);
        return base32_encode(b, 35, out, cap);
    }
    case K_SS58_ED: return ss58_encode(out, cap, c->param, pub);
    case K_PUBHEX:
        if (cap < 65) return CHAIN_ERR_SPACE;
        to_hex(out, pub, 32);
        return 64;
    case K_TON: return ton_address(out, cap, c->param & 0xff, (c->param >> 8) & 1, pub);   /* non-bounceable, the wallet form */
    default: return CHAIN_ERR_UNSUPPORTED;
    }
}

/* Cardano: the payment key at the given path, the staking key at the same account with role 2 and index 0 */
static int ada_node(uint8_t node[96], const hd_secret *s, const hd_path *p);

static int addr_cardano(char *out, size_t cap, const hd_secret *s, const hd_path *p)
{
    uint8_t root[96], node[96], pay[32], stake[32];
    hd_path sp = *p;
    int r;
    if (s->raw_curve == 5) {                                           /* a payment key alone: the staking part is not known, the address is the enterprise one */
        r = ada_node(node, s, p);
        if (r) return r;
        cardano_pubkey(pay, node);
        secure_zero(node, sizeof node);
        r = cardano_enterprise_address(out, cap, pay);
        return r < 0 ? CHAIN_ERR_SPACE : r;
    }
    if (s->entlen < 16) return CHAIN_ERR_NOENTROPY;
    if (p->n < 2) return CHAIN_ERR_PATH;
    cardano_icarus_master(root, s->entropy, (size_t) s->entlen, s->passphrase ? s->passphrase : "");
    memcpy(node, root, 96);
    cardano_derive_path(node, p);
    cardano_pubkey(pay, node);
    sp.idx[sp.n - 2] = 2;
    sp.idx[sp.n - 1] = 0;
    memcpy(node, root, 96);
    cardano_derive_path(node, &sp);
    cardano_pubkey(stake, node);
    r = cardano_base_address(out, cap, pay, stake);
    secure_zero(root, sizeof root);
    secure_zero(node, sizeof node);
    return r < 0 ? CHAIN_ERR_SPACE : r;
}

/* the Cardano node (kL | kR | chain code) of a path, or the raw extended key as it is (no derivation: its chain code is not needed to sign) */
static int ada_node(uint8_t node[96], const hd_secret *s, const hd_path *p)
{
    if (s->raw_curve == 5) { memcpy(node, s->raw, 64); memset(node + 64, 0, 32); return 0; }
    if (s->raw_curve) return CHAIN_ERR_UNSUPPORTED;
    if (s->entlen < 16) return CHAIN_ERR_NOENTROPY;
    if (p->n < 2) return CHAIN_ERR_PATH;
    cardano_icarus_master(node, s->entropy, (size_t) s->entlen, s->passphrase ? s->passphrase : "");
    cardano_derive_path(node, p);
    return 0;
}

/* the sr25519 mini secret: of the words, or the raw one */
static int sr_mini(uint8_t mini[32], const hd_secret *s)
{
    if (s->raw_curve == 3) { memcpy(mini, s->raw, 32); return 0; }
    if (s->raw_curve) return CHAIN_ERR_UNSUPPORTED;
    if (s->entlen < 16) return CHAIN_ERR_NOENTROPY;
    substrate_mini_secret(mini, s->entropy, (size_t) s->entlen, s->passphrase ? s->passphrase : "");
    return 0;
}

/* Polkadot / Kusama: the key from the entropy, junctions like "//polkadot//0/1" */
static int addr_substrate(char *out, size_t cap, const chain_def *c, const hd_secret *s, const char *junctions)
{
    uint8_t mini[32], key[32], pub[32];
    int r = sr_mini(mini, s);
    if (r) return r;
    sr25519_expand(key, mini);
    secure_zero(mini, sizeof mini);
    r = substrate_derive_path(key, junctions);
    if (r) { secure_zero(key, sizeof key); return CHAIN_ERR_PATH; }
    sr25519_pubkey(pub, key);
    secure_zero(key, sizeof key);
    r = ss58_encode(out, cap, c->param, pub);
    return r < 0 ? CHAIN_ERR_SPACE : r;
}

int chain_address_str(char *out, size_t cap, const chain_def *c, const hd_secret *s, const char *path)
{
    hd_path p;
    int r;
    if (c->curve == CV_SR25519) return addr_substrate(out, cap, c, s, path);
    r = path_parse(&p, path);
    if (r) return CHAIN_ERR_PATH;
    return chain_address(out, cap, c, s, &p);
}

/* Zcash Orchard: ZIP-32 from the BIP39 seed along a hardened path, the default diversifier, the unified address */
static int addr_orchard(char *out, size_t cap, const hd_secret *s, const hd_path *p)
{
    uint8_t sk[32], chain[32], j0[11] = {0}, d[11], raw[43];
    orchard_fvk f;
    int r;
    if (s->raw_curve == 4) {                                           /* a spending key as given */
        memcpy(sk, s->raw, 32);
    } else {
        if (s->raw_curve) return CHAIN_ERR_UNSUPPORTED;
        if (!p->n || !path_all_hardened(p)) return CHAIN_ERR_PATH;
        orchard_master(sk, chain, s->seed, 64);
        for (int i = 0; i < p->n; i++) orchard_child(sk, chain, p->idx[i]);
    }
    orchard_fvk_from_sk(&f, sk);
    orchard_diversifier(d, f.dk, j0);
    orchard_address(raw, &f, d);
    r = orchard_unified_address(out, cap, raw);
    secure_zero(sk, sizeof sk);
    secure_zero(chain, sizeof chain);
    secure_zero(&f, sizeof f);
    return r < 0 ? CHAIN_ERR_SPACE : r;
}

int chain_address(char *out, size_t cap, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    switch (c->curve) {
    case CV_ORCHARD: return addr_orchard(out, cap, s, p);
    case CV_ICARUS: return addr_cardano(out, cap, s, p);
    case CV_SR25519: return addr_substrate(out, cap, c, s, "");
    case CV_SECP256K1: return c->kind == K_MWEB ? addr_mweb(out, cap, c, s, p) : addr_secp(out, cap, c, s, p);
    case CV_ED25519: return addr_ed(out, cap, c, s, p);
    default: return CHAIN_ERR_UNSUPPORTED;
    }
}

/* ---- secret keys ---- */

static int wif_version(const chain_def *c)
{
    switch (c->kind) {
    case K_P2PKH: return (int) ((c->param + 0x80) & 0xff);          /* the address version + 0x80: Bitcoin, Litecoin, Dogecoin, Dash */
    case K_P2SH_WPKH: return c->param == 0x32 ? 0xb0 : 0x80;         /* Litecoin M... or Bitcoin */
    case K_P2WPKH: case K_P2TR: return c->hrp && !strcmp(c->hrp, "ltc") ? 0xb0 : 0x80;
    default: return 0x80;
    }
}

static int secret_secp(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    bip32_node n;
    uint8_t pl[34];
    int r = CHAIN_ERR_DERIVE;

    if (secp_node(&n, s, p)) goto out;
    switch (c->kind) {
    case K_P2PKH: case K_P2SH_WPKH: case K_P2WPKH: case K_P2TR: case K_CASHADDR: case K_ZEC_T:
        pl[0] = (uint8_t) wif_version(c);
        memcpy(pl + 1, n.key, 32);
        pl[33] = 1;                                                   /* compressed public key */
        r = base58check_encode(pl, 34, out, cap);
        *label = c->kind == K_P2TR ? T(TXT_WIF_INTERNAL_KEY) : T(TXT_WIF_COMPRESSED);
        break;
    case K_NOSTR:
        r = addr_nsec(out, cap, n.key);
        *label = "nsec";
        break;
    default:
        if (cap < 65) { r = CHAIN_ERR_SPACE; break; }
        to_hex(out, n.key, 32);
        r = 64;
        *label = T(TXT_PRIVATE_KEY_HEX);
    }
out:
    secure_zero(&n, sizeof n);
    secure_zero(pl, sizeof pl);
    if (r < 0 && r != CHAIN_ERR_DERIVE) r = CHAIN_ERR_SPACE;
    return r;
}

static int secret_ed(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    uint8_t key[32], full[64], b[35];
    int r = ed_key(key, s, p);
    if (r) return r;
    memcpy(full, key, 32);
    ed25519_pubkey_from_seed(full + 32, key);
    switch (c->kind) {
    case K_SOLANA:
        r = base58_encode(full, 64, out, cap);                       /* the format of the Phantom / Solana CLI keypair */
        *label = T(TXT_KEYPAIR_BASE58);
        break;
    case K_NEAR:
        if (cap < 9 + 90) { r = CHAIN_ERR_SPACE; break; }
        memcpy(out, "ed25519:", 8);
        r = base58_encode(full, 64, out + 8, cap - 8);
        if (r > 0) r += 8;
        *label = T(TXT_NEAR_PRIVATE_KEY);
        break;
    case K_STELLAR: {
        uint16_t crc;
        b[0] = 18 << 3;
        memcpy(b + 1, key, 32);
        crc = crc16_xmodem(b, 33);
        b[33] = (uint8_t) crc;
        b[34] = (uint8_t) (crc >> 8);
        r = base32_encode(b, 35, out, cap);
        *label = T(TXT_SECRET_SEED_S);
        break;
    }
    default:
        if (cap < 65) { r = CHAIN_ERR_SPACE; break; }
        to_hex(out, key, 32);
        r = 64;
        *label = T(TXT_PRIVATE_SEED_HEX);
    }
    secure_zero(key, sizeof key);
    secure_zero(full, sizeof full);
    secure_zero(b, sizeof b);
    if (r < 0) r = CHAIN_ERR_SPACE;
    return r;
}

int chain_has_view_keys(const chain_def *c) { return c->curve == CV_SECP256K1 && c->kind == K_MWEB; }

const char *chain_alt_path(const chain_def *c) { return chain_has_view_keys(c) ? "m/1000'/0'/1" : NULL; }

int chain_view_keys(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p)
{
    /* Litecoin Core's dumpwallet line "# mweb view keys: <scan secret hex> <spend public key hex>": the scan secret and the master spend public key (b G); they show the
     * incoming payments, they do not spend */
    uint8_t sc[32], sp[32], pub[33];
    uint32_t idx;
    int r;

    *label = "";
    if (!chain_has_view_keys(c)) return CHAIN_ERR_UNSUPPORTED;
    r = mweb_secrets(sc, sp, &idx, s, p);
    if (!r && cap < 132) r = CHAIN_ERR_SPACE;
    if (!r && secp256k1_pubkey_create(pub, sp)) r = CHAIN_ERR_DERIVE;
    if (!r) {
        to_hex(out, sc, 32);
        out[64] = ' ';
        to_hex(out + 65, pub, 33);
        r = 131;
        *label = T(TXT_MWEB_SCAN_KEY_SPEND_PUBKEY);
    }
    secure_zero(sc, sizeof sc);
    secure_zero(sp, sizeof sp);
    return r;
}

int chain_secret(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p, const char *junctions)
{
    *label = "";
    switch (c->curve) {
    case CV_SECP256K1:
        if (c->kind == K_MWEB) {
            /* the keys that spend: the scan secret and the master spend secret (b) of the keychain m/0'/100', two 64 digit hex numbers with a space between them */
            uint8_t sc[32], sp[32];
            uint32_t idx;
            int r = mweb_secrets(sc, sp, &idx, s, p);
            if (!r && cap < 130) r = CHAIN_ERR_SPACE;
            if (!r) {
                to_hex(out, sc, 32);
                out[64] = ' ';
                to_hex(out + 65, sp, 32);
                r = 129;
                *label = T(TXT_MWEB_KEYS_SCAN_SECRET_SPEND_SECRET);
            }
            secure_zero(sc, sizeof sc);
            secure_zero(sp, sizeof sp);
            return r;
        }
        return secret_secp(out, cap, label, c, s, p);
    case CV_ED25519: return secret_ed(out, cap, label, c, s, p);
    case CV_ICARUS: {
        uint8_t node[96], d5[160];
        int m, r = ada_node(node, s, p);
        if (r) return r;
        m = bech32_convert_bits(d5, sizeof d5, node, 96, 8, 5, 1);
        r = m < 0 ? CHAIN_ERR_SPACE : bech32_encode(out, cap, "addr_xsk", d5, (size_t) m, 0);
        secure_zero(node, sizeof node);
        secure_zero(d5, sizeof d5);
        *label = T(TXT_ADDR_XSK_PAYMENT_KEY);
        return r < 0 ? CHAIN_ERR_SPACE : r;
    }
    case CV_SR25519: {
        /* the form polkadot-js takes as a "secret URI": the mini secret in hex followed by the junctions */
        uint8_t mini[32];
        size_t jl = junctions ? strlen(junctions) : 0;
        int e = sr_mini(mini, s);
        if (e) return e;
        if (cap < 67 + jl) return CHAIN_ERR_SPACE;
        out[0] = '0';
        out[1] = 'x';
        to_hex(out + 2, mini, 32);
        if (jl) memcpy(out + 66, junctions, jl);
        out[66 + jl] = 0;
        secure_zero(mini, sizeof mini);
        *label = T(TXT_SECRET_URI_POLKADOT_JS);
        return (int) (66 + jl);
    }
    default: return CHAIN_ERR_UNSUPPORTED;
    }
}

int chain_signing_key(uint8_t key[96], const chain_def *c, const hd_secret *s, const hd_path *p, const char *junctions)
{
    switch (c->curve) {
    case CV_SECP256K1: {
        bip32_node n;
        int r = CHAIN_ERR_DERIVE;
        if (c->kind == K_MWEB) return CHAIN_ERR_UNSUPPORTED;       /* spending MWEB coins is not implemented */
        if (!secp_node(&n, s, p)) { memcpy(key, n.key, 32); r = 32; }
        secure_zero(&n, sizeof n);
        return r;
    }
    case CV_ED25519: {
        int r = ed_key(key, s, p);
        return r ? r : 32;
    }
    case CV_ICARUS: {
        int r = ada_node(key, s, p);
        return r ? r : 96;
    }
    case CV_SR25519: {
        uint8_t mini[32];
        int r = sr_mini(mini, s);
        if (r) return r;
        sr25519_expand(key, mini);
        secure_zero(mini, sizeof mini);
        if (substrate_derive_path(key, junctions ? junctions : "")) return CHAIN_ERR_PATH;
        return 32;
    }
    default: return CHAIN_ERR_UNSUPPORTED;
    }
}
