#include "vanity/vanity.h"
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "ec/secp256k1.h"
#include "hash/keccak.h"
#include "hash/ripemd160.h"
#include "coin/addr.h"
#include "coin/base58.h"
#include "coin/bech32.h"
#include "coin/chains.h"

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int idx_of(const char *alpha, char ch)
{
    for (int i = 0; alpha[i]; i++) if (alpha[i] == ch) return i;
    return -1;
}

static int hexval(char ch)
{
    return ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
}

static int is_hex_kind(int k) { return k == VK_ETH || k == VK_CREATE2; }
static int is_b32_kind(int k) { return k == VK_BECH32 || k == VK_NPUB || k == VK_KASPA; }
static int is_b58_kind(int k) { return k == VK_P2PKH || k == VK_P2SH; }

/* ---- big numbers of at most 28 bytes, big endian, for the Base58 ranges ---- */
#define BL 28

static void b_muladd(uint8_t *n, unsigned mul, unsigned add)
{
    for (int i = BL - 1; i >= 0; i--) {
        unsigned t = (unsigned) n[i] * mul + add;
        n[i] = (uint8_t) t;
        add = t >> 8;
    }
}

static void b_add(uint8_t *a, const uint8_t *b)
{
    unsigned c = 0;
    for (int i = BL - 1; i >= 0; i--) { c += (unsigned) a[i] + b[i]; a[i] = (uint8_t) c; c >>= 8; }
}

static void b_sub1(uint8_t *a)
{
    for (int i = BL - 1; i >= 0; i--) if (a[i]--) break;
}

static int b_cmp(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, BL); }

/* the number of Base58 digits of n */
static int b_digits(const uint8_t *n)
{
    uint8_t p[BL];
    int d = 0;
    memset(p, 0, BL);
    p[BL - 1] = 1;
    while (b_cmp(p, n) <= 0 && d < 40) { b_muladd(p, 58, 0); d++; }
    return d;
}

/* ---- the version bytes and the head ---- */

static int ver_zeros(const vanity_cfg *c) { return c->version == 0; }

/* min and max of the number behind the address: version || 24 bytes of 00 or ff (HASH160 and checksum), without the leading zero version byte */
static void b58_span(const vanity_cfg *c, uint8_t *lo, uint8_t *hi)
{
    memset(lo, 0, BL);
    memset(hi, 0, BL);
    if (!ver_zeros(c)) { lo[BL - 25] = c->version; hi[BL - 25] = c->version; }
    memset(hi + BL - 24, 0xff, 24);
}

int vanity_head(const vanity_cfg *c, char *out, size_t cap)
{
    char t[40];
    int n = 0;

    switch (c->kind) {
    case VK_ETH: case VK_CREATE2: strcpy(t, "0x"); break;
    case VK_BECH32: snprintf(t, sizeof t, "%s1q", c->hrp ? c->hrp : "bc"); break;
    case VK_NPUB: strcpy(t, "npub1"); break;
    case VK_KASPA: snprintf(t, sizeof t, "%s:q", c->hrp ? c->hrp : "kaspa"); break;
    case VK_P2PKH: case VK_P2SH: {                              /* the characters that every address of this version starts with */
        uint8_t a[25], b[25];
        char sa[48], sb[48];
        memset(a, 0, 25); memset(b, 0xff, 25);
        a[0] = b[0] = c->version;
        if (base58_encode(a, 25, sa, sizeof sa) < 0 || base58_encode(b, 25, sb, sizeof sb) < 0) return -1;
        while (sa[n] && sa[n] == sb[n]) n++;
        if (n < 1) n = 1;
        memcpy(t, sa, (size_t) n);
        t[n] = 0;
        break;
    }
    default: return -1;
    }
    n = (int) strlen(t);
    if ((size_t) n + 1 > cap) return -1;
    strcpy(out, t);
    return n;
}

int vanity_char_ok(const vanity_cfg *c, char ch)
{
    if (is_hex_kind(c->kind)) return hexval(ch) >= 0;
    if (is_b32_kind(c->kind)) return idx_of(B32, ch) >= 0;
    return idx_of(B58, ch) >= 0;
}

/* ---- compiling the conditions ---- */

static uint64_t pow_sat(unsigned base, int e)
{
    uint64_t r = 1;
    for (int i = 0; i < e; i++) {
        if (r > UINT64_MAX / base) return UINT64_MAX;
        r *= base;
    }
    return r;
}

static int compile_b58(vanity *v, const char *pre, int m)
{
    const vanity_cfg *c = &v->cfg;
    uint8_t mmin[BL], mmax[BL], P[BL];
    int z = ver_zeros(c), lmax, lmin;

    v->zeros = z;
    v->rlen = (z ? 0 : 1) + 20;
    v->nrange = 0;
    if (m <= 0) return VE_OK;
    for (int i = 0; i < z; i++) if (i >= m || pre[i] != '1') return VE_RANGE;
    pre += z; m -= z;
    if (m <= 0) { v->nrange = 0; return VE_OK; }              /* only the leading ones: no condition */
    memset(P, 0, BL);
    for (int i = 0; i < m; i++) {
        int d = idx_of(B58, pre[i]);
        if (d < 0) return VE_CHAR;
        b_muladd(P, 58, (unsigned) d);
    }
    b58_span(c, mmin, mmax);
    lmax = b_digits(mmax);
    lmin = lmax - 1 > m ? lmax - 1 : m;
    if (lmax < m) return VE_RANGE;
    for (int L = lmin; L <= lmax && v->nrange < 2; L++) {
        uint8_t pw[BL], lo[BL], hi[BL];
        memset(pw, 0, BL);
        pw[BL - 1] = 1;
        for (int i = 0; i < L - m; i++) b_muladd(pw, 58, 0);
        memcpy(lo, P, BL);
        for (int i = 0; i < L - m; i++) b_muladd(lo, 58, 0);   /* P * 58^(L - m) */
        memcpy(hi, lo, BL);
        b_add(hi, pw);
        b_sub1(hi);                                            /* the last number with these digits */
        if (b_cmp(lo, mmin) < 0) memcpy(lo, mmin, BL);
        if (b_cmp(hi, mmax) > 0) memcpy(hi, mmax, BL);
        if (b_cmp(lo, hi) > 0) continue;
        /* compare version || HASH160: the number without its last 4 bytes (the checksum); BL - 4 - rlen is where the bytes start */
        memcpy(v->lo[v->nrange], lo + BL - 4 - v->rlen, (size_t) v->rlen);
        memcpy(v->hi[v->nrange], hi + BL - 4 - v->rlen, (size_t) v->rlen);
        v->nrange++;
    }
    if (!v->nrange) return VE_RANGE;
    return VE_OK;
}

static int compile(vanity *v, const vanity_cfg *cfg)
{
    char head[24];
    int hl, pl, sl, e = VE_OK;

    if (cfg->kind < 0 || cfg->kind >= VK_KINDS) return VE_KIND;
    if ((cfg->kind == VK_BECH32 || cfg->kind == VK_KASPA) && !cfg->hrp) return VE_KIND;
    if (is_b58_kind(cfg->kind) && cfg->version == 0 && cfg->kind == VK_P2SH) return VE_KIND;
    hl = vanity_head(cfg, head, sizeof head);
    pl = (int) strlen(cfg->prefix);
    sl = (int) strlen(cfg->suffix);
    if (hl < 0) return VE_KIND;
    if (pl && (pl < hl || strncmp(cfg->prefix, head, (size_t) hl))) {
        if (!is_hex_kind(cfg->kind) || pl < 2 || cfg->prefix[0] != '0' || (cfg->prefix[1] != 'x' && cfg->prefix[1] != 'X')) return VE_HEAD;
    }
    if (pl > 23 || sl > 23) return VE_LONG;
    for (int i = hl; i < pl; i++) if (!vanity_char_ok(cfg, cfg->prefix[i])) return VE_CHAR;
    for (int i = 0; i < sl; i++) if (!vanity_char_ok(cfg, cfg->suffix[i])) return VE_CHAR;

    if (is_hex_kind(cfg->kind)) {
        v->npn = pl > hl ? pl - hl : 0;
        v->nsn = sl;
        if (v->npn + v->nsn > 40) return VE_LONG;
        for (int i = 0; i < v->npn; i++) v->pn[i] = (uint8_t) hexval(cfg->prefix[hl + i]);
        for (int i = 0; i < v->nsn; i++) v->sn[i] = (uint8_t) hexval(cfg->suffix[i]);
        v->expected = pow_sat(16, v->npn + v->nsn);
    } else if (is_b32_kind(cfg->kind)) {
        v->npg = pl > hl ? pl - hl : 0;
        v->goff = cfg->kind == VK_KASPA ? 1 : 0;
        if (v->npg > 40) return VE_LONG;
        for (int i = 0; i < v->npg; i++) v->pg[i] = (uint8_t) idx_of(B32, cfg->prefix[hl + i]);
        if (cfg->kind == VK_KASPA && v->npg && v->pg[0] > 3) return VE_RANGE;     /* the version byte (0) fills the first three bits of that character */
        v->slow = !v->npg && sl;
        v->expected = pow_sat(32, v->npg + sl);
        if (cfg->kind == VK_KASPA && v->npg) v->expected = pow_sat(32, v->npg - 1 + sl) * 4;
    } else {
        e = compile_b58(v, cfg->prefix, pl);
        if (e) return e;
        v->slow = !v->nrange && sl;
        v->expected = pow_sat(58, sl);
        if (v->nrange) {                                                       /* 2^64 over the width of the ranges (their first 8 bytes) */
            uint64_t w = 0;
            for (int r = 0; r < v->nrange; r++) {
                uint64_t a = 0, b = 0;
                for (int i = 0; i < 8; i++) { a = a << 8 | v->lo[r][i]; b = b << 8 | v->hi[r][i]; }
                w += b - a + 1;
            }
            if (w == 0) w = 1;
            w = (v->zeros ? UINT64_MAX : ((uint64_t) 1 << 56)) / w;                 /* the version byte is not free */
            v->expected = v->expected > UINT64_MAX / (w ? w : 1) ? UINT64_MAX : v->expected * w;
        }
    }
    if (v->expected > 1) v->expected = v->expected * 693 / 1000;              /* the median: ln 2 of the mean */
    return VE_OK;
}

int vanity_check(const vanity_cfg *cfg, uint64_t *expected)
{
    vanity v;
    int e;

    memset(&v, 0, sizeof v);
    v.cfg = *cfg;
    e = compile(&v, cfg);
    if (expected) *expected = e ? 0 : v.expected;
    return e;
}

int vanity_start(vanity *v, const vanity_cfg *cfg, van_ctx *ctx, const uint8_t seed[32])
{
    int e;

    memset(v, 0, sizeof *v);
    v->cfg = *cfg;
    v->ctx = ctx;
    e = compile(v, cfg);
    if (e) return e;
    if (cfg->kind == VK_CREATE2) {
        memcpy(v->salt, seed, 32);
    } else if (secp256k1_van_init(ctx, seed)) return VE_SEED;
    return VE_OK;
}

/* ---- the candidates ---- */

static int group_at(const uint8_t *p, int len, int g)           /* the 5 bit group g of a byte string */
{
    int bit = 5 * g, byte = bit >> 3, sh = bit & 7;
    unsigned w = (unsigned) (byte < len ? p[byte] : 0) << 8 | (unsigned) (byte + 1 < len ? p[byte + 1] : 0);
    return (int) ((w >> (11 - sh)) & 31);
}

static int tail_ok(const char *a, const char *suf)               /* the address ends with the suffix */
{
    size_t la = strlen(a), ls = strlen(suf);
    return ls <= la && !strcmp(a + la - ls, suf);
}

static int hex_ok(const vanity *v, const uint8_t a20[20])
{
    for (int i = 0; i < v->npn; i++) if (((a20[i >> 1] >> ((i & 1) ? 0 : 4)) & 15) != v->pn[i]) return 0;
    for (int i = 0; i < v->nsn; i++) {
        int pos = 40 - v->nsn + i;
        if (((a20[pos >> 1] >> ((pos & 1) ? 0 : 4)) & 15) != v->sn[i]) return 0;
    }
    return 1;
}

/* the full text of the address of a candidate, from its digest (no key needed): payload is the HASH160 (BECH32, P2PKH, P2SH) or x (NPUB, KASPA) */
static int text_of(const vanity *v, char *out, size_t cap, const uint8_t *payload)
{
    const vanity_cfg *c = &v->cfg;
    uint8_t raw[21];

    switch (c->kind) {
    case VK_BECH32: return segwit_addr_encode(out, cap, c->hrp, 0, payload, 20);
    case VK_P2PKH: case VK_P2SH: raw[0] = c->version; memcpy(raw + 1, payload, 20); return base58check_encode(raw, 21, out, cap);
    case VK_NPUB: {
        uint8_t g[52];
        if (bech32_convert_bits(g, sizeof g, payload, 32, 8, 5, 1) < 0) return -1;
        return bech32_encode(out, cap, "npub", g, 52, 0);
    }
    case VK_KASPA: return kaspa_address(out, cap, c->hrp, payload);
    default: return -1;
    }
}

/* the quick condition on the payload of a candidate; 1 if it may be a hit (a suffix is checked by the text, in the caller) */
static int quick_ok(const vanity *v, const uint8_t *payload)
{
    const vanity_cfg *c = &v->cfg;

    if (is_b32_kind(c->kind)) {
        uint8_t pl[33];
        const uint8_t *p = payload;
        int len = c->kind == VK_BECH32 ? 20 : 32;
        if (c->kind == VK_KASPA) { pl[0] = 0; memcpy(pl + 1, payload, 32); p = pl; len = 33; }
        for (int j = 0; j < v->npg; j++) if (group_at(p, len, j + v->goff) != v->pg[j]) return 0;
        return 1;
    }
    /* Base58: version || HASH160 inside one of the ranges */
    if (!v->nrange) return 1;
    {
        uint8_t t[21];
        int n = v->rlen;
        if (n == 21) { t[0] = c->version; memcpy(t + 1, payload, 20); } else memcpy(t, payload, 20);
        for (int r = 0; r < v->nrange; r++) if (memcmp(t, v->lo[r], (size_t) n) >= 0 && memcmp(t, v->hi[r], (size_t) n) <= 0) return 1;
        return 0;
    }
}

/* The address of a key of the kind of the configuration (kind, version and hrp; the conditions do not matter), from the key alone with the code of the wallet: its length, or -1. */
int vanity_address(const vanity_cfg *c, const uint8_t key[32], char *out, size_t cap)
{
    uint8_t pub[33];
    int n;

    switch (c->kind) {
    case VK_ETH: n = addr_eth(out, cap, key); break;
    case VK_BECH32: if (secp256k1_pubkey_create(pub, key)) return -1; n = addr_p2wpkh(out, cap, c->hrp, pub); break;
    case VK_P2PKH: if (secp256k1_pubkey_create(pub, key)) return -1; n = addr_p2pkh(out, cap, c->version, pub); break;
    case VK_P2SH: {
        uint8_t red[22] = {0, 20}, h[20], raw[21];
        if (secp256k1_pubkey_create(pub, key)) return -1;
        hash160(pub, 33, red + 2);
        hash160(red, 22, h);
        raw[0] = c->version; memcpy(raw + 1, h, 20);
        n = base58check_encode(raw, 21, out, cap);
        break;
    }
    case VK_NPUB: n = addr_npub(out, cap, key); break;
    case VK_KASPA: if (secp256k1_pubkey_create(pub, key)) return -1; n = kaspa_address(out, cap, c->hrp, pub + 1); break;
    default: return -1;
    }
    return n <= 0 ? -1 : n;
}

/* The address of a key, from the key alone with the code of the wallet, and the check of the conditions; 0 if all hold. */
static int verify_key(const vanity *v, const uint8_t key[32], char *out, size_t cap)
{
    const vanity_cfg *c = &v->cfg;
    int n = vanity_address(c, key, out, cap);

    if (n <= 0) return -1;
    {
        char pre[24], suf[24];
        size_t pl = strlen(c->prefix), sl = strlen(c->suffix);
        memcpy(pre, c->prefix, pl + 1);
        memcpy(suf, c->suffix, sl + 1);
        if (c->kind == VK_ETH) {                                       /* hex text: the case is the checksum's, not the user's */
            for (int i = 0; i < n; i++) if (out[i] >= 'A' && out[i] <= 'F') out[i] = (char) (out[i] + 32);
            for (size_t i = 0; i < pl; i++) if ((pre[i] >= 'A' && pre[i] <= 'F') || pre[i] == 'X') pre[i] = (char) (pre[i] + 32);
            for (size_t i = 0; i < sl; i++) if (suf[i] >= 'A' && suf[i] <= 'F') suf[i] = (char) (suf[i] + 32);
        }
        if (pl && strncmp(out, pre, pl)) return -1;
        if (sl && !tail_ok(out, suf)) return -1;
    }
    return 0;
}

/* the payload (HASH160 or x) of a candidate, and for ETH the 20 address bytes; returns 0, or 1 if payload is not used */
static void candidate(const vanity *v, int i, int neg, uint8_t *payload, uint8_t a20[20])
{
    uint8_t x[32], y[32], pub[33], h[32];

    switch (v->cfg.kind) {
    case VK_ETH: {
        uint8_t xy[64];
        secp256k1_van_point(v->ctx, i, neg, xy, xy + 32);
        keccak256(xy, 64, h);
        memcpy(a20, h + 12, 20);
        break;
    }
    case VK_BECH32: case VK_P2PKH:
        secp256k1_van_point(v->ctx, i, neg, x, y);
        pub[0] = (uint8_t) (2 | (y[31] & 1));
        memcpy(pub + 1, x, 32);
        hash160(pub, 33, payload);
        break;
    case VK_P2SH: {
        uint8_t red[22] = {0, 20};
        secp256k1_van_point(v->ctx, i, neg, x, y);
        pub[0] = (uint8_t) (2 | (y[31] & 1));
        memcpy(pub + 1, x, 32);
        hash160(pub, 33, red + 2);
        hash160(red, 22, payload);
        break;
    }
    default:                                                           /* NPUB, KASPA: x only */
        secp256k1_van_point(v->ctx, i, neg, payload, NULL);
        break;
    }
}

int vanity_probe(vanity *v, int i, int neg)
{
    uint8_t payload[32], a20[20];

    candidate(v, i, neg, payload, a20);
    if (v->cfg.kind == VK_ETH) return hex_ok(v, a20);
    return quick_ok(v, payload);
}

static void hit(vanity *v, const uint8_t key[32], const uint8_t *a20)
{
    char text[VAN_ADDR];

    if (verify_key(v, key, text, sizeof text)) { v->rejected++; return; }
    memcpy(v->key, key, 32);
    if (a20) memcpy(v->a20, a20, 20);
    if (v->cfg.kind == VK_ETH) addr_eth(v->addr, sizeof v->addr, key); else memcpy(v->addr, text, sizeof text);
    v->found = 1;
}

static void salt_add(uint8_t salt[32], uint64_t n)                 /* the counter in the last 8 bytes, big endian */
{
    unsigned c = 0;
    for (int i = 31; i >= 24; i--) {
        c += salt[i] + (unsigned) (n & 255);
        salt[i] = (uint8_t) c;
        c >>= 8;
        n >>= 8;
    }
}

int vanity_step(vanity *v, int n)
{
    for (int k = 0; k < n && !v->found; k++) {
        if (v->cfg.kind == VK_CREATE2) {
            uint8_t buf[85], h[32], salt[32];
            memcpy(salt, v->salt, 32);
            salt_add(salt, v->tried);
            buf[0] = 0xff;
            memcpy(buf + 1, v->cfg.deployer, 20);
            memcpy(buf + 21, salt, 32);
            memcpy(buf + 53, v->cfg.init_hash, 32);
            keccak256(buf, 85, h);
            v->tried++;
            if (hex_ok(v, h + 12)) {
                memcpy(v->key, salt, 32);
                memcpy(v->a20, h + 12, 20);
                addr_eth20(v->addr, sizeof v->addr, h + 12);
                v->found = 1;
            }
            continue;
        }
        if (!v->prepared) {                                            /* the inverses of the next batch, a few points a step */
            if (secp256k1_van_prepare_step(v->ctx, 8)) { v->prepared = 1; v->c = 0; }
            continue;
        }
        {
            int i = v->c >> 1, neg = v->c & 1;
            uint8_t payload[32], a20[20];
            int ok;

            candidate(v, i, neg, payload, a20);
            if (v->cfg.kind == VK_ETH) ok = hex_ok(v, a20);
            else {
                ok = quick_ok(v, payload);
                if (ok && v->cfg.suffix[0]) {                          /* the text of the address ends as asked */
                    char text[VAN_ADDR];
                    ok = text_of(v, text, sizeof text, payload) > 0 && tail_ok(text, v->cfg.suffix);
                }
            }
            if (ok) {
                uint8_t key[32];
                secp256k1_van_key(v->ctx, i, neg, key);
                hit(v, key, v->cfg.kind == VK_ETH ? a20 : NULL);
                secure_zero(key, sizeof key);
            }
            v->tried++;
            if (++v->c == 2 * VAN_N) { secp256k1_van_advance(v->ctx); v->prepared = 0; }
        }
    }
    return v->found;
}

int vanity_eth_text(char *out, const uint8_t a20[20]) { return addr_eth20(out, 43, a20); }
