#include "sign/mswallet.h"
#include <string.h>
#include "coin/xpub.h"
#include "ec/secp256k1.h"
#include "ec/secp_pub.h"
#include "hash/ripemd160.h"
#include "hash/sha256.h"
#include "util.h"

/* ---- Base58Check decoding of an extended key ---- */

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int b58check(const char *s, size_t len, uint8_t *out, size_t want)
{
    uint8_t buf[90];
    size_t zeros = 0, n = 0;
    uint8_t h[32];

    memset(buf, 0, sizeof buf);
    while (zeros < len && s[zeros] == '1') zeros++;
    for (size_t i = 0; i < len; i++) {
        const char *d = strchr(B58, s[i]);
        unsigned carry;
        if (!d || !s[i]) return -1;
        carry = (unsigned) (d - B58);
        for (size_t j = sizeof buf; j-- > 0;) {
            carry += (unsigned) buf[j] * 58;
            buf[j] = (uint8_t) carry;
            carry >>= 8;
        }
        if (carry) return -1;
    }
    while (n < sizeof buf && !buf[n]) n++;
    n = sizeof buf - n + zeros;                              /* the bytes of the number and the leading zeros */
    if (n != want + 4) return -1;
    memcpy(out, buf + sizeof buf - n, n);
    sha256(out, want, h);
    sha256(h, 32, h);
    return memcmp(h, out + want, 4) ? -1 : 0;
}

/* ---- the descriptor ---- */

static int is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static int hexv(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

/* the extended public key of an xpub text: pub, cc and the depth; versions of public keys only */
static int read_xpub(ms_key *k, const char *s, size_t len)
{
    uint8_t raw[82];
    uint32_t ver;

    if (len < 100 || len > 120 || b58check(s, len, raw, 78)) return MSE_KEY;
    ver = (uint32_t) raw[0] << 24 | (uint32_t) raw[1] << 16 | (uint32_t) raw[2] << 8 | raw[3];
    if (ver != 0x0488B21Eu && ver != 0x043587CFu && ver != 0x02AA7ED3u && ver != 0x02575483u && ver != 0x0295B43Fu && ver != 0x024289EFu) return MSE_KEY;
    if (raw[45] != 2 && raw[45] != 3) return MSE_KEY;
    if (raw[4] != k->depth) return MSE_ORIGIN;                 /* the depth in the key is the length of the origin path */
    memcpy(k->cc, raw + 13, 32);
    memcpy(k->pub, raw + 45, 33);
    return MSE_OK;
}

int ms_parse(ms_policy *p, const char *text)
{
    char d[1400];
    size_t n = 0, i = 0, close;
    char *hash;
    int e;

    memset(p, 0, sizeof *p);
    for (const char *t = text; *t; t++) {
        if (*t == ' ' || *t == '\n' || *t == '\r' || *t == '\t') continue;
        if (n + 1 >= sizeof d) return MSE_LIMIT;
        d[n++] = *t;
    }
    d[n] = 0;
    hash = strchr(d, '#');
    if (hash) {
        char cs[9];
        *hash = 0;
        if (strlen(hash + 1) != 8 || descriptor_checksum(d, cs) || strcmp(cs, hash + 1)) return MSE_CHECKSUM;
        n = (size_t) (hash - d);
    }
    if (!strncmp(d, "wsh(", 4)) { p->type = MS_WSH; i = 4; close = 2; }
    else if (!strncmp(d, "sh(wsh(", 7)) { p->type = MS_SH_WSH; i = 7; close = 3; }
    else if (!strncmp(d, "sh(", 3)) { p->type = MS_SH; i = 3; close = 2; }
    else return MSE_SYNTAX;
    if (!strncmp(d + i, "sortedmulti(", 12)) { p->sorted = 1; i += 12; }
    else if (!strncmp(d + i, "multi(", 6)) { i += 6; }
    else return MSE_SYNTAX;
    if (n < close + 1 || strcmp(d + n - close, ")))" + 3 - close)) return MSE_SYNTAX;
    n -= close;                                            /* the closing parentheses */
    while (i < n && d[i] >= '0' && d[i] <= '9') p->m = (uint8_t) (p->m * 10 + (d[i++] - '0'));
    if (i >= n || d[i] != ',' || p->m < 1) return MSE_SYNTAX;
    i++;
    for (;;) {
        ms_key *k;
        size_t s0;
        unsigned depth = 0;

        if (p->n >= MS_MAXKEYS) return MSE_LIMIT;
        k = &p->key[p->n];
        if (i >= n || d[i] != '[') return MSE_ORIGIN;
        i++;
        for (int b = 0; b < 4; b++) {
            if (i + 1 >= n || !is_hex(d[i]) || !is_hex(d[i + 1])) return MSE_ORIGIN;
            k->fp[b] = (uint8_t) (hexv(d[i]) * 16 + hexv(d[i + 1]));
            i += 2;
        }
        while (i < n && d[i] == '/') {                     /* the origin path */
            uint32_t v = 0;
            int digits = 0;
            i++;
            while (i < n && d[i] >= '0' && d[i] <= '9') { v = v * 10 + (uint32_t) (d[i++] - '0'); digits++; if (v >= 0x80000000u) return MSE_LIMIT; }
            if (!digits) return MSE_ORIGIN;
            if (i < n && (d[i] == 'h' || d[i] == '\'' || d[i] == 'H')) { v |= 0x80000000u; i++; }
            if (depth >= MS_MAXPATH) return MSE_LIMIT;
            k->path[depth++] = v;
        }
        if (i >= n || d[i] != ']') return MSE_ORIGIN;
        i++;
        k->depth = (uint8_t) depth;
        s0 = i;
        while (i < n && d[i] != '/' && d[i] != ',') i++;
        e = read_xpub(k, d + s0, i - s0);
        if (e) return e;
        if (i < n && d[i] == '/') {                        /* the suffix: both chains in the forms that mean that */
            static const char *const SUF[] = {"/<0;1>/*", "/0/*", "/1/*", "/**"};
            int ok = 0;
            for (unsigned x = 0; x < 4 && !ok; x++) {
                size_t l = strlen(SUF[x]);
                if (i + l <= n && !strncmp(d + i, SUF[x], l)) { i += l; ok = 1; }
            }
            if (!ok) return MSE_SYNTAX;
        }
        p->n++;
        if (i < n && d[i] == ',') { i++; continue; }
        break;
    }
    if (i != n) return MSE_SYNTAX;
    if (p->n < 1 || p->m > p->n) return MSE_LIMIT;
    return MSE_OK;
}

/* ---- the scripts of the addresses ---- */

static int cmp33(const void *a, const void *b) { return memcmp(a, b, 33); }

/* a few elements: insertion sort of 33 byte keys (the C library's qsort is not linked in the signer) */
static void sort_keys(uint8_t keys[][33], int n)
{
    for (int i = 1; i < n; i++) {
        uint8_t t[33];
        int j = i;
        memcpy(t, keys[i], 33);
        while (j > 0 && cmp33(keys[j - 1], t) > 0) { memcpy(keys[j], keys[j - 1], 33); j--; }
        memcpy(keys[j], t, 33);
    }
}

int ms_script(const ms_policy *p, ms_cache *cache, unsigned chain, unsigned index, uint8_t *script, size_t *slen, uint8_t *spk, size_t *spklen)
{
    uint8_t keys[MS_MAXKEYS][33], dummy[32], h[32], w[34];
    ms_cache local;
    size_t o = 0;

    if (chain > 1 || index >= 0x80000000u) return -1;
    if (!cache) { memset(&local, 0, sizeof local); cache = &local; }
    for (int i = 0; i < p->n; i++) {
        if (!cache->have[chain][i]) {
            if (secp256k1_ckd_pub(cache->pub[chain][i], cache->cc[chain][i], p->key[i].pub, p->key[i].cc, chain)) return -1;
            cache->have[chain][i] = 1;
        }
        if (secp256k1_ckd_pub(keys[i], dummy, cache->pub[chain][i], cache->cc[chain][i], index)) return -1;
    }
    if (p->sorted) sort_keys(keys, p->n);
    script[o++] = (uint8_t) (0x50 + p->m);
    for (int i = 0; i < p->n; i++) { script[o++] = 33; memcpy(script + o, keys[i], 33); o += 33; }
    script[o++] = (uint8_t) (0x50 + p->n);
    script[o++] = 0xae;
    *slen = o;
    if (p->type == MS_WSH) {
        sha256(script, o, h);
        spk[0] = 0x00; spk[1] = 0x20; memcpy(spk + 2, h, 32);
        *spklen = 34;
    } else if (p->type == MS_SH_WSH) {
        sha256(script, o, h);
        w[0] = 0x00; w[1] = 0x20; memcpy(w + 2, h, 32);
        spk[0] = 0xa9; spk[1] = 0x14; hash160(w, 34, spk + 2); spk[22] = 0x87;
        *spklen = 23;
    } else {
        spk[0] = 0xa9; spk[1] = 0x14; hash160(script, o, spk + 2); spk[22] = 0x87;
        *spklen = 23;
    }
    return 0;
}

int ms_ours(const ms_policy *p, const bip32_node *master)
{
    uint8_t fp[4];

    if (bip32_fingerprint(master, fp)) return MSE_NOTOURS;
    for (int i = 0; i < p->n; i++) {
        bip32_node n = *master;
        uint8_t pub[33];
        int ok;
        if (memcmp(p->key[i].fp, fp, 4)) continue;
        if (bip32_derive_path(&n, p->key[i].path, p->key[i].depth) || secp256k1_pubkey_create(pub, n.key)) { secure_zero(&n, sizeof n); continue; }
        ok = !memcmp(pub, p->key[i].pub, 33) && !memcmp(n.chain, p->key[i].cc, 32);
        secure_zero(&n, sizeof n);
        if (ok) return i;
    }
    return MSE_NOTOURS;
}

/* ---- the record ---- */

#define REC_KEY (4 + 1 + 4 * MS_MAXPATH + 33 + 32)

static size_t body(const ms_policy *p, uint8_t *out)
{
    size_t o = 0;

    memcpy(out, "PSXXMS01", 8); o = 8;
    out[o++] = p->type; out[o++] = p->sorted; out[o++] = p->m; out[o++] = p->n;
    for (int i = 0; i < p->n; i++) {
        memcpy(out + o, p->key[i].fp, 4); o += 4;
        out[o++] = p->key[i].depth;
        for (int d = 0; d < MS_MAXPATH; d++) {
            uint32_t v = p->key[i].path[d];
            out[o++] = (uint8_t) (v >> 24); out[o++] = (uint8_t) (v >> 16); out[o++] = (uint8_t) (v >> 8); out[o++] = (uint8_t) v;
        }
        memcpy(out + o, p->key[i].pub, 33); o += 33;
        memcpy(out + o, p->key[i].cc, 32); o += 32;
    }
    return o;
}

void ms_id(const ms_policy *p, uint8_t id[4])
{
    uint8_t b[12 + MS_MAXKEYS * REC_KEY], h[32];
    size_t n = body(p, b);

    sha256(b, n, h);
    memcpy(id, h, 4);
}

static void mac_of(const bip32_node *master, const uint8_t *b, size_t n, uint8_t mac[32])
{
    static const char TAG[] = "psxx multisig policy v1";
    sha256_ctx c;
    uint8_t k[32];

    sha256_init(&c);                                       /* the key of the MAC: a hash of the tag and the master key, nothing else has it */
    sha256_update(&c, (const uint8_t *) TAG, sizeof TAG - 1);
    sha256_update(&c, master->key, 32);
    sha256_update(&c, master->chain, 32);
    sha256_final(&c, k);
    hmac_sha256(k, 32, b, n, mac);
    secure_zero(k, sizeof k);
}

size_t ms_save(const ms_policy *p, const bip32_node *master, uint8_t *out, size_t cap)
{
    size_t n;

    if (cap < 12 + (size_t) p->n * REC_KEY + 32) return 0;
    n = body(p, out);
    mac_of(master, out, n, out + n);
    return n + 32;
}

int ms_load(ms_policy *p, const uint8_t *rec, size_t len, const bip32_node *master)
{
    size_t o = 12, n;
    uint8_t mac[32];

    memset(p, 0, sizeof *p);
    if (len < 12 || memcmp(rec, "PSXXMS01", 8)) return MSE_FORMAT;
    p->type = rec[8]; p->sorted = rec[9]; p->m = rec[10]; p->n = rec[11];
    if (p->type < MS_WSH || p->type > MS_SH || p->n < 1 || p->n > MS_MAXKEYS || p->m < 1 || p->m > p->n) return MSE_FORMAT;
    n = 12 + (size_t) p->n * REC_KEY;
    if (len < n + 32) return MSE_FORMAT;
    for (int i = 0; i < p->n; i++) {
        memcpy(p->key[i].fp, rec + o, 4); o += 4;
        p->key[i].depth = rec[o++];
        if (p->key[i].depth > MS_MAXPATH) return MSE_FORMAT;
        for (int d = 0; d < MS_MAXPATH; d++, o += 4) p->key[i].path[d] = (uint32_t) rec[o] << 24 | (uint32_t) rec[o + 1] << 16 | (uint32_t) rec[o + 2] << 8 | rec[o + 3];
        memcpy(p->key[i].pub, rec + o, 33); o += 33;
        memcpy(p->key[i].cc, rec + o, 32); o += 32;
    }
    mac_of(master, rec, n, mac);
    if (memcmp(mac, rec + n, 32)) { memset(p, 0, sizeof *p); return MSE_MAC; }
    return MSE_OK;
}
