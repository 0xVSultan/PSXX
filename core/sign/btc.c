/* Bitcoin family PSBT: parser, summary, signature hashes (legacy, BIP143, BIP341 key path, Bitcoin Cash fork id), signing. */
#include "sign/btc.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "coin/bech32.h"
#include "coin/path.h"
#include "ec/secp256k1.h"
#include "hash/ripemd160.h"
#include "hash/sha256.h"
#include "util.h"
#include "tr.h"

/* ---- networks ---- */

static const btc_net NETS[] = {
    {"Bitcoin",      "BTC",  0x00, 0x05, "bc",  NULL,          0, 8},
    {"Litecoin",     "LTC",  0x30, 0x32, "ltc", NULL,          0, 8},
    {"Dogecoin",     "DOGE", 0x1e, 0x16, NULL,  NULL,          0, 8},
    {"Dash",         "DASH", 0x4c, 0x10, NULL,  NULL,          0, 8},
    {"Bitcoin Cash", "BCH",  0x00, 0x05, NULL,  "bitcoincash", 1, 8},
};

const btc_net *btc_net_for(const chain_def *c)
{
    if (!c || c->curve != CV_SECP256K1) return NULL;
    if (!strncmp(c->id, "btc", 3)) return &NETS[0];
    if (!strncmp(c->id, "ltc", 3)) return &NETS[1];
    if (!strcmp(c->id, "doge")) return &NETS[2];
    if (!strcmp(c->id, "dash")) return &NETS[3];
    if (!strcmp(c->id, "bch")) return &NETS[4];
    return NULL;
}

/* ---- byte helpers ---- */

static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t) (v >> (8 * i)); }
static void wr64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t) (v >> (8 * i)); }

static size_t cs_put(uint8_t *o, uint64_t v)
{
    if (v < 0xFD) { o[0] = (uint8_t) v; return 1; }
    if (v <= 0xFFFF) { o[0] = 0xFD; o[1] = (uint8_t) v; o[2] = (uint8_t) (v >> 8); return 3; }
    o[0] = 0xFE; wr32(o + 1, (uint32_t) v);
    return 5;
}

static void sha256d_final(sha256_ctx *c, uint8_t out[32])
{
    sha256_final(c, out);
    sha256(out, 32, out);
}

static void hupd_cs(sha256_ctx *c, uint64_t v)
{
    uint8_t b[9];
    sha256_update(c, b, cs_put(b, v));
}

/* ---- PSBT parser ---- */

typedef struct { uint8_t *buf; size_t cap, n; int err; } wr;

static void w_put(wr *w, const void *d, size_t n)
{
    if (w->n + n > w->cap) { w->err = 1; return; }
    if (w->cap) memcpy(w->buf + w->n, d, n);
    w->n += n;
}

static int map_next(const uint8_t **pp, const uint8_t *end, const uint8_t **key, size_t *klen, const uint8_t **val, size_t *vlen)
{
    const uint8_t *p = *pp;
    uint64_t kl, vl;
    if (rd_cs(&p, end, &kl)) return -1;
    if (kl == 0) { *pp = p; return 0; }
    if ((uint64_t) (end - p) < kl) return -1;
    *key = p; *klen = (size_t) kl;
    p += kl;
    if (rd_cs(&p, end, &vl) || (uint64_t) (end - p) < vl) return -1;
    *val = p; *vlen = (size_t) vl;
    *pp = p + vl;
    return 1;
}

static int parse_tx(psbt *p, const uint8_t *t, size_t n)
{
    const uint8_t *e = t + n, *q = t;
    uint64_t c;

    if (n < 10) return BTC_ERR_PARSE;
    p->version = rd32(q);
    q += 4;
    if (rd_cs(&q, e, &c) || c == 0) return BTC_ERR_PARSE;           /* 0 inputs: a SegWit serialisation, not allowed here */
    if (c > PSBT_MAXIN) return BTC_ERR_UNSUPPORTED;
    p->nin = (int) c;
    p->vin = q;
    for (int i = 0; i < p->nin; i++) {
        if (e - q < 41 || q[36] != 0) return BTC_ERR_PARSE;         /* the transaction of a PSBT has empty scriptSigs */
        q += 41;
    }
    if (rd_cs(&q, e, &c) || c == 0) return BTC_ERR_PARSE;
    if (c > PSBT_MAXOUT) return BTC_ERR_UNSUPPORTED;
    p->nout = (int) c;
    p->vout = q;
    for (int i = 0; i < p->nout; i++) {
        uint64_t sl;
        if (e - q < 9) return BTC_ERR_PARSE;
        q += 8;
        if (rd_cs(&q, e, &sl) || (uint64_t) (e - q) < sl) return BTC_ERR_PARSE;
        q += sl;
    }
    p->vout_end = q;
    if (e - q != 4) return BTC_ERR_PARSE;
    p->locktime = rd32(q);
    p->tx = t;
    p->txlen = n;
    return BTC_OK;
}

int psbt_parse(psbt *p, const uint8_t *buf, size_t len)
{
    const uint8_t *q = buf + 5, *end = buf + len, *key, *val;
    size_t kl, vl;
    int r, have_tx = 0;

    memset(p, 0, sizeof *p);
    if (len < 12 || memcmp(buf, "psbt\xff", 5)) return BTC_ERR_PARSE;
    p->buf = buf;
    p->len = len;
    while ((r = map_next(&q, end, &key, &kl, &val, &vl)) == 1) {
        if (key[0] == 0x00 && kl == 1) {
            int e = parse_tx(p, val, vl);
            if (e) return e;
            have_tx = 1;
        } else if (key[0] == 0xFB && kl == 1) {
            if (vl != 4 || rd32(val) != 0) return BTC_ERR_UNSUPPORTED;      /* PSBT version 2 */
        }
    }
    if (r < 0 || !have_tx) return BTC_ERR_PARSE;
    for (int i = 0; i < p->nin; i++) {
        p->in_map[i] = q;
        while ((r = map_next(&q, end, &key, &kl, &val, &vl)) == 1) {}
        if (r < 0) return BTC_ERR_PARSE;
    }
    for (int i = 0; i < p->nout; i++) {
        p->out_map[i] = q;
        while ((r = map_next(&q, end, &key, &kl, &val, &vl)) == 1) {}
        if (r < 0) return BTC_ERR_PARSE;
    }
    return BTC_OK;
}

/* the fields of an input map that the signer uses (pointers into the PSBT) */
typedef struct {
    const uint8_t *nonwit; size_t nonwit_len;
    const uint8_t *wutxo;  size_t wutxo_len;
    uint32_t sighash; int has_sighash;
    const uint8_t *redeem; size_t redeem_len;
    const uint8_t *wscript; size_t wscript_len;
    struct { const uint8_t *pub, *val; size_t vlen; } der[8];
    int nder;
    struct { const uint8_t *xo, *val; size_t vlen; } tder[4];
    int ntder;
    struct { const uint8_t *script; size_t slen; uint8_t ver; } leaf[4];       /* PSBT_IN_TAP_LEAF_SCRIPT: the script and its leaf version (the control block is not used) */
    int nleaf;
    const uint8_t *tint, *tmerkle;
    struct { const uint8_t *pub, *sig; size_t slen; } psig[4];
    int npsig;
    const uint8_t *tsig; size_t tsig_len;
    int final_;
} in_f;

static void raw_fix_in(const psbt *p, int i, in_f *f);

static int parse_in(const psbt *p, int i, in_f *f)
{
    const uint8_t *q = p->in_map[i], *end = p->buf + p->len, *key, *val;
    size_t kl, vl;
    int r;

    memset(f, 0, sizeof *f);
    while ((r = map_next(&q, end, &key, &kl, &val, &vl)) == 1) {
        switch (key[0]) {
        case 0x00: if (kl == 1) { f->nonwit = val; f->nonwit_len = vl; } break;
        case 0x01: if (kl == 1) { f->wutxo = val; f->wutxo_len = vl; } break;
        case 0x02: if (kl == 34 && f->npsig < 4) { f->psig[f->npsig].pub = key + 1; f->psig[f->npsig].sig = val; f->psig[f->npsig].slen = vl; f->npsig++; } break;
        case 0x03: if (kl == 1 && vl == 4) { f->sighash = rd32(val); f->has_sighash = 1; } break;
        case 0x04: if (kl == 1) { f->redeem = val; f->redeem_len = vl; } break;
        case 0x05: if (kl == 1) { f->wscript = val; f->wscript_len = vl; } break;
        case 0x06: if (kl == 34 && f->nder < 8) { f->der[f->nder].pub = key + 1; f->der[f->nder].val = val; f->der[f->nder].vlen = vl; f->nder++; } break;
        case 0x07: case 0x08: f->final_ = 1; break;
        case 0x13: if (kl == 1) { f->tsig = val; f->tsig_len = vl; } break;
        case 0x15: if (kl >= 34 && (kl - 1) % 32 == 1 && vl >= 1 && f->nleaf < 4) { f->leaf[f->nleaf].script = val; f->leaf[f->nleaf].slen = vl - 1; f->leaf[f->nleaf].ver = val[vl - 1]; f->nleaf++; } break;
        case 0x16: if (kl == 33 && f->ntder < 4) { f->tder[f->ntder].xo = key + 1; f->tder[f->ntder].val = val; f->tder[f->ntder].vlen = vl; f->ntder++; } break;
        case 0x17: if (kl == 1 && vl == 32) f->tint = val; break;
        case 0x18: if (kl == 1 && vl == 32) f->tmerkle = val; break;
        default: break;
        }
    }
    if (r >= 0) raw_fix_in(p, i, f);
    return r < 0 ? BTC_ERR_PARSE : BTC_OK;
}

/* fingerprint and path of a derivation value; for a taproot record `tap` the leaf hash list comes first */
static int der_split(const uint8_t *val, size_t vlen, int tap, const uint8_t **fp, uint32_t path[PATH_MAX_DEPTH], int *depth)
{
    const uint8_t *q = val, *end = val + vlen;
    if (tap) {
        uint64_t nh;
        if (rd_cs(&q, end, &nh) || nh > 255 || (uint64_t) (end - q) < nh * 32) return -1;
        q += nh * 32;
    }
    if (end - q < 4 || (end - q - 4) % 4) return -1;
    *fp = q;
    *depth = (int) ((end - q - 4) / 4);
    if (*depth > PATH_MAX_DEPTH) return -1;
    for (int i = 0; i < *depth; i++) path[i] = rd32(q + 4 + 4 * i);
    return 0;
}

static int derive_priv(const bip32_node *master, const uint32_t *path, int depth, uint8_t priv[32])
{
    bip32_node n = *master;
    int r = bip32_derive_path(&n, path, (size_t) depth);
    if (!r) memcpy(priv, n.key, 32);
    secure_zero(&n, sizeof n);
    return r ? BTC_ERR_KEY : BTC_OK;
}

/* ---- scripts ---- */

enum { ST_UNKNOWN, ST_P2PKH, ST_P2SH, ST_P2WPKH, ST_P2WSH, ST_P2TR, ST_OPRET };

static int spk_type(const uint8_t *s, size_t n)
{
    if (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) return ST_P2PKH;
    if (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) return ST_P2SH;
    if (n == 22 && s[0] == 0x00 && s[1] == 0x14) return ST_P2WPKH;
    if (n == 34 && s[0] == 0x00 && s[1] == 0x20) return ST_P2WSH;
    if (n == 34 && s[0] == 0x51 && s[1] == 0x20) return ST_P2TR;
    if (n >= 1 && s[0] == 0x6a) return ST_OPRET;
    return ST_UNKNOWN;
}

/* does the script push this 33 byte key? */
static int script_has_key(const uint8_t *s, size_t n, const uint8_t pub[33])
{
    for (size_t i = 0; i + 34 <= n; i++)
        if (s[i] == 0x21 && !memcmp(s + i + 1, pub, 33)) return 1;
    return 0;
}

static void p2pkh_script(uint8_t s[25], const uint8_t h[20])
{
    s[0] = 0x76; s[1] = 0xa9; s[2] = 0x14;
    memcpy(s + 3, h, 20);
    s[23] = 0x88; s[24] = 0xac;
}

static const char HEXD[] = "0123456789abcdef";

/* a human readable form of an output script */
static void spk_text(const btc_net *net, const uint8_t *s, size_t n, char *out, size_t cap, uint32_t *warn)
{
    int t = spk_type(s, n);
    uint8_t b[21];
    int r = -1;

    switch (t) {
    case ST_P2PKH:
        if (net->cash) { r = cashaddr_p2pkh(out, cap, net->cash, s + 3); break; }
        b[0] = net->p2pkh; memcpy(b + 1, s + 3, 20);
        r = base58check_encode(b, 21, out, cap);
        break;
    case ST_P2SH:
        if (net->cash) { r = cashaddr_encode(out, cap, net->cash, 1, s + 2); break; }
        b[0] = net->p2sh; memcpy(b + 1, s + 2, 20);
        r = base58check_encode(b, 21, out, cap);
        break;
    case ST_P2WPKH: if (net->hrp) r = segwit_addr_encode(out, cap, net->hrp, 0, s + 2, 20); break;
    case ST_P2WSH:  if (net->hrp) r = segwit_addr_encode(out, cap, net->hrp, 0, s + 2, 32); break;
    case ST_P2TR:   if (net->hrp) r = segwit_addr_encode(out, cap, net->hrp, 1, s + 2, 32); break;
    case ST_OPRET:
        *warn |= TXW_DATA;
        strncpy(out, T(TXT_OP_RETURN_DATA), cap - 1);
        out[cap - 1] = 0;
        return;
    default: break;
    }
    if (r < 0) {                                       /* a script we cannot name: its bytes */
        size_t k = 0, show = n > 24 ? 24 : n;
        *warn |= TXW_UNKNOWN_SCRIPT;
        for (size_t i = 0; i < show && k + 3 < cap; i++) { out[k++] = HEXD[s[i] >> 4]; out[k++] = HEXD[s[i] & 15]; }
        if (n > show && k + 3 < cap) { out[k++] = '.'; out[k++] = '.'; }
        out[k] = 0;
    }
}

/* ---- the output that is spent ---- */

typedef struct { uint64_t amount; const uint8_t *spk; size_t spklen; int verified; } prevout;

static int get_prev(const psbt *p, int i, const in_f *f, prevout *r)
{
    const uint8_t *in = p->vin + 41 * i;
    uint32_t vout = rd32(in + 32);

    if (f->nonwit) {
        const uint8_t *t = f->nonwit, *e = t + f->nonwit_len, *q = t + 4, *a0, *a1;
        uint64_t c, nin, nout;
        int segwit;
        sha256_ctx h;
        uint8_t id[32];
        int found = 0;

        if (f->nonwit_len < 10) return BTC_ERR_UTXO;
        segwit = t[4] == 0 && t[5] != 0;
        if (segwit) q += 2;
        a0 = q;
        if (rd_cs(&q, e, &nin)) return BTC_ERR_UTXO;
        for (uint64_t k = 0; k < nin; k++) {
            if (e - q < 36) return BTC_ERR_UTXO;
            q += 36;
            if (rd_cs(&q, e, &c) || (uint64_t) (e - q) < c + 4) return BTC_ERR_UTXO;
            q += c + 4;
        }
        if (rd_cs(&q, e, &nout)) return BTC_ERR_UTXO;
        for (uint64_t k = 0; k < nout; k++) {
            uint64_t sl;
            if (e - q < 9) return BTC_ERR_UTXO;
            if (k == vout) r->amount = rd64(q);
            q += 8;
            if (rd_cs(&q, e, &sl) || (uint64_t) (e - q) < sl) return BTC_ERR_UTXO;
            if (k == vout) { r->spk = q; r->spklen = (size_t) sl; found = 1; }
            q += sl;
        }
        a1 = q;
        if (segwit) {
            for (uint64_t k = 0; k < nin; k++) {
                uint64_t items;
                if (rd_cs(&q, e, &items)) return BTC_ERR_UTXO;
                for (uint64_t m = 0; m < items; m++) {
                    if (rd_cs(&q, e, &c) || (uint64_t) (e - q) < c) return BTC_ERR_UTXO;
                    q += c;
                }
            }
        }
        if (e - q != 4 || !found) return BTC_ERR_UTXO;
        sha256_init(&h);
        sha256_update(&h, t, 4);
        sha256_update(&h, a0, (size_t) (a1 - a0));
        sha256_update(&h, q, 4);
        sha256d_final(&h, id);
        if (memcmp(id, in, 32)) return BTC_ERR_UTXO;                 /* not the transaction this input spends */
        r->verified = 1;
        return BTC_OK;
    }
    if (f->wutxo && f->wutxo_len >= 9) {
        const uint8_t *q = f->wutxo + 8, *e = f->wutxo + f->wutxo_len;
        uint64_t sl;
        if (rd_cs(&q, e, &sl) || (uint64_t) (e - q) != sl) return BTC_ERR_UTXO;
        r->amount = rd64(f->wutxo);
        r->spk = q;
        r->spklen = (size_t) sl;
        r->verified = 0;
        return BTC_OK;
    }
    return BTC_ERR_UTXO;
}

/* ---- a raw key ---- */

static int     g_raw;
static uint8_t g_rawpub[33], g_rawxo[32], g_rawq[32], g_rawh[20], g_rawsh[20], g_redeem[22], g_rawfp[4], g_taprec[5];

int psbt_raw_key(const uint8_t priv[32])
{
    uint8_t tw[32];
    int bad;

    g_raw = 0;
    if (!priv) return BTC_OK;
    if (secp256k1_pubkey_create(g_rawpub, priv)) return BTC_ERR_KEY;
    hash160(g_rawpub, 33, g_rawh);
    g_redeem[0] = 0x00; g_redeem[1] = 0x14;
    memcpy(g_redeem + 2, g_rawh, 20);
    hash160(g_redeem, 22, g_rawsh);
    bad = secp256k1_xonly_pubkey(g_rawxo, NULL, priv) || secp256k1_taproot_tweak_seckey(tw, priv, NULL, 0) || secp256k1_xonly_pubkey(g_rawq, NULL, tw);
    secure_zero(tw, sizeof tw);
    if (bad) return BTC_ERR_KEY;
    memcpy(g_rawfp, g_rawh, 4);                                         /* the fingerprint of a node of depth 0 holding this key (bip32_fingerprint) */
    g_taprec[0] = 0;                                                    /* no leaf hashes */
    memcpy(g_taprec + 1, g_rawfp, 4);
    g_raw = 1;
    return BTC_OK;
}

/* does the script pay to the raw key? (one of its four single key forms) */
static int raw_spk(const uint8_t *spk, size_t n)
{
    switch (spk_type(spk, n)) {
    case ST_P2PKH: return !memcmp(spk + 3, g_rawh, 20);
    case ST_P2WPKH: return !memcmp(spk + 2, g_rawh, 20);
    case ST_P2SH: return !memcmp(spk + 2, g_rawsh, 20);
    case ST_P2TR: return !memcmp(spk + 2, g_rawq, 32);
    default: return 0;
    }
}

/* an input that spends an output of the raw key gets the records a wallet of the master would have written (the fingerprint of the key, an empty path), so the signing and the
 * summary go the way they go for a seed; the previous output is the checked one (get_prev), the PSBT's own words about keys are not needed */
static void raw_fix_in(const psbt *p, int i, in_f *f)
{
    prevout pv;
    int t;

    if (!g_raw || f->final_ || get_prev(p, i, f, &pv) || !raw_spk(pv.spk, pv.spklen)) return;
    t = spk_type(pv.spk, pv.spklen);
    if (t == ST_P2TR) {
        f->tint = g_rawxo;
        f->tmerkle = NULL;
        f->nleaf = 0;
        f->ntder = 1;
        f->tder[0].xo = g_rawxo; f->tder[0].val = g_taprec; f->tder[0].vlen = sizeof g_taprec;
        return;
    }
    if (t == ST_P2SH) { f->redeem = g_redeem; f->redeem_len = sizeof g_redeem; f->wscript = NULL; f->wscript_len = 0; }
    f->nder = 1;
    f->der[0].pub = g_rawpub; f->der[0].val = g_rawfp; f->der[0].vlen = sizeof g_rawfp;
}

/* ---- signature hashes ---- */

static void digest_legacy(const psbt *p, int i, const uint8_t *sc, size_t sclen, uint32_t hashtype, uint8_t out[32])
{
    sha256_ctx c;
    uint8_t b[4];

    sha256_init(&c);
    wr32(b, p->version); sha256_update(&c, b, 4);
    hupd_cs(&c, (uint64_t) p->nin);
    for (int j = 0; j < p->nin; j++) {
        sha256_update(&c, p->vin + 41 * j, 36);
        if (j == i) { hupd_cs(&c, sclen); sha256_update(&c, sc, sclen); }
        else hupd_cs(&c, 0);
        sha256_update(&c, p->vin + 41 * j + 37, 4);
    }
    hupd_cs(&c, (uint64_t) p->nout);
    sha256_update(&c, p->vout, (size_t) (p->vout_end - p->vout));
    wr32(b, p->locktime); sha256_update(&c, b, 4);
    wr32(b, hashtype); sha256_update(&c, b, 4);
    sha256d_final(&c, out);
}

static void digest_bip143(const psbt *p, int i, const uint8_t *sc, size_t sclen, uint64_t amount, uint32_t hashtype, uint8_t out[32])
{
    sha256_ctx c;
    uint8_t hp[32], hs[32], ho[32], b[8];

    sha256_init(&c);
    for (int j = 0; j < p->nin; j++) sha256_update(&c, p->vin + 41 * j, 36);
    sha256d_final(&c, hp);
    sha256_init(&c);
    for (int j = 0; j < p->nin; j++) sha256_update(&c, p->vin + 41 * j + 37, 4);
    sha256d_final(&c, hs);
    sha256_init(&c);
    sha256_update(&c, p->vout, (size_t) (p->vout_end - p->vout));
    sha256d_final(&c, ho);

    sha256_init(&c);
    wr32(b, p->version); sha256_update(&c, b, 4);
    sha256_update(&c, hp, 32);
    sha256_update(&c, hs, 32);
    sha256_update(&c, p->vin + 41 * i, 36);
    hupd_cs(&c, sclen);
    sha256_update(&c, sc, sclen);
    wr64(b, amount); sha256_update(&c, b, 8);
    sha256_update(&c, p->vin + 41 * i + 37, 4);
    sha256_update(&c, ho, 32);
    wr32(b, p->locktime); sha256_update(&c, b, 4);
    wr32(b, hashtype); sha256_update(&c, b, 4);
    sha256d_final(&c, out);
}

/* BIP341, no annex, hash type default (0) or all (1); key path, or the script path of the leaf with the hash `leaf` (BIP342) */
static int digest_taproot(const psbt *p, int i, uint32_t hashtype, const uint8_t *leaf, uint8_t out[32])
{
    sha256_ctx c, ca, cs_, cq, co;
    uint8_t h1[32], h2[32], h3[32], h4[32], h5[32], b[8];

    sha256_init(&c); sha256_init(&ca); sha256_init(&cs_); sha256_init(&cq);
    for (int j = 0; j < p->nin; j++) {
        in_f f;
        prevout pv;
        int e = parse_in(p, j, &f);
        if (!e) e = get_prev(p, j, &f, &pv);
        if (e) return e;
        sha256_update(&c, p->vin + 41 * j, 36);
        wr64(b, pv.amount); sha256_update(&ca, b, 8);
        hupd_cs(&cs_, pv.spklen); sha256_update(&cs_, pv.spk, pv.spklen);
        sha256_update(&cq, p->vin + 41 * j + 37, 4);
    }
    sha256_final(&c, h1); sha256_final(&ca, h2); sha256_final(&cs_, h3); sha256_final(&cq, h4);
    sha256_init(&co);
    sha256_update(&co, p->vout, (size_t) (p->vout_end - p->vout));
    sha256_final(&co, h5);

    sha256_tagged_init(&c, "TapSighash");
    b[0] = 0x00; sha256_update(&c, b, 1);                    /* epoch */
    b[0] = (uint8_t) hashtype; sha256_update(&c, b, 1);
    wr32(b, p->version); sha256_update(&c, b, 4);
    wr32(b, p->locktime); sha256_update(&c, b, 4);
    sha256_update(&c, h1, 32); sha256_update(&c, h2, 32); sha256_update(&c, h3, 32); sha256_update(&c, h4, 32);
    sha256_update(&c, h5, 32);
    b[0] = leaf ? 0x02 : 0x00; sha256_update(&c, b, 1);      /* spend type: the extension flag of a script path, no annex */
    wr32(b, (uint32_t) i); sha256_update(&c, b, 4);
    if (leaf) {
        sha256_update(&c, leaf, 32);
        b[0] = 0x00; sha256_update(&c, b, 1);                /* key version */
        wr32(b, 0xffffffffu); sha256_update(&c, b, 4);       /* no OP_CODESEPARATOR */
    }
    sha256_final(&c, out);
    return BTC_OK;
}

/* ---- signing ---- */

static void w_psig(wr *w, const uint8_t pub[33], const uint8_t *sig, size_t slen)
{
    uint8_t h[2] = {34, 0x02};
    w_put(w, h, 2);
    w_put(w, pub, 33);
    h[0] = (uint8_t) slen;
    w_put(w, h, 1);
    w_put(w, sig, slen);
}

/* sign input i; appends the records to w. *n counts signatures; returns BTC_OK or an error (an input that is not ours is not an error) */
static int sign_input(const psbt *p, int i, const btc_net *net, const bip32_node *m, const uint8_t mfp[4], wr *w, int *n)
{
    in_f f;
    prevout pv;
    uint8_t h160[20], sc[25], dig[32], priv[32], pub[33], sig[64], der[80];
    const uint8_t *script = NULL;
    size_t scriptlen = 0;
    int type, e, algo = 0, nonwit_needed;      /* algo: 0 legacy, 1 BIP143, 2 taproot */
    uint32_t hashtype = 1;

    e = parse_in(p, i, &f);
    if (e) return e;
    if (f.final_) return BTC_OK;
    if (f.has_sighash) {
        if (f.sighash == 1 || (f.sighash == 0 && f.tint)) hashtype = f.sighash;
        else if (net->forkid && f.sighash == 0x41) hashtype = 0x41;
        else return BTC_ERR_SIGHASH;
    } else {
        hashtype = f.tint ? 0 : (net->forkid ? 0x41 : 1);
    }
    e = get_prev(p, i, &f, &pv);
    type = e ? ST_UNKNOWN : spk_type(pv.spk, pv.spklen);
    if (e == BTC_ERR_UTXO && (f.ntder || f.nder)) {
        /* an input of ours without its previous transaction: refuse rather than sign blind */
        for (int k = 0; k < f.nder + f.ntder; k++) {
            const uint8_t *fp; uint32_t path[PATH_MAX_DEPTH]; int d;
            const uint8_t *val = k < f.nder ? f.der[k].val : f.tder[k - f.nder].val;
            size_t vl = k < f.nder ? f.der[k].vlen : f.tder[k - f.nder].vlen;
            if (!der_split(val, vl, k >= f.nder, &fp, path, &d) && !memcmp(fp, mfp, 4)) return BTC_ERR_UTXO;
        }
        return BTC_OK;
    }
    if (e) return e;
    nonwit_needed = type != ST_P2TR;
    if (nonwit_needed && !pv.verified) {
        for (int k = 0; k < f.nder; k++) {
            const uint8_t *fp; uint32_t path[PATH_MAX_DEPTH]; int d;
            if (!der_split(f.der[k].val, f.der[k].vlen, 0, &fp, path, &d) && !memcmp(fp, mfp, 4)) return BTC_ERR_UTXO;
        }
        return BTC_OK;
    }

    if (type == ST_P2TR) {
        const uint8_t *fp;
        uint32_t path[PATH_MAX_DEPTH];
        int d;
        uint8_t xo[32], q[32];
        for (int k = 0; f.tint && k < f.ntder; k++) {                       /* the key path */
            if (memcmp(f.tder[k].xo, f.tint, 32)) continue;
            if (der_split(f.tder[k].val, f.tder[k].vlen, 1, &fp, path, &d) || memcmp(fp, mfp, 4)) continue;
            if (derive_priv(m, path, d, priv)) return BTC_ERR_KEY;
            if (secp256k1_xonly_pubkey(xo, NULL, priv) || memcmp(xo, f.tint, 32)) { secure_zero(priv, 32); continue; }
            if (secp256k1_taproot_tweak_seckey(priv, priv, f.tmerkle, f.tmerkle ? 32 : 0)) { secure_zero(priv, 32); return BTC_ERR_KEY; }
            if (secp256k1_xonly_pubkey(q, NULL, priv) || memcmp(q, pv.spk + 2, 32)) { secure_zero(priv, 32); continue; }   /* not this output key */
            e = digest_taproot(p, i, hashtype, NULL, dig);
            if (e) { secure_zero(priv, 32); return e; }
            if (secp256k1_schnorr_sign(sig, priv, dig, NULL)) { secure_zero(priv, 32); return BTC_ERR_KEY; }
            secure_zero(priv, 32);
            {
                uint8_t hd[2] = {1, 0x13}, l = (uint8_t) (hashtype ? 65 : 64), sg[65];
                memcpy(sg, sig, 64);
                sg[64] = (uint8_t) hashtype;
                w_put(w, hd, 2);
                w_put(w, &l, 1);
                w_put(w, sg, l);
            }
            (*n)++;
            break;
        }
        for (int k = 0; k < f.ntder; k++) {                                 /* the script paths: PSBT_IN_TAP_SCRIPT_SIG of every leaf the record of our key lists */
            const uint8_t *rec = f.tder[k].val, *rend = rec + f.tder[k].vlen;
            uint64_t nh;
            if (der_split(f.tder[k].val, f.tder[k].vlen, 1, &fp, path, &d) || memcmp(fp, mfp, 4)) continue;
            if (rd_cs(&rec, rend, &nh) || !nh) continue;
            if (derive_priv(m, path, d, priv)) return BTC_ERR_KEY;
            if (secp256k1_xonly_pubkey(xo, NULL, priv) || memcmp(xo, f.tder[k].xo, 32)) { secure_zero(priv, 32); continue; }
            for (uint64_t h = 0; h < nh; h++) {
                const uint8_t *want = rec + 32 * h;
                for (int l = 0; l < f.nleaf; l++) {
                    sha256_ctx c;
                    uint8_t lh[32], ver = f.leaf[l].ver, cs[9];
                    sha256_tagged_init(&c, "TapLeaf");
                    sha256_update(&c, &ver, 1);
                    sha256_update(&c, cs, cs_put(cs, f.leaf[l].slen));
                    sha256_update(&c, f.leaf[l].script, f.leaf[l].slen);
                    sha256_final(&c, lh);
                    if (memcmp(lh, want, 32)) continue;
                    e = digest_taproot(p, i, hashtype, lh, dig);
                    if (e) { secure_zero(priv, 32); return e; }
                    if (secp256k1_schnorr_sign(sig, priv, dig, NULL)) { secure_zero(priv, 32); return BTC_ERR_KEY; }
                    {
                        uint8_t hd[2] = {65, 0x14}, vl = (uint8_t) (hashtype ? 65 : 64), sg[65];
                        memcpy(sg, sig, 64);
                        sg[64] = (uint8_t) hashtype;
                        w_put(w, hd, 2);
                        w_put(w, xo, 32);
                        w_put(w, lh, 32);
                        w_put(w, &vl, 1);
                        w_put(w, sg, vl);
                    }
                    (*n)++;
                    break;
                }
            }
            secure_zero(priv, 32);
        }
        return BTC_OK;
    }

    /* the script that is hashed, and how */
    switch (type) {
    case ST_P2PKH:
        script = pv.spk; scriptlen = 25; algo = net->forkid ? 1 : 0;
        break;
    case ST_P2WPKH:
        p2pkh_script(sc, pv.spk + 2); script = sc; scriptlen = 25; algo = 1;
        break;
    case ST_P2WSH:
        if (!f.wscript) return BTC_OK;
        sha256(f.wscript, f.wscript_len, dig);
        if (memcmp(dig, pv.spk + 2, 32)) return BTC_OK;
        script = f.wscript; scriptlen = f.wscript_len; algo = 1;
        break;
    case ST_P2SH:
        if (!f.redeem) return BTC_OK;
        hash160(f.redeem, f.redeem_len, h160);
        if (memcmp(h160, pv.spk + 2, 20)) return BTC_OK;
        if (spk_type(f.redeem, f.redeem_len) == ST_P2WPKH) {
            p2pkh_script(sc, f.redeem + 2); script = sc; scriptlen = 25; algo = 1;
        } else if (spk_type(f.redeem, f.redeem_len) == ST_P2WSH) {
            if (!f.wscript) return BTC_OK;
            sha256(f.wscript, f.wscript_len, dig);
            if (memcmp(dig, f.redeem + 2, 32)) return BTC_OK;
            script = f.wscript; scriptlen = f.wscript_len; algo = 1;
        } else {
            script = f.redeem; scriptlen = f.redeem_len; algo = net->forkid ? 1 : 0;
        }
        break;
    default:
        return BTC_OK;
    }
    if (algo == 1) digest_bip143(p, i, script, scriptlen, pv.amount, hashtype, dig);
    else digest_legacy(p, i, script, scriptlen, hashtype, dig);

    for (int k = 0; k < f.nder; k++) {
        const uint8_t *fp;
        uint32_t path[PATH_MAX_DEPTH];
        int d, ok;

        if (der_split(f.der[k].val, f.der[k].vlen, 0, &fp, path, &d) || memcmp(fp, mfp, 4)) continue;
        if (derive_priv(m, path, d, priv)) return BTC_ERR_KEY;
        if (secp256k1_pubkey_create(pub, priv) || memcmp(pub, f.der[k].pub, 33)) { secure_zero(priv, 32); continue; }
        hash160(pub, 33, h160);
        if (type == ST_P2PKH) ok = !memcmp(h160, pv.spk + 3, 20);
        else if (type == ST_P2WPKH) ok = !memcmp(h160, pv.spk + 2, 20);
        else if (type == ST_P2SH && spk_type(f.redeem, f.redeem_len) == ST_P2WPKH) ok = !memcmp(h160, f.redeem + 2, 20);
        else ok = script_has_key(script, scriptlen, pub);
        if (ok) {
            int dl;
            if (secp256k1_ecdsa_sign(sig, NULL, priv, dig)) { secure_zero(priv, 32); return BTC_ERR_KEY; }
            dl = secp256k1_sig_to_der(der, sig);
            der[dl] = (uint8_t) hashtype;
            w_psig(w, pub, der, (size_t) dl + 1);
            (*n)++;
        }
        secure_zero(priv, 32);
    }
    return BTC_OK;
}

/* the network transaction, from the original PSBT and the signatures, if every input is a single key kind */
static int build_final(const psbt *p, const psbt *sp, uint8_t *out, size_t cap, size_t *outlen)
{
    wr w = {out, cap, 0, 0};
    uint8_t b[9];
    int any_wit = 0;

    *outlen = 0;
    for (int i = 0; i < p->nin; i++) {
        in_f f, g;
        prevout pv;
        parse_in(p, i, &f);
        parse_in(sp, i, &g);
        if (get_prev(p, i, &f, &pv)) return BTC_OK;
        if (spk_type(pv.spk, pv.spklen) == ST_P2WPKH || spk_type(pv.spk, pv.spklen) == ST_P2TR ||
            (spk_type(pv.spk, pv.spklen) == ST_P2SH && f.redeem && spk_type(f.redeem, f.redeem_len) == ST_P2WPKH)) any_wit = 1;
        if (!g.npsig && !g.tsig) return BTC_OK;                     /* an input without our signature: leave it to the host */
        {
            int t = spk_type(pv.spk, pv.spklen);
            if (t != ST_P2PKH && t != ST_P2WPKH && t != ST_P2TR && !(t == ST_P2SH && f.redeem && spk_type(f.redeem, f.redeem_len) == ST_P2WPKH)) return BTC_OK;
        }
    }
    wr32(b, p->version); w_put(&w, b, 4);
    if (any_wit) { b[0] = 0; b[1] = 1; w_put(&w, b, 2); }
    w_put(&w, b, cs_put(b, (uint64_t) p->nin));
    for (int i = 0; i < p->nin; i++) {
        in_f f, g;
        prevout pv;
        int t;
        uint8_t ss[120];
        size_t sl = 0;
        parse_in(p, i, &f);
        parse_in(sp, i, &g);
        get_prev(p, i, &f, &pv);
        t = spk_type(pv.spk, pv.spklen);
        w_put(&w, p->vin + 41 * i, 36);
        if (t == ST_P2PKH) {
            ss[sl++] = (uint8_t) g.psig[0].slen; memcpy(ss + sl, g.psig[0].sig, g.psig[0].slen); sl += g.psig[0].slen;
            ss[sl++] = 33; memcpy(ss + sl, g.psig[0].pub, 33); sl += 33;
        } else if (t == ST_P2SH) {
            ss[sl++] = (uint8_t) f.redeem_len; memcpy(ss + sl, f.redeem, f.redeem_len); sl += f.redeem_len;
        }
        w_put(&w, b, cs_put(b, sl));
        w_put(&w, ss, sl);
        w_put(&w, p->vin + 41 * i + 37, 4);
    }
    w_put(&w, b, cs_put(b, (uint64_t) p->nout));
    w_put(&w, p->vout, (size_t) (p->vout_end - p->vout));
    if (any_wit) {
        for (int i = 0; i < p->nin; i++) {
            in_f f, g;
            prevout pv;
            int t;
            parse_in(p, i, &f);
            parse_in(sp, i, &g);
            get_prev(p, i, &f, &pv);
            t = spk_type(pv.spk, pv.spklen);
            if (t == ST_P2PKH) { b[0] = 0; w_put(&w, b, 1); }
            else if (t == ST_P2TR) {
                b[0] = 1; w_put(&w, b, 1);
                b[0] = (uint8_t) g.tsig_len; w_put(&w, b, 1);
                w_put(&w, g.tsig, g.tsig_len);
            } else {
                b[0] = 2; w_put(&w, b, 1);
                b[0] = (uint8_t) g.psig[0].slen; w_put(&w, b, 1);
                w_put(&w, g.psig[0].sig, g.psig[0].slen);
                b[0] = 33; w_put(&w, b, 1);
                w_put(&w, g.psig[0].pub, 33);
            }
        }
    }
    wr32(b, p->locktime); w_put(&w, b, 4);
    if (w.err) return BTC_ERR_SPACE;
    *outlen = w.n;
    return BTC_OK;
}

int psbt_sign(const psbt *p, const btc_net *net, const bip32_node *master, uint8_t *out, size_t cap, size_t *outlen,
              uint8_t *tx, size_t txcap, size_t *txlen, int *nsigned)
{
    wr w = {out, cap, 0, 0};
    uint8_t mfp[4], z = 0;
    int n = 0, e;
    uint8_t ktx[2] = {1, 0x00};

    if (txlen) *txlen = 0;
    if (bip32_fingerprint(master, mfp)) return BTC_ERR_KEY;
    w_put(&w, "psbt\xff", 5);
    w_put(&w, ktx, 2);
    {
        uint8_t l[9];
        w_put(&w, l, cs_put(l, p->txlen));
    }
    w_put(&w, p->tx, p->txlen);
    w_put(&w, &z, 1);
    for (int i = 0; i < p->nin; i++) {
        e = sign_input(p, i, net, master, mfp, &w, &n);
        if (e) return e;
        w_put(&w, &z, 1);
    }
    for (int j = 0; j < p->nout; j++) w_put(&w, &z, 1);
    if (w.err) return BTC_ERR_SPACE;
    *outlen = w.n;
    if (nsigned) *nsigned = n;
    if (!n) return BTC_ERR_NOKEY;
    if (tx) {
        psbt sp;
        if (psbt_parse(&sp, out, w.n) == BTC_OK) {
            e = build_final(p, &sp, tx, txcap, txlen ? txlen : &w.n);
            if (e) return e;
        }
    }
    return BTC_OK;
}

/* the text of an output script, for the screens that show an address of a script (the first address of a wallet) */
void btc_spk_text(const btc_net *net, const uint8_t *spk, size_t n, char *out, size_t cap)
{
    uint32_t w = 0;
    spk_text(net, spk, n, out, cap, &w);
}

/* ---- registered multisig wallets ---- */

#define WAL_MAX 4
static const ms_policy *g_wal;
static int g_nwal;
static ms_cache g_wcache[WAL_MAX];

void psbt_set_wallets(const ms_policy *w, int n)
{
    g_wal = w;
    g_nwal = n > WAL_MAX ? WAL_MAX : n;
    memset(g_wcache, 0, sizeof g_wcache);
}

/* The registered wallet whose address has this output script, looking where the derivation records of the PSBT point (chain / index are the last two steps of a path): the script
 * is made from the extended keys of the wallet alone, so a match is proof, whatever else the PSBT claims. Returns the wallet, or -1. */
static int wallet_find(const uint8_t *spk, size_t spklen, const uint8_t *const *vals, const size_t *vlens, int nrec, int m, int n)
{
    unsigned tried[2][2] = {{9, 0}, {9, 0}};
    int ntried = 0;

    for (int r = 0; r < nrec && ntried < 2; r++) {
        const uint8_t *fp;
        uint32_t path[PATH_MAX_DEPTH];
        int d, seen = 0;
        unsigned chain, idx;

        if (der_split(vals[r], vlens[r], 0, &fp, path, &d) || d < 2) continue;
        chain = path[d - 2];
        idx = path[d - 1];
        if (chain > 1 || idx >= 0x80000000u) continue;
        for (int t = 0; t < ntried; t++) if (tried[t][0] == chain && tried[t][1] == idx) seen = 1;
        if (seen) continue;
        tried[ntried][0] = chain; tried[ntried][1] = idx; ntried++;
        for (int w = 0; w < g_nwal; w++) {
            uint8_t sc[MS_SCRIPT_MAX], sp[34];
            size_t sl, pl;
            const ms_policy *pw = &g_wal[w];

            if (m && (pw->m != m || pw->n != n)) continue;
            if ((pw->type == MS_WSH) != (spklen == 34)) continue;      /* a P2WSH output script is 34 bytes, a script hash one 23 */
            if (ms_script(pw, &g_wcache[w], chain, idx, sc, &sl, sp, &pl) || pl != spklen) continue;
            if (!memcmp(sp, spk, pl)) return w;
        }
    }
    return -1;
}

/* ---- the summary ---- */

/* is output j a change output: its derivation record is ours and the script is the one of the key at the path */
static int out_is_mine(const psbt *p, int j, const uint8_t *spk, size_t spklen, const bip32_node *m, const uint8_t mfp[4])
{
    const uint8_t *q = p->out_map[j], *end = p->buf + p->len, *key, *val;
    size_t kl, vl;
    const uint8_t *redeem = NULL, *tint = NULL, *tder_val = NULL;
    size_t redeem_len = 0, tder_len = 0;
    const uint8_t *der_pub[2] = {0}, *der_val[2] = {0};
    size_t der_len[2] = {0};
    const uint8_t *w_val[8];
    size_t w_len[8];
    int nder = 0, nw = 0, tree = 0, type = spk_type(spk, spklen), r;
    uint8_t priv[32], pub[33], h[20];

    if (g_raw) return raw_spk(spk, spklen);                       /* a raw key: the script says it, the PSBT's records are not needed */
    while ((r = map_next(&q, end, &key, &kl, &val, &vl)) == 1) {
        if (key[0] == 0x00 && kl == 1) { redeem = val; redeem_len = vl; }
        else if (key[0] == 0x02 && kl == 34) {
            if (nder < 2) { der_pub[nder] = key + 1; der_val[nder] = val; der_len[nder] = vl; nder++; }
            if (nw < 8) { w_val[nw] = val; w_len[nw] = vl; nw++; }
        }
        else if (key[0] == 0x05 && kl == 1 && vl == 32) tint = val;
        else if (key[0] == 0x06 && kl == 1) tree = 1;
        else if (key[0] == 0x07 && kl == 33) { tder_val = val; tder_len = vl; }
    }
    if (r < 0) return 0;
    if (type == ST_P2TR) {
        const uint8_t *fp;
        uint32_t path[PATH_MAX_DEPTH];
        int d;
        uint8_t q2[32];
        if (!tint || !tder_val || tree) return 0;
        if (der_split(tder_val, tder_len, 1, &fp, path, &d) || memcmp(fp, mfp, 4)) return 0;
        if (derive_priv(m, path, d, priv)) return 0;
        if (secp256k1_taproot_tweak_seckey(priv, priv, NULL, 0) || secp256k1_xonly_pubkey(q2, NULL, priv)) { secure_zero(priv, 32); return 0; }
        secure_zero(priv, 32);
        return !memcmp(q2, spk + 2, 32);
    }
    for (int k = 0; k < nder; k++) {
        const uint8_t *fp;
        uint32_t path[PATH_MAX_DEPTH];
        int d, ok = 0;
        if (der_split(der_val[k], der_len[k], 0, &fp, path, &d) || memcmp(fp, mfp, 4)) continue;
        if (derive_priv(m, path, d, priv)) return 0;
        r = secp256k1_pubkey_create(pub, priv);
        secure_zero(priv, 32);
        if (r || memcmp(pub, der_pub[k], 33)) continue;
        hash160(pub, 33, h);
        if (type == ST_P2PKH) ok = !memcmp(h, spk + 3, 20);
        else if (type == ST_P2WPKH) ok = !memcmp(h, spk + 2, 20);
        else if (type == ST_P2SH && redeem && spk_type(redeem, redeem_len) == ST_P2WPKH) {
            uint8_t h2[20];
            hash160(redeem, redeem_len, h2);
            ok = !memcmp(h2, spk + 2, 20) && !memcmp(h, redeem + 2, 20);
        }
        if (ok) return 1;
    }
    if ((type == ST_P2WSH || type == ST_P2SH) && g_nwal && nw) return wallet_find(spk, spklen, w_val, w_len, nw, 0, 0) >= 0;     /* change back to a registered multisig wallet */
    return 0;
}

/* ---- what the summary tells besides the outputs: size and fee rate, replaceability, lock time, multisig ---- */

typedef struct { int m, n; const uint8_t *pub[16]; } msig;

/* OP_m <key>... OP_n OP_CHECKMULTISIG with compressed keys */
static int msig_parse(const uint8_t *s, size_t len, msig *ms)
{
    size_t i = 1;

    if (len < 37 || s[len - 1] != 0xae || s[0] < 0x51 || s[0] > 0x60) return -1;
    ms->m = s[0] - 0x50;
    ms->n = 0;
    while (i + 34 <= len - 2 && s[i] == 0x21 && ms->n < 16) { ms->pub[ms->n++] = s + i + 1; i += 34; }
    if (i != len - 2 || s[len - 2] < 0x51 || s[len - 2] > 0x60 || s[len - 2] - 0x50 != ms->n || ms->m > ms->n) return -1;
    return 0;
}

/* The script an input proves with when it is a script hash: *sc, *sl. Returns 0 if that cannot be told (not a script hash, or the script is not in the PSBT), 1 for
 * P2SH, 2 for P2WSH, 3 for P2SH-P2WSH, -1 if the script is not the one the output commits to. */
static int script_of(const prevout *pv, const in_f *f, const uint8_t **sc, size_t *sl)
{
    uint8_t h[32];
    int t = spk_type(pv->spk, pv->spklen);

    if (t == ST_P2WSH) {
        if (!f->wscript) return 0;
        sha256(f->wscript, f->wscript_len, h);
        if (memcmp(h, pv->spk + 2, 32)) return -1;
        *sc = f->wscript; *sl = f->wscript_len;
        return 2;
    }
    if (t == ST_P2SH) {
        if (!f->redeem) return 0;
        hash160(f->redeem, f->redeem_len, h);
        if (memcmp(h, pv->spk + 2, 20)) return -1;
        if (spk_type(f->redeem, f->redeem_len) == ST_P2WSH) {
            if (!f->wscript) return 0;
            sha256(f->wscript, f->wscript_len, h);
            if (memcmp(h, f->redeem + 2, 32)) return -1;
            *sc = f->wscript; *sl = f->wscript_len;
            return 3;
        }
        if (spk_type(f->redeem, f->redeem_len) == ST_P2WPKH) return 0;
        *sc = f->redeem; *sl = f->redeem_len;
        return 1;
    }
    return 0;
}

static unsigned vi_len(uint64_t n) { return n < 0xfd ? 1u : n <= 0xffff ? 3u : 5u; }

/* The size of an input once signed, estimated with 72 byte signatures: *base the bytes outside the witness (outpoint, script length, scriptSig, sequence),
 * *wit the witness bytes (0 for a non-segwit input). `ms` is the multisig of its script if it has one. */
static void est_input(const prevout *pv, int have_pv, const in_f *f, const msig *ms, unsigned *base, unsigned *wit)
{
    unsigned ss = 107, w = 0;                                 /* an unknown input counts as P2PKH */
    int t = have_pv ? spk_type(pv->spk, pv->spklen) : ST_P2PKH;
    unsigned m = ms ? (unsigned) ms->m : 1;

    switch (t) {
    case ST_P2WPKH: ss = 0; w = 1 + 1 + 72 + 1 + 33; break;
    case ST_P2TR: ss = 0; w = 1 + 1 + 64; break;
    case ST_P2WSH: ss = 0; w = 1 + 1 + m * 73 + vi_len(f->wscript_len) + (unsigned) f->wscript_len; break;
    case ST_P2SH:
        if (f->redeem && spk_type(f->redeem, f->redeem_len) == ST_P2WPKH) { ss = 23; w = 1 + 1 + 72 + 1 + 33; }
        else if (f->redeem && spk_type(f->redeem, f->redeem_len) == ST_P2WSH) { ss = 35; w = 1 + 1 + m * 73 + vi_len(f->wscript_len) + (unsigned) f->wscript_len; }
        else {
            unsigned rl = (unsigned) f->redeem_len;
            ss = 1 + m * 73 + (rl < 76 ? 1 : rl < 256 ? 2 : 3) + rl;
        }
        break;
    default: break;
    }
    *base = 41 + ss + (ss >= 253 ? 2u : 0u);
    *wit = w;
}

/* days since 1970-01-01 -> year, month, day (proleptic Gregorian) */
static void civil(uint32_t days, unsigned *y, unsigned *m, unsigned *d)
{
    uint32_t z = days + 719468, era = z / 146097, doe = z - era * 146097, yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, doy;
    uint32_t mp;

    *y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    if (*m <= 2) (*y)++;
}

/* the line that names the keys of a multisig script: ours as "you", the others by the fingerprint of their derivation record, or "?" */
static void ms_describe(char *line, size_t cap, const msig *ms, const in_f *f, const bip32_node *master, const uint8_t mfp[4])
{
    size_t o = (size_t) snprintf(line, cap, T(TXT_MULTISIG_N_OF_N), ms->m, ms->n);

    for (int k = 0; k < ms->n && o + 11 < cap; k++) {
        const uint8_t *fp4 = NULL;
        int you = 0;
        for (int d = 0; d < f->nder; d++) {
            if (memcmp(f->der[d].pub, ms->pub[k], 33) || f->der[d].vlen < 4) continue;
            fp4 = f->der[d].val;
            if (master && !memcmp(fp4, mfp, 4)) {
                const uint8_t *fp; uint32_t path[PATH_MAX_DEPTH]; int dd; uint8_t priv[32], pub[33];
                if (!der_split(f->der[d].val, f->der[d].vlen, 0, &fp, path, &dd) && !derive_priv(master, path, dd, priv)) {
                    you = !secp256k1_pubkey_create(pub, priv) && !memcmp(pub, ms->pub[k], 33);
                    secure_zero(priv, 32);
                }
            }
        }
        if (you) o += (size_t) snprintf(line + o, cap - o, T(TXT_YOU));
        else if (fp4) o += (size_t) snprintf(line + o, cap - o, " %02x%02x%02x%02x", fp4[0], fp4[1], fp4[2], fp4[3]);
        else o += (size_t) snprintf(line + o, cap - o, " ?");
    }
}

int psbt_summary(const psbt *p, const btc_net *net, const bip32_node *master, tx_view *v)
{
    uint64_t in_sum = 0, out_sum = 0, spend = 0;
    int unknown_in = 0, rbf = 0, all_final = 1, nms = 0, ms_mixed = 0, next = 0, unreg = 0, wal_first = -1, wal_mixed = 0, tapscript = 0;
    unsigned nonwit = 4 + vi_len((uint64_t) p->nin) + 4, witsum = 0, anywit = 0;
    char ms_line[96] = "";
    msig ms0 = {0, 0, {0}};
    uint8_t mfp[4] = {0};
    const uint8_t *q = p->vout;

    txv_clear(v);
    strncpy(v->title, net->name, sizeof v->title - 1);
    strncat(v->title, T(TXT_TRANSACTION), sizeof v->title - strlen(v->title) - 1);
    v->ninputs = p->nin;
    if (master) bip32_fingerprint(master, mfp);

    for (int i = 0; i < p->nin; i++) {
        in_f f;
        prevout pv;
        msig ms;
        const uint8_t *sc = NULL;
        size_t sl = 0;
        unsigned b, w;
        uint32_t seq = rd32(p->vin + 41 * i + 37);
        int e = parse_in(p, i, &f), have_ms = 0, kind;
        if (e) return e;
        if (seq < 0xfffffffe) rbf = 1;
        if (seq != 0xffffffff) all_final = 0;
        e = get_prev(p, i, &f, &pv);
        if (e) { unknown_in = 1; v->warn |= TXW_NO_FEE; }
        else {
            in_sum += pv.amount;
            if (!pv.verified) v->warn |= TXW_UNVERIFIED;
            kind = script_of(&pv, &f, &sc, &sl);
            if (kind < 0) v->warn |= TXW_UNVERIFIED;           /* the script in the PSBT is not the one the spent output commits to */
            else if (kind > 0 && !msig_parse(sc, sl, &ms)) have_ms = 1;
        }
        est_input(&pv, !e, &f, have_ms ? &ms : NULL, &b, &w);
        nonwit += b;
        witsum += w ? w : 1;
        if (w) anywit = 1;
        if (have_ms) {
            int w = -1;

            nms++;
            if (g_nwal) {                                      /* is it an address of a registered wallet? */
                const uint8_t *vv[8];
                size_t vl[8];
                for (int d = 0; d < f.nder; d++) { vv[d] = f.der[d].val; vl[d] = f.der[d].vlen; }
                w = wallet_find(pv.spk, pv.spklen, vv, vl, f.nder, ms.m, ms.n);
            }
            if (w < 0) unreg = 1;
            else if (wal_first < 0) wal_first = w;
            else if (w != wal_first) wal_mixed = 1;
            if (nms == 1) { ms0 = ms; ms_describe(ms_line, sizeof ms_line, &ms, &f, master, mfp); }    /* the first multisig input: whose keys they are */
            else if (ms.m != ms0.m || ms.n != ms0.n) ms_mixed = 1;
        }
        if (master) {
            int mine = 0;
            for (int k = 0; k < f.nder && !mine; k++) {
                const uint8_t *fp; uint32_t path[PATH_MAX_DEPTH]; int d;
                if (!der_split(f.der[k].val, f.der[k].vlen, 0, &fp, path, &d) && !memcmp(fp, mfp, 4)) mine = 1;
            }
            for (int k = 0; k < f.ntder && !mine; k++) {
                const uint8_t *fp; uint32_t path[PATH_MAX_DEPTH]; int d;
                if (!der_split(f.tder[k].val, f.tder[k].vlen, 1, &fp, path, &d) && !memcmp(fp, mfp, 4)) {
                    const uint8_t *rec = f.tder[k].val;
                    uint64_t nh;
                    mine = 1;
                    if (!rd_cs(&rec, f.tder[k].val + f.tder[k].vlen, &nh) && nh && f.nleaf) tapscript = 1;     /* a script path leaf is signed */
                }
            }
            v->nsign += mine;
        }
        if (f.has_sighash && f.sighash != 1 && f.sighash != 0 && !(net->forkid && f.sighash == 0x41)) v->warn |= TXW_NONSTD_SIGHASH;
    }
    if (master && !v->nsign) v->warn |= TXW_NOT_MINE;

    nonwit += vi_len((uint64_t) p->nout);
    for (int j = 0; j < p->nout; j++) {
        uint64_t sl, amount = rd64(q);
        const uint8_t *spk;
        int mine;
        q += 8;
        rd_cs(&q, p->vout_end, &sl);
        spk = q;
        q += sl;
        nonwit += 8 + vi_len(sl) + (unsigned) sl;
        out_sum += amount;
        mine = master ? out_is_mine(p, j, spk, (size_t) sl, master, mfp) : 0;
        if (!mine) { spend += amount; if (spk_type(spk, (size_t) sl) != ST_OPRET) next++; }
        if (v->nout < TXV_OUTS) {
            txv_out *o = &v->out[v->nout++];
            spk_text(net, spk, (size_t) sl, o->to, sizeof o->to, &v->warn);
            txv_amount_u64(o->amount, sizeof o->amount, amount, net->decimals, net->sym);
            o->mine = (uint8_t) mine;
        } else {
            v->nmore++;
            v->warn |= TXW_TRUNCATED;
        }
    }
    txv_amount_u64(v->total, sizeof v->total, spend, net->decimals, net->sym);
    if (!unknown_in) {
        if (in_sum >= out_sum) {
            uint64_t fee = in_sum - out_sum, weight = 4ull * nonwit + (anywit ? 2 + witsum : 0), vsize = (weight + 3) / 4;
            char line[96];

            txv_amount_u64(v->fee, sizeof v->fee, fee, net->decimals, net->sym);
            if (fee * 10 > in_sum) v->warn |= TXW_HIGH_FEE;
            if (vsize) {
                uint64_t r10 = fee * 10 / vsize;
                snprintf(line, sizeof line, T(TXT_FEE_RATE_N_SAT_VB_ABOUT_N_VB), (unsigned) (r10 / 10), (unsigned) (r10 % 10), (unsigned) vsize);
                txv_note(v, line);
            }
        } else {
            v->warn |= TXW_NO_FEE;                         /* the outputs are worth more than the inputs: nonsense */
            strcpy(v->fee, "?");
        }
    }
    if (nms) {
        if (unreg) v->warn |= TXW_UNREG_MULTISIG;
        if (ms_mixed) txv_note(v, T(TXT_SEVERAL_MULTISIG_SCRIPTS_OF));
        else if (!unreg && !wal_mixed && wal_first >= 0) {                    /* all inputs are of one registered wallet: its name and its cosigners */
            const ms_policy *w = &g_wal[wal_first];
            char line[96];
            uint8_t id[4];
            int ours = master ? ms_ours(w, master) : -1;
            size_t o;
            ms_id(w, id);
            o = (size_t) snprintf(line, sizeof line, T(TXT_WALLET_N_OF_N), id[0], id[1], id[2], id[3], w->m, w->n);
            for (int k = 0; k < w->n && o + 11 < sizeof line; k++) {
                if (k == ours) o += (size_t) snprintf(line + o, sizeof line - o, T(TXT_YOU));
                else o += (size_t) snprintf(line + o, sizeof line - o, " %02x%02x%02x%02x", w->key[k].fp[0], w->key[k].fp[1], w->key[k].fp[2], w->key[k].fp[3]);
            }
            txv_note(v, line);
        } else txv_note(v, ms_line);
    }
    if (rbf && !net->forkid) txv_note(v, T(TXT_REPLACEABLE_RBF_A_HIGHER_FEE));
    if (p->locktime) {
        char line[96];
        if (all_final) snprintf(line, sizeof line, T(TXT_LOCK_TIME_N_IS_NOT_ENFORCED), (unsigned) p->locktime);
        else if (p->locktime < 500000000u) snprintf(line, sizeof line, T(TXT_CANNOT_BE_MINED_BEFORE_BLOCK_N), (unsigned) p->locktime);
        else {
            unsigned y, mo, d;
            civil(p->locktime / 86400, &y, &mo, &d);
            snprintf(line, sizeof line, T(TXT_CANNOT_BE_MINED_BEFORE_N_UTC), y, mo, d, (unsigned) (p->locktime % 86400 / 3600), (unsigned) (p->locktime % 3600 / 60));
        }
        txv_note(v, line);
    }
    if (next > 1) {
        char line[96];
        snprintf(line, sizeof line, T(TXT_PAYS_N_ADDRESSES), next);
        txv_note(v, line);
    }
    if (master && v->nsign && v->nsign < v->ninputs) {                        /* Payjoin, CoinJoin: the other party's inputs are in it and are left unsigned */
        char line[96];
        snprintf(line, sizeof line, T(TXT_N_OF_N_INPUTS_ARE_NOT_YOURS), v->ninputs - v->nsign, v->ninputs);
        txv_note(v, line);
    }
    if (tapscript) {                                                          /* a Taproot script path (multi_a ...): the other keys of the script are not known */
        v->warn |= TXW_UNREG_MULTISIG;
        txv_note(v, T(TXT_SIGNS_A_TAPROOT_SCRIPT_PATH_THE_OTHER));
    }
    if (p->version != 1 && p->version != 2) {
        char line[96];
        snprintf(line, sizeof line, T(TXT_TRANSACTION_VERSION_N_USUAL_1), (unsigned) p->version);
        txv_note(v, line);
    }
    return BTC_OK;
}
