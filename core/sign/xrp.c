#include "sign/xrp.h"
#include <stdio.h>
#include <string.h>
#include "coin/chains.h"
#include "ec/secp256k1.h"
#include "hash/ripemd160.h"
#include "hash/sha512.h"
#include "tr.h"

typedef struct {
    int      type, field;                  /* field id */
    size_t   off, hdr, len;                /* offset of the header, header length, length of the value (without a VL prefix) */
    size_t   vl;                           /* bytes of the VL prefix (0 for fixed size types) */
} xfield;

static int field_next(const uint8_t *b, size_t n, size_t *pos, xfield *f);

/* skip the fields up to and including the end marker of an object (0xE1) or an array (0xF1) */
static int skip_container(const uint8_t *b, size_t n, size_t *pp, uint8_t endm)
{
    size_t p = *pp;
    for (;;) {
        xfield g;
        size_t q = p;
        if (p >= n) return -1;
        if (b[p] == endm) { *pp = p + 1; return 0; }
        if (field_next(b, n, &q, &g) != 1) return -1;
        p = q;
    }
}

/* the next field at *pos; returns 1, 0 at the end, -1 for an error */
static int field_next(const uint8_t *b, size_t n, size_t *pos, xfield *f)
{
    size_t p = *pos;
    int type, field;

    if (p >= n) return 0;
    f->off = p;
    type = b[p] >> 4; field = b[p] & 15;
    p++;
    if (!type) { if (p >= n) return -1; type = b[p++]; }
    if (!field) { if (p >= n) return -1; field = b[p++]; }
    f->type = type; f->field = field;
    f->hdr = p - f->off;
    f->vl = 0;
    switch (type) {
    case 1: f->len = 2; break;
    case 2: f->len = 4; break;
    case 3: f->len = 8; break;
    case 4: f->len = 16; break;
    case 5: f->len = 32; break;
    case 16: f->len = 1; break;
    case 17: f->len = 20; break;
    case 6:
        if (p >= n) return -1;
        f->len = (b[p] & 0x80) ? 48 : 8;
        break;
    case 7: case 8: case 19: {                   /* a length prefix */
        size_t l;
        if (p >= n) return -1;
        if (b[p] <= 192) { l = b[p]; f->vl = 1; }
        else if (b[p] <= 240) { if (p + 1 >= n) return -1; l = 193 + ((size_t) (b[p] - 193) << 8) + b[p + 1]; f->vl = 2; }
        else return -1;
        f->len = l;
        break;
    }
    case 14: case 15: {                          /* an object or an array: the fields up to the end marker */
        size_t q = p;
        if (skip_container(b, n, &q, type == 14 ? 0xE1 : 0xF1)) return -1;
        f->len = q - p;
        break;
    }
    case 18: {                                   /* a path set: steps, 0xFF between the paths, 0x00 at the end */
        size_t q = p;
        for (;;) {
            if (q >= n) return -1;
            if (b[q] == 0x00) { q++; break; }
            if (b[q] == 0xFF) { q++; continue; }
            { size_t st = (size_t) (((b[q] & 0x01) ? 20 : 0) + ((b[q] & 0x10) ? 20 : 0) + ((b[q] & 0x20) ? 20 : 0)); if (n - q < 1 + st) return -1; q += 1 + st; }
        }
        f->len = q - p;
        break;
    }
    default: return -1;
    }
    if (n - p < f->vl + f->len) return -1;
    p += f->vl + f->len;
    *pos = p;
    return 1;
}

static const uint8_t *fval(const uint8_t *b, const xfield *f) { return b + f->off + f->hdr + f->vl; }

static uint64_t be(const uint8_t *p, int n) { uint64_t v = 0; for (int i = 0; i < n; i++) v = (v << 8) | p[i]; return v; }

static void account_text(char *out, size_t cap, const uint8_t id[20])
{
    if (xrp_address(out, cap, id) < 0) snprintf(out, cap, "?");
}

/* an Amount as text: drops as XRP, an issued currency as "value CUR (issuer)" */
static void amount_text(char *out, size_t cap, const uint8_t *a, size_t len, uint64_t *drops)
{
    if (len == 8) {
        uint64_t v = be(a, 8) & 0x3fffffffffffffffull;
        if (drops) *drops = v;
        txv_amount_u64(out, cap, v, 6, "XRP");
    } else {
        uint64_t w = be(a, 8), mant = w & 0x3fffffffffffffull;
        int exp = (int) ((w >> 54) & 0xff) - 97, neg = !(w & 0x4000000000000000ull);
        char digits[24], cur[4] = {0}, issuer[40], val[64];
        int nd = 0, k = 0;
        if (drops) *drops = 0;
        if (!mant) strcpy(val, "0");
        else {
            char rev[24];
            int nr = 0;
            while (mant) { rev[nr++] = (char) ('0' + mant % 10); mant /= 10; }
            for (int i = nr - 1; i >= 0; i--) digits[nd++] = rev[i];
            while (nd > 1 && digits[nd - 1] == '0') { nd--; exp++; }     /* trailing zeros move into the exponent */
            if (exp >= 0) { for (int i = 0; i < nd; i++) val[k++] = digits[i]; for (int i = 0; i < exp && k < 50; i++) val[k++] = '0'; }
            else if (-exp >= nd) { val[k++] = '0'; val[k++] = '.'; for (int i = 0; i < -exp - nd; i++) val[k++] = '0'; for (int i = 0; i < nd; i++) val[k++] = digits[i]; }
            else { for (int i = 0; i < nd + exp; i++) val[k++] = digits[i]; val[k++] = '.'; for (int i = nd + exp; i < nd; i++) val[k++] = digits[i]; }
            val[k] = 0;
        }
        memcpy(cur, a + 8 + 12, 3);
        for (int i = 0; i < 3; i++) if (cur[i] < 0x20 || cur[i] > 0x7e) cur[i] = '?';
        account_text(issuer, sizeof issuer, a + 28);
        snprintf(out, cap, T(TXT_N_ISSUER_N_2), neg ? "-" : "", val, cur, issuer);
    }
}

int xrp_summary(const uint8_t *tx, size_t len, tx_view *v)
{
    size_t pos = 0;
    xfield f;
    int r, ttype = -1, have_amount = 0, have_dest = 0;
    uint64_t fee = 0, seq = 0, tag = 0, flags = 0, drops = 0;
    int have_tag = 0;
    char line[96];

    txv_clear(v);
    while ((r = field_next(tx, len, &pos, &f)) == 1) {
        const uint8_t *val = fval(tx, &f);
        if (f.type == 1 && f.field == 2) ttype = (int) be(val, 2);
        else if (f.type == 2 && f.field == 4) seq = be(val, 4);
        else if (f.type == 2 && f.field == 14) { tag = be(val, 4); have_tag = 1; }
        else if (f.type == 2 && f.field == 2) flags = be(val, 4);
        else if (f.type == 6 && f.field == 8 && f.len == 8) fee = be(val, 8) & 0x3fffffffffffffffull;
        else if (f.type == 6 && f.field == 1) {
            amount_text(v->out[0].amount, sizeof v->out[0].amount, val, f.len, &drops);
            have_amount = 1;
        } else if (f.type == 8 && f.field == 3 && f.len == 20) { account_text(v->out[0].to, sizeof v->out[0].to, val); have_dest = 1; }
    }
    if (r < 0) return XRP_ERR_PARSE;
    if (ttype < 0) return XRP_ERR_PARSE;
    strcpy(v->title, T(TXT_XRP_TRANSACTION));
    v->nout = 1;
    if (ttype == 0 && have_amount && have_dest) {
        if (drops) strcpy(v->total, v->out[0].amount);
    } else {
        snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_TRANSACTION_TYPE_N), ttype);
        v->out[0].amount[0] = 0;
        v->warn |= TXW_BLIND;
        txv_note(v, T(TXT_ONLY_A_PAYMENT_CAN_BE_SHOWN));
    }
    txv_amount_u64(v->fee, sizeof v->fee, fee, 6, "XRP");
    snprintf(line, sizeof line, T(TXT_SEQUENCE_N), (unsigned long long) seq, flags ? T(TXT_FLAGS_SET) : "");
    txv_note(v, line);
    if (have_tag) { snprintf(line, sizeof line, T(TXT_DESTINATION_TAG_N), (unsigned long long) tag); txv_note(v, line); }
    return XRP_OK;
}

int xrp_sign(const uint8_t *tx, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap, size_t *outlen)
{
    size_t pos = 0, ins = (size_t) -1;
    xfield f;
    int r, have_pub = 0;
    uint8_t pub[33], h64[64], sig[64], der[80], prefix[4] = {0x53, 0x54, 0x58, 0x00};
    sha512_ctx c;
    int dl;

    if (secp256k1_pubkey_create(pub, priv)) return XRP_ERR_KEY;
    while ((r = field_next(tx, len, &pos, &f)) == 1) {
        if (f.type == 7 && f.field == 4) return XRP_ERR_PARSE;                  /* already signed */
        if (f.type == 7 && f.field == 3) {
            if (f.len != 33 || memcmp(fval(tx, &f), pub, 33)) return XRP_ERR_PUBKEY;
            have_pub = 1;
        }
        if (ins == (size_t) -1 && (f.type > 7 || (f.type == 7 && f.field > 4))) ins = f.off;
    }
    if (r < 0 || !have_pub) return XRP_ERR_PARSE;
    if (ins == (size_t) -1) ins = len;
    sha512_init(&c);
    sha512_update(&c, prefix, 4);
    sha512_update(&c, tx, len);
    sha512_final(&c, h64);
    if (secp256k1_ecdsa_sign(sig, NULL, priv, h64)) return XRP_ERR_KEY;       /* the first 32 bytes are the hash */
    dl = secp256k1_sig_to_der(der, sig);
    if (len + 2 + (size_t) dl > cap) return XRP_ERR_SPACE;
    memcpy(out, tx, ins);
    out[ins] = 0x74;
    out[ins + 1] = (uint8_t) dl;
    memcpy(out + ins + 2, der, (size_t) dl);
    memcpy(out + ins + 2 + dl, tx + ins, len - ins);
    *outlen = len + 2 + (size_t) dl;
    return XRP_OK;
}
