#include "sign/ada.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "coin/bech32.h"
#include "coin/cardano.h"
#include "ec/ed25519.h"
#include "hash/blake2b.h"
#include "tr.h"

/* "N inputs, N outputs" with the counts in the right form */
static void count_line(char *out, size_t cap, int nin, int nout)
{
    char a[24], b[24];
    snprintf(a, sizeof a, TN(nin, TXT_COUNT_INPUT_ONE, TXT_COUNT_INPUT_MANY), nin);
    snprintf(b, sizeof b, TN(nout, TXT_COUNT_OUTPUT_ONE, TXT_COUNT_OUTPUT_MANY), nout);
    snprintf(out, cap, "%s, %s", a, b);
}

/* ---- CBOR (definite lengths only) ---- */

typedef struct { const uint8_t *p, *end; int err; } cb;

enum { M_UINT = 0, M_NEG = 1, M_BYTES = 2, M_TEXT = 3, M_ARRAY = 4, M_MAP = 5, M_TAG = 6, M_SIMPLE = 7 };

/* the head of an item: major type and argument; *indef set for an indefinite length (not supported) */
static int head(cb *r, int *major, uint64_t *arg)
{
    uint8_t b;
    int ai;
    if (r->p >= r->end) { r->err = 1; return -1; }
    b = *r->p++;
    *major = b >> 5;
    ai = b & 31;
    if (ai < 24) { *arg = (uint64_t) ai; return 0; }
    if (ai > 27) { r->err = 1; return -1; }                             /* 28..31: reserved or indefinite */
    {
        int n = 1 << (ai - 24);
        uint64_t v = 0;
        if (r->end - r->p < n) { r->err = 1; return -1; }
        for (int i = 0; i < n; i++) v = (v << 8) | *r->p++;
        *arg = v;
    }
    return 0;
}

static void skip(cb *r, int depth);

static void skip(cb *r, int depth)
{
    int m;
    uint64_t a;
    if (depth > 8 || head(r, &m, &a)) { r->err = 1; return; }
    switch (m) {
    case M_BYTES: case M_TEXT:
        if ((uint64_t) (r->end - r->p) < a) { r->err = 1; return; }
        r->p += a;
        break;
    case M_ARRAY: for (uint64_t i = 0; i < a && !r->err; i++) skip(r, depth + 1); break;
    case M_MAP: for (uint64_t i = 0; i < 2 * a && !r->err; i++) skip(r, depth + 1); break;
    case M_TAG: skip(r, depth + 1); break;
    default: break;
    }
}

/* bytes item: pointer and length */
static const uint8_t *bytes_item(cb *r, size_t *n)
{
    int m;
    uint64_t a;
    const uint8_t *p;
    if (head(r, &m, &a) || m != M_BYTES || (uint64_t) (r->end - r->p) < a) { r->err = 1; return NULL; }
    p = r->p;
    r->p += a;
    *n = (size_t) a;
    return p;
}

static uint64_t uint_item(cb *r)
{
    int m;
    uint64_t a;
    if (head(r, &m, &a) || m != M_UINT) { r->err = 1; return 0; }
    return a;
}

/* ---- addresses ---- */

static void address_text(char *out, size_t cap, const uint8_t *a, size_t n)
{
    uint8_t d5[100];
    int hdr = n ? a[0] >> 4 : -1, net = n ? a[0] & 15 : 0, k;
    const char *hrp;
    size_t want = 0;

    out[0] = 0;
    if (hdr >= 0 && hdr <= 3) want = 57;
    else if (hdr == 6 || hdr == 7 || hdr == 14 || hdr == 15) want = 29;
    if (!want || n != want || (net != 0 && net != 1)) {                 /* Byron and the rest: the bytes in Base58 */
        if (n && base58_encode(a, n, out, cap) < 0) out[0] = 0;
        return;
    }
    hrp = hdr >= 14 ? (net ? "stake" : "stake_test") : (net ? "addr" : "addr_test");
    k = bech32_convert_bits(d5, sizeof d5, a, n, 8, 5, 1);
    if (k < 0 || bech32_encode(out, cap, hrp, d5, (size_t) k, 0) < 0) out[0] = 0;
}

/* an output's value: a coin, or [coin, multiasset]; returns the lovelace and counts the tokens */
static uint64_t value_item(cb *r, int *ntokens)
{
    int m;
    uint64_t a, coin = 0;
    const uint8_t *save = r->p;
    if (head(r, &m, &a)) return 0;
    if (m == M_UINT) return a;
    if (m != M_ARRAY || a != 2) { r->err = 1; return 0; }
    coin = uint_item(r);
    {
        uint64_t np;
        if (head(r, &m, &np) || m != M_MAP) { r->err = 1; return 0; }
        for (uint64_t i = 0; i < np && !r->err; i++) {
            uint64_t na;
            size_t bl;
            bytes_item(r, &bl);
            if (head(r, &m, &na) || m != M_MAP) { r->err = 1; return 0; }
            for (uint64_t k = 0; k < na && !r->err; k++) { bytes_item(r, &bl); skip(r, 0); (*ntokens)++; }
        }
    }
    (void) save;
    return coin;
}

int ada_summary(const uint8_t *body, size_t len, tx_view *v)
{
    cb r = {body, body + len, 0};
    int m;
    uint64_t nkeys, fee = 0, ttl = 0, spend = 0, wd = 0;
    int have_fee = 0, ncert = 0, nin = 0, mint = 0, nwd = 0, have_ttl = 0, ntok_total = 0;
    char line[96], amt[80], to[112];

    txv_clear(v);
    strcpy(v->title, T(TXT_CARDANO_TRANSACTION));
    if (head(&r, &m, &nkeys) || m != M_MAP || nkeys > 32) return ADA_ERR_PARSE;
    for (uint64_t i = 0; i < nkeys && !r.err; i++) {
        uint64_t key = uint_item(&r);
        if (r.err) break;
        if (key == 0) {                                                    /* inputs: an array, or a tagged set */
            uint64_t n;
            if (r.p < r.end && (*r.p >> 5) == M_TAG) { int mm; uint64_t t; head(&r, &mm, &t); }
            if (head(&r, &m, &n) || m != M_ARRAY) { r.err = 1; break; }
            nin = (int) n;
            for (uint64_t k = 0; k < n && !r.err; k++) skip(&r, 0);
        } else if (key == 1) {                                             /* outputs */
            uint64_t n;
            if (head(&r, &m, &n) || m != M_ARRAY) { r.err = 1; break; }
            for (uint64_t k = 0; k < n && !r.err; k++) {
                const uint8_t *addr = NULL;
                size_t al = 0;
                uint64_t coin = 0, fields;
                int ntok = 0;
                int mm;
                uint64_t a;
                if (head(&r, &mm, &a)) break;
                if (mm == M_ARRAY && a >= 2) {                             /* [address, value, ...] */
                    addr = bytes_item(&r, &al);
                    coin = value_item(&r, &ntok);
                    for (uint64_t x = 2; x < a && !r.err; x++) skip(&r, 0);
                } else if (mm == M_MAP) {                                  /* post-Alonzo: {0: address, 1: value, ...} */
                    fields = a;
                    for (uint64_t x = 0; x < fields && !r.err; x++) {
                        uint64_t fk = uint_item(&r);
                        if (fk == 0) addr = bytes_item(&r, &al);
                        else if (fk == 1) coin = value_item(&r, &ntok);
                        else { skip(&r, 0); v->warn |= TXW_DATA; }
                    }
                } else { r.err = 1; break; }
                if (r.err || !addr) { r.err = 1; break; }
                address_text(to, sizeof to, addr, al);
                txv_amount_u64(amt, sizeof amt, coin, 6, "ADA");
                if (ntok) { char t[32]; snprintf(t, sizeof t, TN(ntok, TXT_PLUS_TOKEN_ONE, TXT_PLUS_TOKEN_MANY), ntok); strncat(amt, t, sizeof amt - strlen(amt) - 1); v->warn |= TXW_DATA; }
                ntok_total += ntok;
                spend += coin;
                txv_add_out(v, to, amt);
            }
        } else if (key == 2) { fee = uint_item(&r); have_fee = 1; }
        else if (key == 3) { ttl = uint_item(&r); have_ttl = 1; }
        else if (key == 4) {                                               /* certificates */
            uint64_t n;
            const uint8_t *s = r.p;
            if (r.p < r.end && (*r.p >> 5) == M_TAG) { int mm; uint64_t t; head(&r, &mm, &t); }
            if (head(&r, &m, &n) || m != M_ARRAY) { r.err = 1; break; }
            ncert = (int) n;
            for (uint64_t k = 0; k < n && !r.err; k++) skip(&r, 0);
            (void) s;
        } else if (key == 5) {                                             /* withdrawals {reward address: lovelace} */
            uint64_t n;
            if (head(&r, &m, &n) || m != M_MAP) { r.err = 1; break; }
            nwd = (int) n;
            for (uint64_t k = 0; k < n && !r.err; k++) { size_t bl; bytes_item(&r, &bl); wd += uint_item(&r); }
        } else if (key == 9) { mint = 1; skip(&r, 0); }
        else skip(&r, 0);
    }
    if (r.err || r.p != r.end || !have_fee || !v->nout) return ADA_ERR_PARSE;
    txv_amount_u64(v->total, sizeof v->total, spend, 6, "ADA");
    txv_amount_u64(v->fee, sizeof v->fee, fee, 6, "ADA");
    count_line(line, sizeof line, nin, v->nout + v->nmore);
    txv_note(v, line);
    if (have_ttl) { snprintf(line, sizeof line, T(TXT_VALID_UNTIL_SLOT_N), (unsigned long long) ttl); txv_note(v, line); }
    if (nwd) { char w[44]; txv_amount_u64(w, sizeof w, wd, 6, "ADA"); snprintf(line, sizeof line, T(TXT_WITHDRAWS_N_OF_STAKING_REWARDS), w); txv_note(v, line); }
    if (ncert) { snprintf(line, sizeof line, TN(ncert, TXT_CERTIFICATE_ONE, TXT_CERTIFICATE_MANY), ncert); txv_note(v, line); v->warn |= TXW_DATA; }
    if (mint) { txv_note(v, T(TXT_MINTS_OR_BURNS_TOKENS)); v->warn |= TXW_DATA | TXW_BLIND; }
    (void) ntok_total;
    return ADA_OK;
}

int ada_sign(const uint8_t *body, size_t len, const uint8_t node[96], uint8_t vkey[32], uint8_t sig[64], uint8_t hash[32])
{
    if (ada_summary(body, len, &txv_shared)) return ADA_ERR_PARSE;
    blake2b(hash, 32, body, len);
    ed25519_scalarmult_base(vkey, node);                               /* kL as it is */
    ed25519_sign_scalar(sig, node, node + 32, vkey, hash, 32);
    return ADA_OK;
}

size_t ada_witness_set(uint8_t *out, int n, const uint8_t (*vkey)[32], const uint8_t (*sig)[64])
{
    size_t o = 0;
    out[o++] = 0xa1; out[o++] = 0x00; out[o++] = (uint8_t) (0x80 | n);
    for (int i = 0; i < n; i++) {
        out[o++] = 0x82;
        out[o++] = 0x58; out[o++] = 0x20; memcpy(out + o, vkey[i], 32); o += 32;
        out[o++] = 0x58; out[o++] = 0x40; memcpy(out + o, sig[i], 64); o += 64;
    }
    return o;
}
