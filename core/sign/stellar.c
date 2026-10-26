#include "sign/stellar.h"
#include <stdio.h>
#include <string.h>
#include "coin/chains.h"
#include "ec/ed25519.h"
#include "hash/sha256.h"
#include "tr.h"

typedef struct { const uint8_t *p, *end; int err; } xr;

static uint32_t x32(xr *r)
{
    uint32_t v;
    if (r->end - r->p < 4) { r->err = 1; return 0; }
    v = (uint32_t) r->p[0] << 24 | (uint32_t) r->p[1] << 16 | (uint32_t) r->p[2] << 8 | r->p[3];
    r->p += 4;
    return v;
}

static uint64_t x64(xr *r) { uint64_t hi = x32(r); return hi << 32 | x32(r); }

static const uint8_t *xop(xr *r, size_t n)                          /* opaque with its padding */
{
    const uint8_t *p = r->p;
    size_t pad = (4 - n % 4) % 4;
    if ((size_t) (r->end - r->p) < n + pad) { r->err = 1; return NULL; }
    r->p += n + pad;
    return p;
}

int stellar_address(char *out, size_t cap, const uint8_t pub[32])
{
    uint8_t b[35];
    uint16_t crc;
    int n;
    b[0] = 6 << 3;
    memcpy(b + 1, pub, 32);
    crc = crc16_xmodem(b, 33);
    b[33] = (uint8_t) crc;
    b[34] = (uint8_t) (crc >> 8);
    n = base32_encode(b, 35, out, cap);
    return n;
}

/* a MuxedAccount or an AccountID (muxed = 1 allows the 0x100 form) as G... text */
static void account(xr *r, int muxed, char *out, size_t cap)
{
    uint32_t t = x32(r);
    const uint8_t *k;
    out[0] = 0;
    if (muxed && t == 0x100) { x64(r); }                              /* the id of a muxed account is dropped here */
    else if (t != 0) { r->err = 1; return; }
    k = xop(r, 32);
    if (!k) return;
    if (stellar_address(out, cap, k) < 0) out[0] = 0;
}

/* an Asset as text: "XLM", or "CODE (issuer G...)" */
static void asset(xr *r, char *out, size_t cap)
{
    uint32_t t = x32(r);
    if (t == 0) { snprintf(out, cap, "XLM"); return; }
    if (t == 1 || t == 2) {
        size_t n = t == 1 ? 4 : 12;
        const uint8_t *code = xop(r, n);
        char issuer[60], c[13];
        size_t i;
        if (!code) return;
        for (i = 0; i < n && code[i]; i++) c[i] = (code[i] >= 0x20 && code[i] < 0x7f) ? (char) code[i] : '?';
        c[i] = 0;
        account(r, 0, issuer, sizeof issuer);
        snprintf(out, cap, T(TXT_N_ISSUER_N), c, issuer);
        return;
    }
    r->err = 1;
}

static void amount_text(char *out, size_t cap, int64_t stroops, const char *asset_text)
{
    char a[44];
    txv_amount_u64(a, sizeof a, (uint64_t) stroops, 7, NULL);
    snprintf(out, cap, "%.43s %.80s", a, asset_text);
}

int stellar_summary(const uint8_t *tx, size_t len, tx_view *v)
{
    xr r = {tx, tx + len, 0};
    char src[60], line[160], to[60], as[100], amt[128];
    uint32_t fee, cond, memo, nops;
    uint64_t seq, total = 0;
    int only_xlm = 1;

    txv_clear(v);
    strcpy(v->title, T(TXT_STELLAR_TRANSACTION));
    account(&r, 1, src, sizeof src);
    fee = x32(&r);
    seq = x64(&r);
    cond = x32(&r);
    if (cond == 1) { x64(&r); x64(&r); }
    else if (cond == 2) {                                              /* PRECOND_V2 */
        if (x32(&r)) { x64(&r); x64(&r); }
        if (x32(&r)) { x32(&r); x32(&r); }
        if (x32(&r)) x64(&r);
        x64(&r); x32(&r);
        { uint32_t ns = x32(&r); if (ns > 2) r.err = 1; for (uint32_t i = 0; i < ns && !r.err; i++) { uint32_t kt = x32(&r); if (kt != 0) { r.err = 1; break; } xop(&r, 32); } }
    } else if (cond != 0) r.err = 1;
    memo = x32(&r);
    switch (memo) {
    case 0: break;
    case 1: {
        uint32_t n = x32(&r);
        const uint8_t *t;
        if (n > 28) { r.err = 1; break; }
        t = xop(&r, n);
        if (t) {
            char m[32];
            for (uint32_t i = 0; i < n; i++) m[i] = (t[i] >= 0x20 && t[i] < 0x7f) ? (char) t[i] : '?';
            m[n] = 0;
            snprintf(line, sizeof line, T(TXT_MEMO_N), m);
            txv_note(v, line);
        }
        break;
    }
    case 2: snprintf(line, sizeof line, T(TXT_MEMO_ID_N), (unsigned long long) x64(&r)); txv_note(v, line); break;
    case 3: case 4: xop(&r, 32); txv_note(v, T(TXT_MEMO_A_32_BYTE_HASH)); break;
    default: r.err = 1;
    }
    nops = x32(&r);
    if (r.err || nops == 0 || nops > 100) return XLM_ERR_PARSE;
    for (uint32_t i = 0; i < nops && !r.err; i++) {
        uint32_t type;
        if (x32(&r)) {                                                  /* an operation source account */
            account(&r, 1, to, sizeof to);
            snprintf(line, sizeof line, T(TXT_OP_N_SOURCE_ACCOUNT_N), (unsigned) i + 1, to);
            txv_note(v, line);
        }
        type = x32(&r);
        if (type == 0) {                                                /* CREATE_ACCOUNT */
            account(&r, 0, to, sizeof to);
            { int64_t b = (int64_t) x64(&r); amount_text(amt, sizeof amt, b, "XLM"); total += (uint64_t) b; }
            if (r.err) break;
            snprintf(as, sizeof as, T(TXT_CREATE_ACCOUNT_N), to);
            txv_add_out(v, as, amt);
        } else if (type == 1) {                                         /* PAYMENT */
            account(&r, 1, to, sizeof to);
            asset(&r, as, sizeof as);
            { int64_t b = (int64_t) x64(&r); amount_text(amt, sizeof amt, b, as); if (strcmp(as, "XLM")) only_xlm = 0; else total += (uint64_t) b; }
            if (r.err) break;
            txv_add_out(v, to, amt);
        } else if (type == 6) {                                         /* CHANGE_TRUST */
            uint32_t t = x32(&r);
            if (t == 1 || t == 2) {
                size_t n = t == 1 ? 4 : 12;
                const uint8_t *code = xop(&r, n);
                char issuer[60], c[13];
                size_t k;
                if (!code) break;
                for (k = 0; k < n && code[k]; k++) c[k] = (code[k] >= 0x20 && code[k] < 0x7f) ? (char) code[k] : '?';
                c[k] = 0;
                account(&r, 0, issuer, sizeof issuer);
                x64(&r);
                if (r.err) break;
                snprintf(as, sizeof as, T(TXT_TRUST_N), c);
                snprintf(amt, sizeof amt, T(TXT_ISSUER_N), issuer);
                txv_add_out(v, as, amt);
            } else { v->warn |= TXW_BLIND; snprintf(as, sizeof as, T(TXT_OPERATION_TYPE_6_LIQUIDITY)); txv_add_out(v, as, ""); break; }
        } else if (type == 8) {                                         /* ACCOUNT_MERGE */
            account(&r, 1, to, sizeof to);
            if (r.err) break;
            snprintf(as, sizeof as, T(TXT_MERGE_ALL_FUNDS_INTO_N), to);
            txv_add_out(v, as, "everything");
        } else {
            snprintf(as, sizeof as, T(TXT_OPERATION_TYPE_N), (unsigned) type);
            txv_add_out(v, as, T(TXT_CANNOT_BE_SHOWN));
            v->warn |= TXW_BLIND | TXW_DATA;
            if (i + 1 < nops) txv_note(v, T(TXT_OPERATIONS_AFTER_THIS_ONE_ARE));
            break;
        }
    }
    if (r.err) return XLM_ERR_PARSE;
    snprintf(line, sizeof line, T(TXT_SOURCE_N_SEQUENCE_N), src, (unsigned long long) seq);
    txv_note(v, line);
    txv_amount_u64(v->fee, sizeof v->fee, (uint64_t) fee, 7, "XLM");
    if (total && only_xlm) txv_amount_u64(v->total, sizeof v->total, total, 7, "XLM");
    return XLM_OK;
}

int stellar_sign(const uint8_t *tx, size_t len, const char *passphrase, const uint8_t seed[32], uint8_t sig[64], uint8_t hint[4])
{
    static const uint8_t TYPE_TX[4] = {0, 0, 0, 2};
    sha256_ctx c;
    uint8_t net[32], h[32], pub[32];
    if (stellar_summary(tx, len, &txv_shared)) return XLM_ERR_PARSE;

    sha256((const uint8_t *) passphrase, strlen(passphrase), net);
    sha256_init(&c);
    sha256_update(&c, net, 32);
    sha256_update(&c, TYPE_TX, 4);
    sha256_update(&c, tx, len);
    sha256_final(&c, h);
    ed25519_pubkey_from_seed(pub, seed);
    ed25519_sign(sig, seed, h, 32);
    memcpy(hint, pub + 28, 4);
    return XLM_OK;
}
