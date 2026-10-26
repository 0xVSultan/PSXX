#include "sign/cosmos.h"
#include <stdio.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "hash/sha256.h"
#include "sign/pb.h"
#include "util.h"
#include "tr.h"

typedef struct {
    const uint8_t *body; size_t bodylen;
    const uint8_t *auth; size_t authlen;
    const uint8_t *chain; size_t chainlen;
    uint64_t account;
} signdoc;

static int doc_parse(signdoc *s, const uint8_t *b, size_t n)
{
    pb_reader r;
    uint32_t f; int wt, e;
    uint64_t v; const uint8_t *d; size_t dl;

    memset(s, 0, sizeof *s);
    pb_init(&r, b, n);
    while ((e = pb_next(&r, &f, &wt, &v, &d, &dl)) == 1) {
        if (f == 1 && wt == 2) { s->body = d; s->bodylen = dl; }
        else if (f == 2 && wt == 2) { s->auth = d; s->authlen = dl; }
        else if (f == 3 && wt == 2) { s->chain = d; s->chainlen = dl; }
        else if (f == 4 && wt == 0) s->account = v;
    }
    if (e < 0 || !s->body || !s->auth) return COS_ERR_PARSE;
    return COS_OK;
}

static void cpy(char *out, size_t cap, const uint8_t *d, size_t n)
{
    if (n > cap - 1) n = cap - 1;
    for (size_t i = 0; i < n; i++) out[i] = (d[i] >= 0x20 && d[i] < 0x7f) ? (char) d[i] : '?';
    out[n] = 0;
}

/* a Coin message as text: "1.5 ATOM" for the micro denominations we know, else "<amount> <denom>" */
static void coin_text(char *out, size_t cap, const uint8_t *b, size_t n)
{
    pb_reader r;
    uint32_t f; int wt;
    uint64_t v; const uint8_t *d, *denom = NULL, *amt = NULL; size_t dl, denoml = 0, amtl = 0;

    pb_init(&r, b, n);
    while (pb_next(&r, &f, &wt, &v, &d, &dl) == 1) {
        if (f == 1 && wt == 2) { denom = d; denoml = dl; }
        else if (f == 2 && wt == 2) { amt = d; amtl = dl; }
    }
    if (!denom || !amt) { snprintf(out, cap, "?"); return; }
    {
        char den[80], num[40];
        cpy(den, sizeof den, denom, denoml);
        cpy(num, sizeof num, amt, amtl);
        if (den[0] == 'u' && den[1] && amtl <= 19) {                  /* micro units of the named coin */
            uint64_t x = 0;
            int digits = 1;
            for (size_t i = 0; i < amtl; i++) { if (amt[i] < '0' || amt[i] > '9') digits = 0; else x = x * 10 + (uint64_t) (amt[i] - '0'); }
            if (digits && amtl) {
                char sym[24];
                for (size_t i = 0; den[1 + i] && i < sizeof sym - 1; i++) sym[i] = (char) ((den[1 + i] >= 'a' && den[1 + i] <= 'z') ? den[1 + i] - 32 : den[1 + i]), sym[i + 1] = 0;
                txv_amount_u64(out, cap, x, 6, sym);
                return;
            }
        }
        snprintf(out, cap, "%.30s %.76s", num, den);
    }
}

int cosmos_summary(const uint8_t *signdoc_b, size_t len, tx_view *v)
{
    signdoc s;
    pb_reader r, a;
    uint32_t f, f2; int wt, wt2, e;
    uint64_t x, x2; const uint8_t *d, *d2; size_t dl, dl2;
    char line[96], chain[40];
    int e0 = doc_parse(&s, signdoc_b, len);

    txv_clear(v);
    if (e0) return e0;
    cpy(chain, sizeof chain, s.chain ? s.chain : (const uint8_t *) "", s.chainlen);
    snprintf(v->title, sizeof v->title, T(TXT_COSMOS_TRANSACTION));
    snprintf(line, sizeof line, T(TXT_CHAIN_N_ACCOUNT_NUMBER_N), chain, (unsigned long long) s.account);
    txv_note(v, line);

    pb_init(&r, s.body, s.bodylen);
    while ((e = pb_next(&r, &f, &wt, &x, &d, &dl)) == 1) {
        if (f == 1 && wt == 2) {                                        /* a message: Any { type_url, value } */
            const uint8_t *url = NULL, *val = NULL;
            size_t urll = 0, vall = 0;
            pb_init(&a, d, dl);
            while ((e = pb_next(&a, &f2, &wt2, &x2, &d2, &dl2)) == 1) {
                if (f2 == 1 && wt2 == 2) { url = d2; urll = dl2; }
                else if (f2 == 2 && wt2 == 2) { val = d2; vall = dl2; }
            }
            if (e < 0) return COS_ERR_PARSE;
            if (url && urll == 28 && !memcmp(url, "/cosmos.bank.v1beta1.MsgSend", 28) && val) {
                pb_reader m;
                uint32_t f3; int wt3; uint64_t x3; const uint8_t *d3, *to = NULL; size_t dl3, tol = 0;
                char amount[128] = "";
                pb_init(&m, val, vall);
                while (pb_next(&m, &f3, &wt3, &x3, &d3, &dl3) == 1) {
                    if (f3 == 2 && wt3 == 2) { to = d3; tol = dl3; }
                    else if (f3 == 3 && wt3 == 2) {
                        char c[112];
                        coin_text(c, sizeof c, d3, dl3);
                        if (amount[0] && strlen(amount) + strlen(c) + 4 < sizeof amount) strcat(amount, " + ");
                        if (strlen(amount) + strlen(c) < sizeof amount) strcat(amount, c);
                    }
                }
                if (v->nout < TXV_OUTS) {
                    txv_out *o = &v->out[v->nout++];
                    cpy(o->to, sizeof o->to, to ? to : (const uint8_t *) "", tol);
                    snprintf(o->amount, sizeof o->amount, "%s", amount);
                } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
            } else {
                if (v->nout < TXV_OUTS) {
                    txv_out *o = &v->out[v->nout++];
                    cpy(o->to, sizeof o->to, url ? url : (const uint8_t *) "", urll);
                    o->amount[0] = 0;
                } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
                v->warn |= TXW_BLIND | TXW_DATA;
            }
        } else if (f == 2 && wt == 2) {
            char memo[80];
            cpy(memo, sizeof memo, d, dl);
            if (dl) { snprintf(line, sizeof line, T(TXT_MEMO_N), memo); txv_note(v, line); }
        }
    }
    if (e < 0) return COS_ERR_PARSE;
    if (!v->nout) return COS_ERR_PARSE;

    pb_init(&r, s.auth, s.authlen);                                     /* AuthInfo.fee */
    while ((e = pb_next(&r, &f, &wt, &x, &d, &dl)) == 1) {
        if (f == 2 && wt == 2) {
            pb_init(&a, d, dl);
            while (pb_next(&a, &f2, &wt2, &x2, &d2, &dl2) == 1) {
                if (f2 == 1 && wt2 == 2) {
                    char c[112];
                    coin_text(c, sizeof c, d2, dl2);
                    if (v->fee[0] && strlen(v->fee) + strlen(c) + 4 < sizeof v->fee) strcat(v->fee, " + ");
                    if (strlen(v->fee) + strlen(c) < sizeof v->fee) strcat(v->fee, c);
                } else if (f2 == 2 && wt2 == 0) {
                    snprintf(line, sizeof line, T(TXT_GAS_LIMIT_N), (unsigned long long) x2);
                    txv_note(v, line);
                }
            }
        }
    }
    if (e < 0) return COS_ERR_PARSE;
    return COS_OK;
}

int cosmos_sign(const uint8_t *signdoc_b, size_t len, const uint8_t priv[32], uint8_t sig64[64], uint8_t *txraw, size_t cap, size_t *txlen)
{
    signdoc s;
    uint8_t h[32];
    int e = doc_parse(&s, signdoc_b, len);

    if (e) return e;
    sha256(signdoc_b, len, h);
    if (secp256k1_ecdsa_sign(sig64, NULL, priv, h)) return COS_ERR_KEY;
    if (txraw) {                                                        /* TxRaw { body_bytes = 1, auth_info_bytes = 2, signatures = 3 } */
        size_t o = 0;
        uint8_t tmp[10];
        size_t l1 = pb_put_varint(tmp, s.bodylen);
        size_t need = 1 + l1 + s.bodylen;
        l1 = pb_put_varint(tmp, s.authlen);
        need += 1 + l1 + s.authlen + 2 + 64;
        if (need > cap) return COS_ERR_SPACE;
        txraw[o++] = 0x0a; o += pb_put_varint(txraw + o, s.bodylen); memcpy(txraw + o, s.body, s.bodylen); o += s.bodylen;
        txraw[o++] = 0x12; o += pb_put_varint(txraw + o, s.authlen); memcpy(txraw + o, s.auth, s.authlen); o += s.authlen;
        txraw[o++] = 0x1a; txraw[o++] = 64; memcpy(txraw + o, sig64, 64); o += 64;
        *txlen = o;
    }
    return COS_OK;
}
