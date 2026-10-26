#include "sign/ton.h"
#include <stdio.h>
#include <string.h>
#include "b64.h"
#include "coin/chains.h"
#include "ec/ed25519.h"
#include "hash/sha256.h"
#include "tr.h"

#define MAXCELLS 48

typedef struct {
    const uint8_t *data;
    int            bits, nrefs;
    uint8_t        refs[4];
    uint16_t       depth;
    uint8_t        hash[32];
} cell;

typedef struct {
    cell c[MAXCELLS];
    int  n, root;
} boc;

static int rdn(const uint8_t **p, const uint8_t *end, int n, uint32_t *v)
{
    uint32_t x = 0;
    if (n < 1 || n > 4 || end - *p < n) return -1;
    for (int i = 0; i < n; i++) x = (x << 8) | *(*p)++;
    *v = x;
    return 0;
}

static int boc_parse(boc *b, const uint8_t *p, size_t len)
{
    const uint8_t *end = p + len, *q;
    uint32_t cells, roots, absent, tot, root;
    int size, offb, has_idx;

    memset(b, 0, sizeof *b);
    if (len < 12 || p[0] != 0xb5 || p[1] != 0xee || p[2] != 0x9c || p[3] != 0x72) return TON_SIGN_ERR_PARSE;
    has_idx = p[4] & 0x80;
    size = p[4] & 7;
    offb = p[5];
    q = p + 6;
    if (rdn(&q, end, size, &cells) || rdn(&q, end, size, &roots) || rdn(&q, end, size, &absent) || rdn(&q, end, offb, &tot)) return TON_SIGN_ERR_PARSE;
    if (cells < 1 || cells > MAXCELLS || roots != 1 || absent != 0) return TON_SIGN_ERR_PARSE;
    if (rdn(&q, end, size, &root) || root >= cells) return TON_SIGN_ERR_PARSE;
    b->n = (int) cells;
    b->root = (int) root;
    if (has_idx) { if ((size_t) (end - q) < (size_t) cells * (size_t) offb) return TON_SIGN_ERR_PARSE; q += (size_t) cells * (size_t) offb; }
    if ((size_t) (end - q) < tot) return TON_SIGN_ERR_PARSE;
    end = q + tot;                                                     /* the cells; a CRC may follow, it is not checked here */
    for (uint32_t i = 0; i < cells; i++) {
        cell *c = &b->c[i];
        uint8_t d1, d2;
        size_t nb;
        if (end - q < 2) return TON_SIGN_ERR_PARSE;
        d1 = q[0]; d2 = q[1];
        q += 2;
        if (d1 & 0xf8) return TON_SIGN_ERR_PARSE;                      /* exotic cells and levels: not here */
        c->nrefs = d1 & 7;
        if (c->nrefs > 4) return TON_SIGN_ERR_PARSE;
        nb = (size_t) (d2 + 1) >> 1;
        if ((size_t) (end - q) < nb) return TON_SIGN_ERR_PARSE;
        c->data = q;
        c->bits = (int) nb * 8;
        if (d2 & 1) {                                                  /* the last byte carries the completion tag */
            uint8_t last = q[nb - 1];
            int tz = 0;
            if (!last) return TON_SIGN_ERR_PARSE;
            while (!((last >> tz) & 1)) tz++;
            c->bits -= tz + 1;
        }
        q += nb;
        for (int r = 0; r < c->nrefs; r++) {
            uint32_t idx;
            if (rdn(&q, end, size, &idx) || idx <= i || idx >= cells) return TON_SIGN_ERR_PARSE;     /* children come after their parents */
            c->refs[r] = (uint8_t) idx;
        }
    }
    for (int i = b->n - 1; i >= 0; i--) {                              /* hashes, from the leaves up */
        cell *c = &b->c[i];
        sha256_ctx h;
        uint8_t d[2], dd[2];
        size_t nb = (size_t) (c->bits + 7) / 8;
        uint16_t depth = 0;
        d[0] = (uint8_t) c->nrefs;
        d[1] = (uint8_t) (c->bits / 8 + (c->bits + 7) / 8);
        sha256_init(&h);
        sha256_update(&h, d, 2);
        sha256_update(&h, c->data, nb);
        for (int r = 0; r < c->nrefs; r++) {
            uint16_t rd_ = b->c[c->refs[r]].depth;
            dd[0] = (uint8_t) (rd_ >> 8); dd[1] = (uint8_t) rd_;
            sha256_update(&h, dd, 2);
            if (rd_ + 1u > depth) depth = (uint16_t) (rd_ + 1);
        }
        for (int r = 0; r < c->nrefs; r++) sha256_update(&h, b->c[c->refs[r]].hash, 32);
        sha256_final(&h, c->hash);
        c->depth = depth;
    }
    return TON_SIGN_OK;
}

/* ---- a bit reader on a cell ---- */

typedef struct { const cell *c; int pos; int err; } br;

static uint64_t bits(br *r, int n)
{
    uint64_t v = 0;
    if (n > 64 || r->pos + n > r->c->bits) { r->err = 1; return 0; }
    for (int i = 0; i < n; i++) {
        int p = r->pos + i;
        v = (v << 1) | (uint64_t) ((r->c->data[p >> 3] >> (7 - (p & 7))) & 1);
    }
    r->pos += n;
    return v;
}

/* Grams: 4 bit length and that many bytes; the value is limited to 64 bits here */
static uint64_t coins(br *r)
{
    int n = (int) bits(r, 4);
    uint64_t v = 0;
    if (n > 8) { r->err = 1; return 0; }
    for (int i = 0; i < n; i++) v = (v << 8) | bits(r, 8);
    return v;
}

static void raw_to_user(char *out, size_t cap, int wc, const uint8_t hash[32], int bounceable)
{
    uint8_t raw[36];
    uint16_t crc;
    raw[0] = bounceable ? 0x11 : 0x51;
    raw[1] = (uint8_t) wc;
    memcpy(raw + 2, hash, 32);
    crc = crc16_xmodem(raw, 34);
    raw[34] = (uint8_t) (crc >> 8);
    raw[35] = (uint8_t) crc;
    if (cap < 49 || b64_encode(raw, 36, out, cap) < 0) { out[0] = 0; return; }
    for (char *c = out; *c; c++) { if (*c == '+') *c = '-'; else if (*c == '/') *c = '_'; }
}

/* MsgAddressInt addr_std: returns 0 and the workchain and hash, -1 otherwise */
static int addr_std(br *r, int *wc, uint8_t hash[32])
{
    if (bits(r, 2) != 2) return -1;
    if (bits(r, 1)) return -1;                                          /* anycast */
    *wc = (int8_t) bits(r, 8);
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t) bits(r, 8);
    return r->err ? -1 : 0;
}

/* an internal message cell; returns 0 if it was shown */
static int show_message(const boc *b, int idx, tx_view *v, uint64_t *sum)
{
    br r = {&b->c[idx], 0, 0};
    int bounce, wc;
    uint8_t dest[32];
    uint64_t value;
    char to[60], amt[64];
    const cell *body = NULL;
    br br_;
    int has_init;

    if (bits(&r, 1) != 0) return -1;                                    /* int_msg_info$0 */
    bits(&r, 1);                                                        /* ihr_disabled */
    bounce = (int) bits(&r, 1);
    bits(&r, 1);                                                        /* bounced */
    if (bits(&r, 2) != 0) return -1;                                    /* src: addr_none */
    if (addr_std(&r, &wc, dest)) return -1;
    value = coins(&r);
    if (bits(&r, 1)) return -1;                                         /* extra currencies */
    coins(&r); coins(&r);                                               /* ihr_fee, fwd_fee */
    bits(&r, 64); bits(&r, 32);                                         /* created_lt, created_at */
    has_init = (int) bits(&r, 1);
    if (has_init) return -1;                                            /* a deployment: not shown here */
    if (bits(&r, 1)) {                                                  /* the body in a reference */
        if (b->c[idx].nrefs < 1) return -1;
        body = &b->c[b->c[idx].refs[0]];
        br_.c = body; br_.pos = 0; br_.err = 0;
    } else { br_.c = &b->c[idx]; br_.pos = r.pos; br_.err = 0; }
    if (r.err) return -1;
    raw_to_user(to, sizeof to, wc, dest, bounce);
    txv_amount_u64(amt, sizeof amt, value, 9, "TON");
    *sum += value;
    {
        int left = br_.c->bits - br_.pos;
        if (left >= 32) {
            uint64_t op = bits(&br_, 32);
            if (op == 0 && left > 32 && ((left - 32) & 7) == 0) {              /* a text comment */
                char text[64];
                int n = (left - 32) / 8;
                char line[96];
                if (n > 60) n = 60;
                for (int i = 0; i < n; i++) { uint8_t ch = (uint8_t) bits(&br_, 8); text[i] = (ch >= 0x20 && ch < 0x7f) ? (char) ch : '?'; }
                text[n] = 0;
                snprintf(line, sizeof line, T(TXT_COMMENT_N), text);
                txv_note(v, line);
            } else if (op == 0x0f8a7ea5u) {                                  /* jetton transfer */
                uint64_t qid = bits(&br_, 64), amount;
                int wc2;
                uint8_t to2[32];
                char to2s[60];
                (void) qid;
                amount = coins(&br_);
                if (!addr_std(&br_, &wc2, to2) && !br_.err) {
                    raw_to_user(to2s, sizeof to2s, wc2, to2, 1);
                    snprintf(to, sizeof to, "%s", to2s);
                    txv_amount_u64(amt, sizeof amt, amount, 0, NULL);
                    strcat(amt, T(TXT_JETTON_UNITS));
                    txv_note(v, T(TXT_JETTON_TRANSFER_THE_TON_OF_THE));
                    v->warn |= TXW_DATA;
                    *sum -= value;
                } else { v->warn |= TXW_DATA | TXW_BLIND; txv_note(v, T(TXT_JETTON_TRANSFER_THE_DETAILS)); }
            } else {
                char line[96];
                snprintf(line, sizeof line, T(TXT_MESSAGE_BODY_OPERATION_N), (unsigned) op);
                txv_note(v, line);
                v->warn |= TXW_DATA;
            }
        }
    }
    txv_add_out(v, to, amt);
    return 0;
}

int ton_summary(const uint8_t *data, size_t len, tx_view *v)
{
    static boc b;
    const cell *root;
    br r;
    uint64_t first, sum = 0;
    int e = boc_parse(&b, data, len), shown = 0;
    char line[96];

    txv_clear(v);
    if (e) return e;
    root = &b.c[b.root];
    strcpy(v->title, T(TXT_TON_WALLET_MESSAGE));
    r.c = root; r.pos = 0; r.err = 0;
    first = bits(&r, 32);
    if (first == 0x7369676eu && root->bits >= 129) {                       /* wallet v5R1 */
        uint64_t wid = bits(&r, 32), until = bits(&r, 32), seq = bits(&r, 32);
        (void) wid;
        snprintf(line, sizeof line, T(TXT_WALLET_V5R1_SEQNO_N_VALID), (unsigned long long) seq, (unsigned long long) until);
        txv_note(v, line);
        if (bits(&r, 1) && root->nrefs >= 1) {                              /* the list of actions, newest first */
            int idx = root->refs[0], msgs[8], nm = 0;
            while (nm < 8) {
                const cell *c = &b.c[idx];
                br a = {c, 0, 0};
                if (c->nrefs < 1) break;
                if (c->nrefs >= 2 && c->bits >= 40 && bits(&a, 32) == 0x0ec3c86du) { bits(&a, 8); msgs[nm++] = c->refs[1]; idx = c->refs[0]; }
                else break;
            }
            for (int i = nm - 1; i >= 0; i--) if (!show_message(&b, msgs[i], v, &sum)) shown++;
        }
    } else if (root->bits == 104 + 8 * root->nrefs && root->nrefs <= 4) {  /* wallet v4R2 */
        uint64_t until = bits(&r, 32), seq = bits(&r, 32), op = bits(&r, 8);
        if (op == 0) {
            snprintf(line, sizeof line, T(TXT_WALLET_V4R2_SEQNO_N_VALID), (unsigned long long) seq, (unsigned long long) until);
            txv_note(v, line);
            for (int i = 0; i < root->nrefs; i++) {
                bits(&r, 8);                                                /* mode */
                if (!show_message(&b, root->refs[i], v, &sum)) shown++;
            }
        }
    }
    if (!shown) {
        txv_add_out(v, T(TXT_UNKNOWN_MESSAGE_FORMAT), "");
        txv_note(v, T(TXT_ONLY_THE_HASH_OF_THE_MESSAGE));
        v->warn |= TXW_BLIND;
    }
    if (sum) txv_amount_u64(v->total, sizeof v->total, sum, 9, "TON");
    return TON_SIGN_OK;
}

int ton_sign(const uint8_t *data, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t hash[32])
{
    static boc b;
    int e = boc_parse(&b, data, len);
    if (e) return e;
    memcpy(hash, b.c[b.root].hash, 32);
    ed25519_sign(sig, seed, hash, 32);
    return TON_SIGN_OK;
}
