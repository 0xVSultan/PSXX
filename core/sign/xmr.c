#include "sign/xmr.h"
#include <stdio.h>
#include <string.h>
#include "coin/xmr.h"
#include "ec/ed25519.h"
#include "ec/ed25519_ge.h"
#include "hash/keccak.h"
#include "util.h"
#include "prof.h"
#include "tr.h"

/* the second generator H = 8 * decode(keccak256(G)) */
static const uint8_t H_BYTES[32] = {0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
                                    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};
/* 1/8 modulo the group order */
static const uint8_t INV8[32] = {0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06};
static const uint8_t ZERO32[32];

typedef struct { const uint8_t *addr; uint8_t flags; uint64_t amount; const uint8_t *r, *pid; uint32_t acct, idx; } xout;
typedef struct { int n, l; const uint8_t *ring, *Rin, *enc; uint32_t oidx, acct, idx; } xin;

typedef struct {
    uint8_t type;
    int nin, nout;
    uint64_t fee;
    const uint8_t *prefix, *proof;
    size_t prefix_len, proof_len;
    xout out[XMR_MAXOUT];
    xin in[XMR_MAXIN];
    const uint8_t *kimg[XMR_MAXIN], *okey[XMR_MAXOUT];       /* from the prefix */
    uint8_t has_tag[XMR_MAXOUT], vtag[XMR_MAXOUT];
    const uint8_t *tx_pub, *add_pub, *nonce;
    int nadd;
    size_t nonce_len;
    uint64_t unlock;
} xreq;

typedef struct {
    uint8_t x[XMR_MAXIN][32], inmask[XMR_MAXIN][32];
    uint64_t inamt[XMR_MAXIN];
    uint8_t outC[XMR_MAXOUT][32], outenc[XMR_MAXOUT][8], outmask[XMR_MAXOUT][32], own[XMR_MAXOUT];
    uint64_t in_sum, out_sum;
    int plain_pid;
} xver;

static uint16_t rd16(const uint8_t *p) { return (uint16_t) (p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }

static int rd_varint(const uint8_t **pp, const uint8_t *end, uint64_t *v)
{
    const uint8_t *p = *pp;
    uint64_t x = 0;
    for (int sh = 0; sh < 63; sh += 7) {
        if (p >= end) return -1;
        x |= (uint64_t) (*p & 0x7f) << sh;
        if (!(*p++ & 0x80)) { *v = x; *pp = p; return 0; }
    }
    return -1;
}

static size_t put_varint(uint8_t *o, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) { o[n++] = (uint8_t) (v | 0x80); v >>= 7; }
    o[n++] = (uint8_t) v;
    return n;
}

/* ---- the request ---- */

static int prefix_parse(xreq *r)
{
    const uint8_t *p = r->prefix, *end = p + r->prefix_len;
    uint64_t v, cnt;

    if (rd_varint(&p, end, &v) || v != 2) return XMR_ERR_UNSUPPORTED;         /* transaction version 2 (RingCT) */
    if (rd_varint(&p, end, &r->unlock)) return XMR_ERR_PARSE;
    if (rd_varint(&p, end, &cnt) || cnt != (uint64_t) r->nin) return XMR_ERR_PARSE;
    for (int i = 0; i < r->nin; i++) {
        uint64_t n;
        if (p >= end || *p++ != 0x02) return XMR_ERR_PARSE;                    /* txin_to_key */
        if (rd_varint(&p, end, &v) || v != 0) return XMR_ERR_PARSE;            /* amount 0 */
        if (rd_varint(&p, end, &n) || n != (uint64_t) r->in[i].n) return XMR_ERR_PARSE;
        for (uint64_t k = 0; k < n; k++) if (rd_varint(&p, end, &v)) return XMR_ERR_PARSE;
        if (end - p < 32) return XMR_ERR_PARSE;
        r->kimg[i] = p;
        p += 32;
    }
    if (rd_varint(&p, end, &cnt) || cnt != (uint64_t) r->nout) return XMR_ERR_PARSE;
    for (int j = 0; j < r->nout; j++) {
        uint8_t tag;
        if (rd_varint(&p, end, &v) || v != 0) return XMR_ERR_PARSE;
        if (p >= end) return XMR_ERR_PARSE;
        tag = *p++;
        if ((tag != 0x02 && tag != 0x03) || end - p < 32 + (tag == 0x03)) return XMR_ERR_PARSE;
        r->okey[j] = p;
        p += 32;
        if (tag == 0x03) { r->has_tag[j] = 1; r->vtag[j] = *p++; }
    }
    if (rd_varint(&p, end, &v) || (uint64_t) (end - p) != v) return XMR_ERR_PARSE;     /* the extra runs to the end */
    end = p + v;
    while (p < end) {
        uint8_t tag = *p++;
        if (tag == 0x00) continue;                                              /* padding */
        if (tag == 0x01) {
            if (end - p < 32 || r->tx_pub) return XMR_ERR_UNSUPPORTED;
            r->tx_pub = p;
            p += 32;
        } else if (tag == 0x02) {
            if (rd_varint(&p, end, &v) || (uint64_t) (end - p) < v || r->nonce) return XMR_ERR_UNSUPPORTED;
            r->nonce = p;
            r->nonce_len = (size_t) v;
            p += v;
        } else if (tag == 0x04) {
            if (rd_varint(&p, end, &cnt) || cnt > XMR_MAXOUT || (uint64_t) (end - p) < 32 * cnt || r->add_pub) return XMR_ERR_UNSUPPORTED;
            r->add_pub = p;
            r->nadd = (int) cnt;
            p += 32 * cnt;
        } else return XMR_ERR_UNSUPPORTED;
    }
    return XMR_OK;
}

static int req_parse(xreq *r, const uint8_t *b, size_t n)
{
    const uint8_t *p = b + 16, *end = b + n;

    memset(r, 0, sizeof *r);
    if (n < 24 || memcmp(b, "XMRQ", 4) || b[4] != 1) return XMR_ERR_PARSE;
    r->type = b[5];
    if (r->type != 5 && r->type != 6) return XMR_ERR_UNSUPPORTED;
    r->nin = b[6];
    r->nout = b[7];
    if (r->nin < 1 || r->nin > XMR_MAXIN || r->nout < 1 || r->nout > XMR_MAXOUT) return XMR_ERR_PARSE;
    r->fee = rd64(b + 8);
    if (end - p < 2) return XMR_ERR_PARSE;
    r->prefix_len = rd16(p); p += 2;
    if ((size_t) (end - p) < r->prefix_len) return XMR_ERR_PARSE;
    r->prefix = p; p += r->prefix_len;
    if (end - p < 2) return XMR_ERR_PARSE;
    r->proof_len = rd16(p); p += 2;
    if ((size_t) (end - p) < r->proof_len || r->proof_len % 32) return XMR_ERR_PARSE;
    r->proof = p; p += r->proof_len;
    for (int j = 0; j < r->nout; j++) {
        xout *o = &r->out[j];
        if (end - p < 65 + 1 + 8 + 32) return XMR_ERR_PARSE;
        o->addr = p; p += 65;
        o->flags = *p++;
        o->amount = rd64(p); p += 8;
        o->r = p; p += 32;
        if (o->flags & ~7u) return XMR_ERR_UNSUPPORTED;
        if (o->flags & 2) { if (end - p < 8) return XMR_ERR_PARSE; o->pid = p; p += 8; }
        if (o->flags & 4) { if (end - p < 8) return XMR_ERR_PARSE; o->acct = rd32(p); o->idx = rd32(p + 4); p += 8; }
    }
    for (int i = 0; i < r->nin; i++) {
        xin *in = &r->in[i];
        if (end - p < 2) return XMR_ERR_PARSE;
        in->n = p[0]; in->l = p[1]; p += 2;
        if (in->n < 2 || in->n > XMR_MAXRING || in->l >= in->n || (size_t) (end - p) < 64u * (size_t) in->n + 32 + 4 + 8 + 8) return XMR_ERR_PARSE;
        in->ring = p; p += 64 * in->n;
        in->Rin = p; p += 32;
        in->oidx = rd32(p); in->acct = rd32(p + 4); in->idx = rd32(p + 8); p += 12;
        in->enc = p; p += 8;
    }
    if (p != end) return XMR_ERR_PARSE;
    return prefix_parse(r);
}

/* ---- the checks ---- */

static void hs(uint8_t out[32], const uint8_t *buf, size_t n)
{
    keccak256(buf, n, out);
    ed25519_sc_reduce32(out);
}

/* the scalar of an output: Hs(derivation || varint(index)) */
static void deriv_scalar(uint8_t s[32], const uint8_t der[32], uint32_t idx)
{
    uint8_t buf[40];
    memcpy(buf, der, 32);
    hs(s, buf, 32 + put_varint(buf + 32, idx));
}

static void mask_of(uint8_t mask[32], const uint8_t s[32])
{
    uint8_t buf[15 + 32];
    memcpy(buf, "commitment_mask", 15);
    memcpy(buf + 15, s, 32);
    hs(mask, buf, sizeof buf);
}

/* the 8 bytes that hide the amount: keccak("amount" || s) */
static void amount_pad(uint8_t pad[8], const uint8_t s[32])
{
    uint8_t buf[6 + 32], h[32];
    memcpy(buf, "amount", 6);
    memcpy(buf + 6, s, 32);
    keccak256(buf, sizeof buf, h);
    memcpy(pad, h, 8);
}

static void u64_scalar(uint8_t o[32], uint64_t v)
{
    memset(o, 0, 32);
    for (int i = 0; i < 8; i++) o[i] = (uint8_t) (v >> (8 * i));
}

/* C = mask * G + amount * H */
static void commit(ed_ge *c, const uint8_t mask[32], uint64_t amount, const ed_ge *H)
{
    ed_ge a, b;
    uint8_t am[32];
    ed_ge_mul_base(&a, mask);
    u64_scalar(am, amount);
    ed_ge_mul2_vt(&b, am, H, ZERO32, H);
    ed_ge_add(c, &a, &b);
}

static int is_subaddress(uint8_t net) { return net == 0x2a || net == 0x3f || net == 0x24; }
static uint8_t std_net(uint8_t net) { return net == 0x13 ? 0x12 : net == 0x36 ? 0x35 : net == 0x19 ? 0x18 : net; }

static int verify(const xreq *r, const xmr_keys *k, xver *v)
{
    ed_ge H, T, U;
    uint8_t der[32], s[32], x[32], t[32], m[32], buf[48];
    int pid_seen = 0;

    if (ed_ge_decode(&H, H_BYTES)) return XMR_ERR_PARSE;
    memset(v, 0, sizeof *v);

    for (int i = 0; i < r->nin; i++) {
        const xin *in = &r->in[i];
        const uint8_t *Pl = in->ring + 64 * in->l, *Cl = Pl + 32;
        uint8_t pad[8];
        uint64_t amount = 0;
        ed_ge R;

        if (ed_ge_decode(&R, in->Rin)) return XMR_ERR_PARSE;
        ed_ge_mul(&T, &R, k->view_sec);
        ed_ge_mul8(&T, &T);
        ed_ge_encode(der, &T);
        deriv_scalar(s, der, in->oidx);
        ed25519_sc_add(x, s, k->spend_sec);
        if (in->acct || in->idx) {                                                /* received at a subaddress */
            memcpy(buf, "SubAddr\0", 8);
            memcpy(buf + 8, k->view_sec, 32);
            for (int b = 0; b < 4; b++) { buf[40 + b] = (uint8_t) (in->acct >> (8 * b)); buf[44 + b] = (uint8_t) (in->idx >> (8 * b)); }
            hs(m, buf, 48);
            ed25519_sc_add(x, x, m);
        }
        ed_ge_mul_base(&T, x);
        ed_ge_encode(t, &T);
        if (memcmp(t, Pl, 32)) return XMR_ERR_KEY;
        keccak256(Pl, 32, t);
        ed_hash_to_point(&U, t);
        ed_ge_mul(&T, &U, x);
        ed_ge_encode(t, &T);
        if (memcmp(t, r->kimg[i], 32)) return XMR_ERR_KEY;
        mask_of(m, s);
        amount_pad(pad, s);
        for (int b = 0; b < 8; b++) amount |= (uint64_t) (in->enc[b] ^ pad[b]) << (8 * b);
        commit(&T, m, amount, &H);
        ed_ge_encode(t, &T);
        if (memcmp(t, Cl, 32)) return XMR_ERR_AMOUNT;
        PROF("verify: input checked");
        memcpy(v->x[i], x, 32);
        memcpy(v->inmask[i], m, 32);
        v->inamt[i] = amount;
        if (v->in_sum + amount < v->in_sum) return XMR_ERR_BALANCE;
        v->in_sum += amount;
    }

    for (int j = 0; j < r->nout; j++) {
        const xout *o = &r->out[j];
        const uint8_t *B = o->addr + 1, *A = o->addr + 33;
        ed_ge Ap, Bp, P;
        uint8_t pad[8], pub[32];
        const uint8_t *want;

        if (ed_ge_decode(&Ap, A) || ed_ge_decode(&Bp, B)) return XMR_ERR_PARSE;
        ed_ge_mul(&T, &Ap, o->r);
        ed_ge_mul8(&T, &T);
        ed_ge_encode(der, &T);
        deriv_scalar(s, der, (uint32_t) j);
        ed_ge_mul_base(&P, s);
        ed_ge_add(&P, &P, &Bp);
        ed_ge_encode(t, &P);
        if (memcmp(t, r->okey[j], 32)) return XMR_ERR_OUTPUT;
        if (r->has_tag[j]) {                                                      /* the view tag */
            uint8_t vb[8 + 32 + 5], h[32];
            memcpy(vb, "view_tag", 8);
            memcpy(vb + 8, der, 32);
            keccak256(vb, 40 + put_varint(vb + 40, (uint64_t) j), h);
            if (h[0] != r->vtag[j]) return XMR_ERR_OUTPUT;
        }
        mask_of(v->outmask[j], s);
        commit(&T, v->outmask[j], o->amount, &H);
        ed_ge_encode(v->outC[j], &T);
        amount_pad(pad, s);
        for (int b = 0; b < 8; b++) v->outenc[j][b] = (uint8_t) (o->amount >> (8 * b)) ^ pad[b];
        PROF("verify: output checked");
        if (v->out_sum + o->amount < v->out_sum) return XMR_ERR_BALANCE;
        v->out_sum += o->amount;
        /* the transaction public key: r * G, or r * B for a subaddress */
        if (is_subaddress(o->addr[0])) ed_ge_mul(&T, &Bp, o->r);
        else { ed_ge G; uint8_t one[32] = {1}; ed_ge_mul_base(&G, one); ed_ge_mul(&T, &G, o->r); }
        ed_ge_encode(pub, &T);
        if (o->flags & 1) want = (r->add_pub && j < r->nadd) ? r->add_pub + 32 * j : NULL;
        else want = r->tx_pub;
        if (!want || memcmp(want, pub, 32)) return XMR_ERR_OUTPUT;
        if (o->flags & 2) {                                                       /* encrypted payment id */
            uint8_t pb[33], h[32];
            memcpy(pb, der, 32);
            pb[32] = 0x8d;
            keccak256(pb, 33, h);
            if (pid_seen++ || !r->nonce || r->nonce_len != 9 || r->nonce[0] != 1) return XMR_ERR_OUTPUT;
            for (int b = 0; b < 8; b++) if ((uint8_t) (o->pid[b] ^ h[b]) != r->nonce[1 + b]) return XMR_ERR_OUTPUT;
        }
        /* is it back to us? the main address, or the (sub)address the request names */
        if (!memcmp(B, k->spend_pub, 32) && !memcmp(A, k->view_pub, 32)) v->own[j] = 1;
        else if (o->flags & 4) {
            uint8_t D[32], C[32];
            memcpy(buf, "SubAddr\0", 8);
            memcpy(buf + 8, k->view_sec, 32);
            for (int b = 0; b < 4; b++) { buf[40 + b] = (uint8_t) (o->acct >> (8 * b)); buf[44 + b] = (uint8_t) (o->idx >> (8 * b)); }
            hs(m, buf, 48);
            if (!ed25519_subaddress_keys(D, C, k->spend_pub, k->view_sec, m) && !memcmp(D, B, 32) && !memcmp(C, A, 32)) v->own[j] = 1;
        }
    }
    if (r->nonce && !pid_seen) {
        if (r->nonce_len == 33 && r->nonce[0] == 0) v->plain_pid = 1;               /* an unencrypted payment id */
        else if (!(r->nonce_len == 9 && r->nonce[0] == 1)) return XMR_ERR_UNSUPPORTED;     /* anything but the dummy encrypted one */
    }
    if (v->in_sum != v->out_sum + r->fee || v->out_sum + r->fee < v->out_sum) return XMR_ERR_BALANCE;
    secure_zero(s, sizeof s); secure_zero(x, sizeof x); secure_zero(m, sizeof m);
    return XMR_OK;
}

static void pid_text(char *out, size_t cap, const uint8_t pid[8])
{
    static const char HX[] = "0123456789abcdef";
    size_t k = 0;
    for (int i = 0; i < 8 && k + 3 < cap; i++) { out[k++] = HX[pid[i] >> 4]; out[k++] = HX[pid[i] & 15]; }
    out[k] = 0;
}

static void keys_from_seed(xmr_keys *k, const uint8_t seed[32]) { xmr_keys_from_seed(k, seed); }

/* What the summary found out (keys of the inputs, masks, commitments) is kept for the signature of the same request, so that the console
 * does not check everything twice. Tied to the request and the seed by a hash; wiped after the signature and by xmr_tx_forget(). */
static struct { int valid; uint8_t tag[32]; xver v; } cache;

static void cache_tag(uint8_t tag[32], const uint8_t *req, size_t len, const uint8_t seed[32])
{
    uint8_t b[64];
    keccak256(req, len, b);
    memcpy(b + 32, seed, 32);
    keccak256(b, 64, tag);
    secure_zero(b, sizeof b);
}

void xmr_tx_forget(void)
{
    secure_zero(&cache, sizeof cache);
}

int xmr_tx_summary(const uint8_t *req, size_t len, const uint8_t spend_seed[32], tx_view *vw)
{
    xreq r;
    xver v;
    xmr_keys k;
    uint64_t sent = 0;
    char line[96];
    int e;

    txv_clear(vw);
    e = req_parse(&r, req, len);
    if (e) return e;
    keys_from_seed(&k, spend_seed);
    e = verify(&r, &k, &v);
    secure_zero(&k, sizeof k);
    xmr_tx_forget();
    if (e) { secure_zero(&v, sizeof v); return e; }
    cache.valid = 1;
    cache_tag(cache.tag, req, len, spend_seed);
    cache.v = v;
    snprintf(vw->title, sizeof vw->title, T(TXT_MONERO_TRANSACTION));
    vw->ninputs = r.nin;
    vw->nsign = r.nin;
    for (int j = 0; j < r.nout; j++) {
        if (vw->nout < TXV_OUTS) {
            txv_out *o = &vw->out[vw->nout++];
            xmr_address(o->to, sizeof o->to, std_net(r.out[j].addr[0]), r.out[j].addr + 1, r.out[j].addr + 33);
            txv_amount_u64(o->amount, sizeof o->amount, r.out[j].amount, 12, "XMR");
            o->mine = v.own[j];
        } else { vw->nmore++; vw->warn |= TXW_TRUNCATED; }
        if (!v.own[j]) sent += r.out[j].amount;
        if (r.out[j].pid) { char hx[20]; pid_text(hx, sizeof hx, r.out[j].pid); snprintf(line, sizeof line, T(TXT_PAYMENT_ID_OUTPUT_N), j + 1, hx); txv_note(vw, line); }
    }
    txv_amount_u64(vw->total, sizeof vw->total, sent, 12, "XMR");
    txv_amount_u64(vw->fee, sizeof vw->fee, r.fee, 12, "XMR");
    if (sent && r.fee * 10 > sent) vw->warn |= TXW_HIGH_FEE;
    {
        char a[40], b[24];
        snprintf(a, sizeof a, TN(r.nin, TXT_COUNT_INPUT_RING_ONE, TXT_COUNT_INPUT_RING_MANY), r.nin, r.in[0].n);
        snprintf(b, sizeof b, TN(r.nout, TXT_COUNT_OUTPUT_ONE, TXT_COUNT_OUTPUT_MANY), r.nout);
        snprintf(line, sizeof line, "%s, %s", a, b);
    }
    txv_note(vw, line);
    if (v.plain_pid) txv_note(vw, T(TXT_UNENCRYPTED_PAYMENT_ID_IN_THE));
    if (r.unlock) txv_note(vw, T(TXT_THE_OUTPUTS_ARE_TIME_LOCKED));
    secure_zero(&v, sizeof v);
    return XMR_OK;
}

/* ---- CLSAG ---- */

static uint8_t hbuf[(2 * XMR_MAXRING + 5) * 32];

static void pad_label(uint8_t d[32], const char *s)
{
    memset(d, 0, 32);
    memcpy(d, s, strlen(s));
}

/* The CLSAG signature of one input (rctSigs.cpp CLSAG_Gen). ring: n pairs (one time key, commitment); x the secret key of ring[l],
 * z the difference of the input commitment mask and the pseudo output mask. base seeds the deterministic nonces. */
static int clsag_sign(uint8_t *s_out, uint8_t c1[32], uint8_t Dst[32], const uint8_t Iimg[32], const uint8_t *ring, int n, int l,
                      const uint8_t msg[32], const uint8_t coff[32], const uint8_t x[32], const uint8_t z[32],
                      const uint8_t base[32], int idx)
{
    ed_ge off, Ip, Dp, Zp, Hl, Pt, Ct, W, Hk, Lp, Rp, tmp;
    uint8_t mu_p[32], mu_c[32], zi[32], a[32], c[32], cp[32], t[32], t2[32], sb[32 + 12];
    uint8_t *Pb = hbuf + 32, *Cb = hbuf + 32 + 32 * n, *tail = hbuf + 32 + 64 * n;
    int e = XMR_OK;

    if (ed_ge_decode(&off, coff) || ed_ge_decode(&Ip, Iimg)) return XMR_ERR_PARSE;
    for (int k = 0; k < n; k++) { memcpy(Pb + 32 * k, ring + 64 * k, 32); memcpy(Cb + 32 * k, ring + 64 * k + 32, 32); }
    keccak256(Pb + 32 * l, 32, t);
    ed_hash_to_point(&Hl, t);
    ed25519_sc_mul(zi, z, INV8);
    ed_ge_mul(&tmp, &Hl, zi);                                   /* D / 8 */
    ed_ge_encode(Dst, &tmp);
    ed_ge_mul8(&Dp, &tmp);                                      /* D */
    memcpy(tail, Iimg, 32); memcpy(tail + 32, Dst, 32); memcpy(tail + 64, coff, 32);
    pad_label(hbuf, "CLSAG_agg_0"); hs(mu_p, hbuf, 32 + 64 * (size_t) n + 96);
    pad_label(hbuf, "CLSAG_agg_1"); hs(mu_c, hbuf, 32 + 64 * (size_t) n + 96);
    PROF("clsag: key image part, hashes");
    ed_ge_mul2_vt(&Zp, mu_p, &Ip, mu_c, &Dp);                   /* the part of R that does not depend on the ring member */

    memcpy(sb, base, 32);                                       /* nonce a = Hs(base || "a" || idx) */
    sb[32] = 'a'; sb[33] = (uint8_t) idx;
    hs(a, sb, 34);
    pad_label(hbuf, "CLSAG_round");
    memcpy(tail, coff, 32); memcpy(tail + 32, msg, 32);
    ed_ge_mul_base(&Lp, a);
    ed_ge_mul(&Rp, &Hl, a);
    ed_ge_encode(tail + 64, &Lp);
    ed_ge_encode(tail + 96, &Rp);
    hs(c, hbuf, 32 + 64 * (size_t) n + 128);
    {
        int i = (l + 1) % n;
        if (i == 0) memcpy(c1, c, 32);
        while (i != l) {
            const uint8_t *Pi = ring + 64 * i, *Ci = Pi + 32;
            uint8_t sk[32];
            if (ed_ge_decode(&Pt, Pi) || ed_ge_decode(&Ct, Ci)) { e = XMR_ERR_PARSE; goto done; }
            memcpy(sb, base, 32);                               /* decoy s_i = Hs(base || "s" || idx || i) */
            sb[32] = 's'; sb[33] = (uint8_t) idx; sb[34] = (uint8_t) i;
            hs(sk, sb, 35);
            memcpy(s_out + 32 * i, sk, 32);
            ed_ge_sub(&Ct, &Ct, &off);
            ed_ge_mul2_vt(&W, mu_p, &Pt, mu_c, &Ct);           /* mu_P P + mu_C (C - C_offset) */
            ed_ge_mul_base(&Lp, sk);
            ed_ge_mul2_vt(&tmp, c, &W, ZERO32, &W);
            ed_ge_add(&Lp, &Lp, &tmp);
            keccak256(Pi, 32, t);
            ed_hash_to_point(&Hk, t);
            ed_ge_mul2_vt(&Rp, sk, &Hk, c, &Zp);
            ed_ge_encode(tail + 64, &Lp);
            ed_ge_encode(tail + 96, &Rp);
            hs(c, hbuf, 32 + 64 * (size_t) n + 128);
            PROF("clsag: ring member");
            i = (i + 1) % n;
            if (i == 0) memcpy(c1, c, 32);
        }
    }
    /* s_l = a - c (mu_P x + mu_C z) */
    ed25519_sc_mul(t, mu_p, x);
    ed25519_sc_mul(t2, mu_c, z);
    ed25519_sc_add(t, t, t2);
    ed25519_sc_mul(cp, c, t);
    ed25519_sc_sub(s_out + 32 * l, a, cp);
done:
    secure_zero(a, sizeof a); secure_zero(t, sizeof t); secure_zero(t2, sizeof t2); secure_zero(cp, sizeof cp); secure_zero(zi, sizeof zi);
    return e;
}

int xmr_tx_sign(const uint8_t *req, size_t len, const uint8_t spend_seed[32], uint8_t *out, size_t cap, size_t *outlen)
{
    xreq r;
    xver v;
    xmr_keys k;
    uint8_t base[64], msg[32], pre[96], seed[32], mask_sum[32], pmask[XMR_MAXIN][32];
    uint8_t *o = out;
    size_t need = 3, rbn;
    ed_ge H, T;
    int e;

    e = req_parse(&r, req, len);
    if (e) return e;
    for (int i = 0; i < r.nin; i++) need += 1 + 32 * 4 + 32 * (size_t) r.in[i].n;
    if (need > cap) return XMR_ERR_SPACE;
    keys_from_seed(&k, spend_seed);
    {
        uint8_t tag[32];
        cache_tag(tag, req, len, spend_seed);
        if (cache.valid && !memcmp(tag, cache.tag, 32)) { v = cache.v; e = XMR_OK; PROF("sign: checks of the summary reused"); }
        else e = verify(&r, &k, &v);
    }
    xmr_tx_forget();
    if (e) goto fail;
    if (ed_ge_decode(&H, H_BYTES)) { e = XMR_ERR_PARSE; goto fail; }

    /* the message: keccak(prefix hash || hash of the base || hash of the proof) */
    keccak256(r.prefix, r.prefix_len, pre);
    {
        static uint8_t bb[1 + 10 + XMR_MAXOUT * 40];
        rbn = 0;
        bb[rbn++] = r.type;
        rbn += put_varint(bb + rbn, r.fee);
        for (int j = 0; j < r.nout; j++) { memcpy(bb + rbn, v.outenc[j], 8); rbn += 8; }
        for (int j = 0; j < r.nout; j++) { memcpy(bb + rbn, v.outC[j], 32); rbn += 32; }
        keccak256(bb, rbn, pre + 32);
    }
    keccak256(r.proof, r.proof_len, pre + 64);
    keccak256(pre, 96, msg);
    memcpy(base, "PSXX Monero", 11);
    memcpy(base + 11, k.spend_sec, 32);
    keccak256(base, 43, seed);                                  /* the secret part: never leaves this function */
    memcpy(base, seed, 32);
    memcpy(base + 32, msg, 32);
    keccak256(base, 64, seed);

    /* pseudo output masks: random but the last, which makes the sum of the pseudo outputs the sum of the outputs + fee*H */
    memset(mask_sum, 0, 32);
    for (int j = 0; j < r.nout; j++) ed25519_sc_add(mask_sum, mask_sum, v.outmask[j]);
    {
        uint8_t acc[32] = {0}, sb[34];
        for (int i = 0; i < r.nin - 1; i++) {
            memcpy(sb, seed, 32); sb[32] = 'p'; sb[33] = (uint8_t) i;
            hs(pmask[i], sb, 34);
            ed25519_sc_add(acc, acc, pmask[i]);
        }
        ed25519_sc_sub(pmask[r.nin - 1], mask_sum, acc);
    }
    memcpy(o, "XMRS", 4); o[4] = 1; o[5] = (uint8_t) r.nin; o += 6;
    for (int i = 0; i < r.nin; i++) {
        uint8_t coff[32], z[32], Dst[32], c1[32];
        uint8_t *s_out = o + 1 + 32 * 4;
        const xin *in = &r.in[i];

        commit(&T, pmask[i], v.inamt[i], &H);
        ed_ge_encode(coff, &T);
        ed25519_sc_sub(z, v.inmask[i], pmask[i]);
        e = clsag_sign(s_out, c1, Dst, r.kimg[i], in->ring, in->n, in->l, msg, coff, v.x[i], z, seed, i);
        if (e) goto fail;
        o[0] = (uint8_t) in->n;
        memcpy(o + 1, coff, 32);
        memcpy(o + 33, r.kimg[i], 32);
        memcpy(o + 65, Dst, 32);
        memcpy(o + 97, c1, 32);
        o = s_out + 32 * in->n;
        secure_zero(z, sizeof z);
    }
    *outlen = (size_t) (o - out);
fail:
    secure_zero(&k, sizeof k); secure_zero(&v, sizeof v); secure_zero(seed, sizeof seed); secure_zero(base, sizeof base);
    secure_zero(pmask, sizeof pmask); secure_zero(mask_sum, sizeof mask_sum);
    return e;
}
