#include "sign/zec.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "coin/path.h"
#include "ec/secp256k1.h"
#include "hash/blake2b.h"
#include "hash/ripemd160.h"
#include "coin/orchard.h"
#include "prof.h"
#include "sign/orchard_out.h"
#include "sign/redpallas.h"
#include "util.h"
#include "tr.h"

#define MAXIN 32
#define MAXOUT 32
#define MAXACT 8
#define MAXSIG 8
#define ACTION_LEN 820

typedef struct {
    int      ver;                          /* 4 or 5 */
    uint32_t header, group, branch, locktime, expiry;
    int      nin, nout;
    const uint8_t *vin;                    /* 41 bytes per input: txid, index, empty script, sequence */
    const uint8_t *vout, *vout_end;
    const uint8_t *tail; size_t taillen;   /* what follows the outputs, copied unchanged */
    uint64_t amount[MAXIN];
    const uint8_t *spk[MAXIN]; size_t spklen[MAXIN];
    const uint8_t *path[MAXIN]; int depth[MAXIN];
    int nact;                              /* Orchard actions (ZIP-225 without the proof and the signatures) */
    const uint8_t *act, *anchor;
    uint8_t oflags;
    int64_t vbal;                          /* the Orchard value balance: positive = value leaves the shielded pool */
    int nsig;                              /* the actions we are asked to authorize */
    uint8_t sidx[MAXSIG];
    const uint8_t *alpha[MAXSIG];
    uint8_t snote[MAXSIG];                 /* 0: no note data, 1: a note of the external address, 2: of the internal address */
    const uint8_t *sdata[MAXSIG];          /* d (11) | v (8) | rseed (32) | rho (32) */
} zreq;

static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }
static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t) (v >> (8 * i)); }
static void wr64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t) (v >> (8 * i)); }

static size_t cs_put(uint8_t *o, uint64_t v)
{
    if (v < 0xFD) { o[0] = (uint8_t) v; return 1; }
    o[0] = 0xFD; o[1] = (uint8_t) v; o[2] = (uint8_t) (v >> 8);
    return 3;
}

static int req_parse(zreq *r, const uint8_t *b, size_t n)
{
    const uint8_t *p = b + 12, *end = b + n, *t, *tend;
    uint32_t txlen;
    uint64_t c;

    memset(r, 0, sizeof *r);
    if (n < 12 || memcmp(b, "ZTXR", 4)) return ZEC_ERR_PARSE;
    r->branch = rd32(b + 4);
    txlen = rd32(b + 8);
    if ((size_t) (end - p) < txlen || txlen < 16) return ZEC_ERR_PARSE;
    t = p;
    tend = p + txlen;
    p = tend;
    r->header = rd32(t);
    r->group = rd32(t + 4);
    t += 8;
    if (r->header == 0x80000005u && r->group == 0x26A7270Au) {
        if (tend - t < 12) return ZEC_ERR_PARSE;
        r->ver = 5;
        if (rd32(t) != r->branch) return ZEC_ERR_PARSE;
        r->locktime = rd32(t + 4);
        r->expiry = rd32(t + 8);
        t += 12;
    } else if (r->header == 0x80000004u && r->group == 0x892F2085u) r->ver = 4;
    else return ZEC_ERR_UNSUPPORTED;
    if (rd_cs(&t, tend, &c) || c > MAXIN) return ZEC_ERR_PARSE;
    r->nin = (int) c;
    r->vin = t;
    for (int i = 0; i < r->nin; i++) {
        if (tend - t < 41 || t[36] != 0) return ZEC_ERR_PARSE;
        t += 41;
    }
    if (rd_cs(&t, tend, &c) || c > MAXOUT) return ZEC_ERR_PARSE;
    r->nout = (int) c;
    r->vout = t;
    for (int i = 0; i < r->nout; i++) {
        uint64_t sl;
        if (tend - t < 9) return ZEC_ERR_PARSE;
        t += 8;
        if (rd_cs(&t, tend, &sl) || (uint64_t) (tend - t) < sl) return ZEC_ERR_PARSE;
        t += sl;
    }
    r->vout_end = t;
    r->tail = t;
    r->taillen = (size_t) (tend - t);
    if (r->ver == 5) {                                                   /* no Sapling spends or outputs; Orchard actions or none */
        if (r->taillen >= 3 && !t[0] && !t[1] && !t[2] && r->taillen == 3) { /* nothing shielded */ }
        else {
            const uint8_t *q = t + 2;
            uint64_t na;
            if (r->taillen < 3 || t[0] || t[1]) return ZEC_ERR_UNSUPPORTED;     /* Sapling parts are not supported */
            if (rd_cs(&q, tend, &na) || na == 0 || na > MAXACT) return ZEC_ERR_UNSUPPORTED;
            if ((size_t) (tend - q) != (size_t) na * ACTION_LEN + 1 + 8 + 32) return ZEC_ERR_PARSE;
            r->nact = (int) na;
            r->act = q;
            q += (size_t) na * ACTION_LEN;
            r->oflags = q[0];
            r->vbal = (int64_t) rd64(q + 1);
            r->anchor = q + 9;
        }
    } else {
        if (r->taillen != 19) return ZEC_ERR_UNSUPPORTED;
        r->locktime = rd32(t);
        r->expiry = rd32(t + 4);
        if (rd64(t + 8) || t[16] || t[17] || t[18]) return ZEC_ERR_UNSUPPORTED;     /* value balance, spends, outputs, joinsplits */
    }
    for (int i = 0; i < r->nin; i++) {                                   /* the input data */
        uint64_t sl;
        if (end - p < 8) return ZEC_ERR_PARSE;
        r->amount[i] = rd64(p);
        p += 8;
        if (rd_cs(&p, end, &sl) || sl > 64 || (uint64_t) (end - p) < sl + 1) return ZEC_ERR_PARSE;
        r->spk[i] = p; r->spklen[i] = (size_t) sl;
        p += sl;
        r->depth[i] = *p++;
        if (r->depth[i] > PATH_MAX_DEPTH || (end - p) < 4 * r->depth[i]) return ZEC_ERR_PARSE;
        r->path[i] = p;
        p += 4 * r->depth[i];
    }
    if (r->nact) {                                                       /* the actions to authorize */
        if (end - p < 1) return ZEC_ERR_PARSE;
        r->nsig = *p++;
        if (r->nsig > MAXSIG) return ZEC_ERR_PARSE;
        for (int i = 0; i < r->nsig; i++) {
            if (end - p < 34) return ZEC_ERR_PARSE;
            r->sidx[i] = p[0];
            if (r->sidx[i] >= r->nact) return ZEC_ERR_PARSE;
            r->alpha[i] = p + 1;
            r->snote[i] = p[33];
            p += 34;
            if (r->snote[i] > 2) return ZEC_ERR_PARSE;
            if (r->snote[i]) {
                if (end - p < 83) return ZEC_ERR_PARSE;
                r->sdata[i] = p;
                p += 83;
            }
        }
    }
    if (p != end) return ZEC_ERR_PARSE;
    if (r->nin == 0 && r->nact == 0) return ZEC_ERR_PARSE;
    return ZEC_OK;
}

/* ---- hashing ---- */

static void bl(blake2b_ctx *c, const char *person)
{
    blake2b_init(c, 32, NULL, 0, NULL, (const uint8_t *) person);
}

static void branch_person(uint8_t person[16], const char *twelve, uint32_t branch)
{
    memcpy(person, twelve, 12);
    wr32(person + 12, branch);
}

static void hash_prevouts(const zreq *r, const char *person, uint8_t out[32])
{
    blake2b_ctx c;
    bl(&c, person);
    for (int i = 0; i < r->nin; i++) blake2b_update(&c, r->vin + 41 * i, 36);
    blake2b_final(&c, out);
}

static void hash_sequence(const zreq *r, const char *person, uint8_t out[32])
{
    blake2b_ctx c;
    bl(&c, person);
    for (int i = 0; i < r->nin; i++) blake2b_update(&c, r->vin + 41 * i + 37, 4);
    blake2b_final(&c, out);
}

static void hash_outputs(const zreq *r, const char *person, uint8_t out[32])
{
    blake2b_ctx c;
    bl(&c, person);
    blake2b_update(&c, r->vout, (size_t) (r->vout_end - r->vout));
    blake2b_final(&c, out);
}

/* ZIP-244 digest of the Orchard bundle (the actions without proofs and signatures, which the signature hash does not cover) */
static void orchard_digest(const zreq *r, uint8_t out[32])
{
    blake2b_ctx c, a;
    uint8_t d[32];

    bl(&c, "ZTxIdOrchardHash");
    if (r->nact) {
        bl(&a, "ZTxIdOrcActCHash");                                      /* compact: nullifier, cmx, ephemeral key, the first 52 bytes */
        for (int i = 0; i < r->nact; i++) {
            const uint8_t *x = r->act + (size_t) i * ACTION_LEN;
            blake2b_update(&a, x + 32, 32); blake2b_update(&a, x + 96, 32); blake2b_update(&a, x + 128, 32); blake2b_update(&a, x + 160, 52);
        }
        blake2b_final(&a, d); blake2b_update(&c, d, 32);
        bl(&a, "ZTxIdOrcActMHash");                                      /* the memos */
        for (int i = 0; i < r->nact; i++) blake2b_update(&a, r->act + (size_t) i * ACTION_LEN + 160 + 52, 512);
        blake2b_final(&a, d); blake2b_update(&c, d, 32);
        bl(&a, "ZTxIdOrcActNHash");                                      /* the rest: cv, rk, the end of the ciphertext, out ciphertext */
        for (int i = 0; i < r->nact; i++) {
            const uint8_t *x = r->act + (size_t) i * ACTION_LEN;
            blake2b_update(&a, x, 32); blake2b_update(&a, x + 64, 32); blake2b_update(&a, x + 160 + 564, 16); blake2b_update(&a, x + 740, 80);
        }
        blake2b_final(&a, d); blake2b_update(&c, d, 32);
        blake2b_update(&c, &r->oflags, 1);
        {
            uint8_t b[8];
            wr64(b, (uint64_t) r->vbal);
            blake2b_update(&c, b, 8);
        }
        blake2b_update(&c, r->anchor, 32);
    }
    blake2b_final(&c, out);
}

static void script_hash_part(blake2b_ctx *a, const uint8_t *spk, size_t n)
{
    uint8_t cs[3];
    size_t k = cs_put(cs, n);
    blake2b_update(a, cs, k);
    blake2b_update(a, spk, n);
}

/* The signature hash (ZIP-243 for version 4, ZIP-244 for version 5), hash type "all". i >= 0: of transparent input i; i = -1: the one
 * that authorizes the shielded part (Orchard spends) of a version 5 transaction. */
static void sighash(const zreq *r, int i, uint8_t out[32])
{
    blake2b_ctx c;
    uint8_t h[32], b[8], person[16];

    if (r->ver == 4) {
        static const uint8_t ZERO[32] = {0};
        branch_person(person, "ZcashSigHash", r->branch);
        blake2b_init(&c, 32, NULL, 0, NULL, person);
        wr32(b, r->header); blake2b_update(&c, b, 4);
        wr32(b, r->group); blake2b_update(&c, b, 4);
        hash_prevouts(r, "ZcashPrevoutHash", h); blake2b_update(&c, h, 32);
        hash_sequence(r, "ZcashSequencHash", h); blake2b_update(&c, h, 32);
        hash_outputs(r, "ZcashOutputsHash", h); blake2b_update(&c, h, 32);
        blake2b_update(&c, ZERO, 32);                                    /* joinsplits, shielded spends, shielded outputs */
        blake2b_update(&c, ZERO, 32);
        blake2b_update(&c, ZERO, 32);
        wr32(b, r->locktime); blake2b_update(&c, b, 4);
        wr32(b, r->expiry); blake2b_update(&c, b, 4);
        wr64(b, 0); blake2b_update(&c, b, 8);                            /* value balance */
        wr32(b, 1); blake2b_update(&c, b, 4);                            /* hash type all */
        blake2b_update(&c, r->vin + 41 * i, 36);
        {
            uint8_t cs[3];
            size_t n = cs_put(cs, r->spklen[i]);
            blake2b_update(&c, cs, n);
            blake2b_update(&c, r->spk[i], r->spklen[i]);                 /* the script code of a P2PKH input is its scriptPubKey */
        }
        wr64(b, r->amount[i]); blake2b_update(&c, b, 8);
        blake2b_update(&c, r->vin + 41 * i + 37, 4);
        blake2b_final(&c, out);
        return;
    }
    {
        uint8_t hdr[32], tr[32], sap[32], orc[32], pre[32], amt[32], scr[32], seq[32], outs[32], txin[32];
        blake2b_ctx a;
        bl(&c, "ZTxIdHeadersHash");                                      /* header digest */
        wr32(b, r->header); blake2b_update(&c, b, 4);
        wr32(b, r->group); blake2b_update(&c, b, 4);
        wr32(b, r->branch); blake2b_update(&c, b, 4);
        wr32(b, r->locktime); blake2b_update(&c, b, 4);
        wr32(b, r->expiry); blake2b_update(&c, b, 4);
        blake2b_final(&c, hdr);
        hash_prevouts(r, "ZTxIdPrevoutHash", pre);
        hash_sequence(r, "ZTxIdSequencHash", seq);
        hash_outputs(r, "ZTxIdOutputsHash", outs);
        if (r->nin == 0) {                                               /* no transparent inputs: the transparent digest of the txid */
            bl(&c, "ZTxIdTranspaHash");
            if (r->nout) { blake2b_update(&c, pre, 32); blake2b_update(&c, seq, 32); blake2b_update(&c, outs, 32); }
            blake2b_final(&c, tr);
        } else {
            bl(&a, "ZTxTrAmountsHash");
            for (int k = 0; k < r->nin; k++) { wr64(b, r->amount[k]); blake2b_update(&a, b, 8); }
            blake2b_final(&a, amt);
            bl(&a, "ZTxTrScriptsHash");
            for (int k = 0; k < r->nin; k++) script_hash_part(&a, r->spk[k], r->spklen[k]);
            blake2b_final(&a, scr);
            bl(&a, "Zcash___TxInHash");
            if (i >= 0) {
                blake2b_update(&a, r->vin + 41 * i, 36);
                wr64(b, r->amount[i]); blake2b_update(&a, b, 8);
                script_hash_part(&a, r->spk[i], r->spklen[i]);
                blake2b_update(&a, r->vin + 41 * i + 37, 4);
            }
            blake2b_final(&a, txin);
            bl(&c, "ZTxIdTranspaHash");                                 /* transparent signature digest */
            b[0] = 1; blake2b_update(&c, b, 1);
            blake2b_update(&c, pre, 32); blake2b_update(&c, amt, 32); blake2b_update(&c, scr, 32);
            blake2b_update(&c, seq, 32); blake2b_update(&c, outs, 32); blake2b_update(&c, txin, 32);
            blake2b_final(&c, tr);
        }
        bl(&c, "ZTxIdSaplingHash"); blake2b_final(&c, sap);              /* no Sapling parts */
        orchard_digest(r, orc);
        branch_person(person, "ZcashTxHash_", r->branch);
        blake2b_init(&c, 32, NULL, 0, NULL, person);
        blake2b_update(&c, hdr, 32); blake2b_update(&c, tr, 32); blake2b_update(&c, sap, 32); blake2b_update(&c, orc, 32);
        blake2b_final(&c, out);
    }
}

/* ---- summary ---- */

static void script_text(char *out, size_t cap, const uint8_t *s, size_t n, uint32_t *warn)
{
    uint8_t b[22];
    int r = -1;
    if (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) {
        b[0] = 0x1c; b[1] = 0xb8; memcpy(b + 2, s + 3, 20);
        r = base58check_encode(b, 22, out, cap);
    } else if (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) {
        b[0] = 0x1c; b[1] = 0xbd; memcpy(b + 2, s + 2, 20);
        r = base58check_encode(b, 22, out, cap);
    } else if (n >= 1 && s[0] == 0x6a) {
        snprintf(out, cap, T(TXT_OP_RETURN_DATA));
        *warn |= TXW_DATA;
        return;
    }
    if (r < 0) {
        static const char HX[] = "0123456789abcdef";
        size_t k = 0, show = n > 24 ? 24 : n;
        *warn |= TXW_UNKNOWN_SCRIPT;
        for (size_t i = 0; i < show && k + 3 < cap; i++) { out[k++] = HX[s[i] >> 4]; out[k++] = HX[s[i] & 15]; }
        out[k] = 0;
    }
}

/* does the action idx[i] belong to our Orchard key? (rk = [ask + alpha] G) */
static int orchard_key_fits(const zreq *r, int i, const uint8_t ask[32], uint8_t rsk[32])
{
    uint8_t rk[32];
    redpallas_randomize(rsk, rk, ask, r->alpha[i]);
    return memcmp(rk, r->act + (size_t) r->sidx[i] * ACTION_LEN + 64, 32) == 0;
}

/* Open the outputs of all actions with the outgoing viewing keys of the wallet (external, then internal for change), add them to the
 * list on the screen. Returns ZEC_ERR_MISMATCH when an output opens but does not fit its action. */
static int orchard_review(const zreq *r, const uint8_t sk[32], orchard_fvk *fe, orchard_fvk *fi, int *fi_ivk, tx_view *v, int *unread,
                          uint64_t *ov, uint64_t *shielded_sent)
{
    PROF("review: start");
    orchard_fvk_from_sk(fe, sk);
    orchard_internal_fvk_light(fi, fe);
    PROF("review: full viewing keys");
    for (int i = 0; i < r->nact; i++) {
        orch_note n;
        uint8_t raw[43];
        char ua[112];
        int rc = orchard_open_output(&n, r->act + (size_t) i * ACTION_LEN, fe->ovk), mine;
        if (rc == ORCH_NOT_OURS) rc = orchard_open_output(&n, r->act + (size_t) i * ACTION_LEN, fi->ovk);
        if (rc == ORCH_BAD) return ZEC_ERR_MISMATCH;
        PROF("review: action opened or not");
        if (rc != ORCH_OK) { (*unread)++; continue; }
        mine = orchard_is_address_of(n.d, n.pk_d, fe->ivk);
        if (!mine) {
            if (!*fi_ivk) { orchard_fvk_complete_ivk(fi); *fi_ivk = 1; }
            mine = orchard_is_address_of(n.d, n.pk_d, fi->ivk);
        }
        PROF("review: ownership checked");
        *ov += n.v;
        if (!mine) *shielded_sent += n.v;
        memcpy(raw, n.d, 11);
        memcpy(raw + 11, n.pk_d, 32);
        if (v->nout < TXV_OUTS) {
            txv_out *o = &v->out[v->nout++];
            if (orchard_unified_address(ua, sizeof ua, raw) > 0) snprintf(o->to, sizeof o->to, "%s", ua);
            else snprintf(o->to, sizeof o->to, T(TXT_ORCHARD_ADDRESS));
            txv_amount_u64(o->amount, sizeof o->amount, n.v, 8, "ZEC");
            o->mine = (uint8_t) mine;
        } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
    }
    return ZEC_OK;
}

int zec_summary(const uint8_t *req, size_t len, const zec_keys *k, tx_view *v)
{
    zreq r;
    int e = req_parse(&r, req, len);
    uint64_t in_sum = 0, out_sum = 0, spend = 0;
    const uint8_t *q;
    char line[96];

    txv_clear(v);
    if (e) return e;
    if (r.nact && r.nsig && k && k->orchard_sk) {                        /* the actions we should authorize must be ours */
        uint8_t ask[32], rsk[32];
        if (orchard_ask(ask, k->orchard_sk)) return ZEC_ERR_KEY;
        for (int i = 0; i < r.nsig; i++) if (!orchard_key_fits(&r, i, ask, rsk)) { secure_zero(ask, 32); secure_zero(rsk, 32); return ZEC_ERR_NOKEY; }
        secure_zero(ask, 32); secure_zero(rsk, 32);
    } else if (r.nact && r.nsig) return ZEC_ERR_NOKEY;
    snprintf(v->title, sizeof v->title, r.nact ? T(TXT_ZCASH_TRANSACTION_V5_ORCHARD) : T(TXT_ZCASH_TRANSACTION_V_N), r.ver);
    v->ninputs = r.nin;
    for (int i = 0; i < r.nin; i++) in_sum += r.amount[i];
    q = r.vout;
    for (int j = 0; j < r.nout; j++) {
        uint64_t sl, amount = rd64(q);
        const uint8_t *spk;
        q += 8;
        rd_cs(&q, r.vout_end, &sl);
        spk = q;
        q += sl;
        int mine = 0;
        out_sum += amount;
        for (int i = 0; i < r.nin && !mine; i++) mine = r.spklen[i] == sl && !memcmp(r.spk[i], spk, (size_t) sl);   /* back to an input address: change */
        if (!mine) spend += amount;
        if (v->nout < TXV_OUTS) {
            txv_out *o = &v->out[v->nout++];
            script_text(o->to, sizeof o->to, spk, (size_t) sl, &v->warn);
            txv_amount_u64(o->amount, sizeof o->amount, amount, 8, "ZEC");
            o->mine = (uint8_t) mine;
        } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
    }
    txv_amount_u64(v->total, sizeof v->total, spend, 8, "ZEC");
    if (r.nact) {                                                        /* the fee = transparent in + value leaving Orchard - transparent out */
        int64_t fee = (int64_t) in_sum + r.vbal - (int64_t) out_sum;
        int blind = 1, unread = 0, spends_known = 0;
        uint64_t ov = 0, sv = 0, shielded_sent = 0;
        if (fee >= 0) {
            txv_amount_u64(v->fee, sizeof v->fee, (uint64_t) fee, 8, "ZEC");
            if (r.vbal < 0 && (uint64_t) fee * 10 > (uint64_t) -r.vbal + in_sum) v->warn |= TXW_HIGH_FEE;
        } else { strcpy(v->fee, "?"); v->warn |= TXW_NO_FEE; }
        if (k && k->orchard_sk) {                                        /* open the outputs with our outgoing keys, check the spent notes */
            orchard_fvk fe, fi;
            int fi_ivk = 0;
            e = orchard_review(&r, k->orchard_sk, &fe, &fi, &fi_ivk, v, &unread, &ov, &shielded_sent);
            if (e) return e;
            spends_known = 1;
            for (int i = 0; i < r.nsig; i++) {
                const uint8_t *dd = r.sdata[i];
                uint64_t val = 0;
                if (!r.snote[i]) { spends_known = 0; continue; }
                for (int b = 0; b < 8; b++) val |= (uint64_t) dd[11 + b] << (8 * b);
                if (r.snote[i] == 2 && !fi_ivk) { orchard_fvk_complete_ivk(&fi); fi_ivk = 1; }
                if (orchard_check_spend(r.act + (size_t) r.sidx[i] * ACTION_LEN, dd, val, dd + 19, dd + 51, r.snote[i] == 1 ? fe.ivk : fi.ivk, fe.nk)) {
                    secure_zero(&fe, sizeof fe); secure_zero(&fi, sizeof fi);
                    return ZEC_ERR_MISMATCH;
                }
                sv += val;
                PROF("review: spent note checked");
            }
            secure_zero(&fe, sizeof fe); secure_zero(&fi, sizeof fi);
            if (spends_known) {
                /* the pool balance: spends - outputs = value balance, so what we spend, less what the readable outputs take and what
                 * leaves the pool, is the least the outputs we cannot read hold */
                int64_t rem = (int64_t) sv - r.vbal - (int64_t) ov;
                blind = rem > 0;
                if (rem > 0) { char am[40]; txv_amount_u64(am, sizeof am, (uint64_t) rem, 8, "ZEC"); snprintf(line, sizeof line, T(TXT_N_OR_MORE_GOES_TO_OUTPUTS_THAT), am); txv_note(v, line); }
            } else txv_note(v, T(TXT_THE_VALUE_OF_THE_NOTES_SPENT));
            if (spends_known && r.nsig) {
                char am[40];
                txv_amount_u64(am, sizeof am, sv, 8, "ZEC");
                snprintf(line, sizeof line, T(TXT_SPENDS_N_OF_THIS_WALLET_IN), am);
                txv_note(v, line);
            }
            if (unread) { snprintf(line, sizeof line, TN(unread, TXT_SHIELDED_OUTPUT_CANNOT_BE_READ_ONE, TXT_SHIELDED_OUTPUT_CANNOT_BE_READ_MANY), unread); txv_note(v, line); }
        }
        if (blind) v->warn |= TXW_BLIND;
        if (shielded_sent) txv_amount_u64(v->total, sizeof v->total, spend + shielded_sent, 8, "ZEC");
        snprintf(line, sizeof line, TN(r.nact, TXT_ORCHARD_ACTION_ONE, TXT_ORCHARD_ACTION_MANY), r.nact, blind ? T(TXT_WHAT_THEY_SEND_AND_TO_WHOM) : "");
        txv_note(v, line);
        if (r.vbal < 0) { char am[40]; txv_amount_u64(am, sizeof am, (uint64_t) -r.vbal, 8, "ZEC"); snprintf(line, sizeof line, T(TXT_N_GOES_INTO_THE_SHIELDED_POOL), am); txv_note(v, line); }
        else if (r.vbal > 0) { char am[40]; txv_amount_u64(am, sizeof am, (uint64_t) r.vbal, 8, "ZEC"); snprintf(line, sizeof line, T(TXT_N_COMES_OUT_OF_THE_SHIELDED), am); txv_note(v, line); }
        snprintf(line, sizeof line, TN(r.nsig, TXT_SPEND_TO_AUTHORIZE_ONE, TXT_SPEND_TO_AUTHORIZE_MANY), r.nsig, (unsigned) r.branch);
        txv_note(v, line);
        return ZEC_OK;
    }
    if (in_sum >= out_sum) {
        txv_amount_u64(v->fee, sizeof v->fee, in_sum - out_sum, 8, "ZEC");
        if ((in_sum - out_sum) * 10 > in_sum) v->warn |= TXW_HIGH_FEE;
    } else { strcpy(v->fee, "?"); v->warn |= TXW_NO_FEE; }
    snprintf(line, sizeof line, TN(r.nin, TXT_INPUT_BRANCH_ID_EXPIRY_ONE, TXT_INPUT_BRANCH_ID_EXPIRY_MANY), r.nin, (unsigned) r.branch, (unsigned) r.expiry);
    txv_note(v, line);
    return ZEC_OK;
}

/* ---- signing ---- */

int zec_sign(const uint8_t *req, size_t len, const zec_keys *k, uint8_t *out, size_t cap, size_t *outlen)
{
    const bip32_node *master = k ? k->master : NULL;
    const uint8_t *rawk = k ? k->raw : NULL;
    zreq r;
    int e = req_parse(&r, req, len);
    uint8_t sc[MAXIN][110];
    size_t scl[MAXIN];
    size_t need;
    uint8_t *o;

    if (e) return e;
    if (r.nin && !master && !rawk) return ZEC_ERR_NOKEY;
    for (int i = 0; i < r.nin; i++) {
        uint8_t dig[32], priv[32], pub[33], h[20], sig[64], der[80];
        uint32_t path[PATH_MAX_DEPTH];
        int dl;
        const uint8_t *s = r.spk[i];

        if (r.spklen[i] != 25 || s[0] != 0x76 || s[1] != 0xa9 || s[2] != 0x14 || s[23] != 0x88 || s[24] != 0xac) return ZEC_ERR_UNSUPPORTED;
        if (rawk) {                                                      /* a raw key: the script says whose it is, the path is not used */
            memcpy(priv, rawk, 32);
        } else {
            bip32_node n = *master;

            for (int k = 0; k < r.depth[i]; k++) path[k] = rd32(r.path[i] + 4 * k);
            if (bip32_derive_path(&n, path, (size_t) r.depth[i])) return ZEC_ERR_KEY;
            memcpy(priv, n.key, 32);
            secure_zero(&n, sizeof n);
        }
        if (secp256k1_pubkey_create(pub, priv)) { secure_zero(priv, 32); return ZEC_ERR_KEY; }
        hash160(pub, 33, h);
        if (memcmp(h, s + 3, 20)) { secure_zero(priv, 32); return ZEC_ERR_NOKEY; }
        sighash(&r, i, dig);
        if (secp256k1_ecdsa_sign(sig, NULL, priv, dig)) { secure_zero(priv, 32); return ZEC_ERR_KEY; }
        secure_zero(priv, 32);
        dl = secp256k1_sig_to_der(der, sig);
        der[dl] = 1;                                                     /* hash type all */
        sc[i][0] = (uint8_t) (dl + 1);
        memcpy(sc[i] + 1, der, (size_t) dl + 1);
        sc[i][dl + 2] = 33;
        memcpy(sc[i] + dl + 3, pub, 33);
        scl[i] = (size_t) dl + 3 + 33;
    }
    if (r.nact) {                                                        /* the Orchard spend authorizations + the transparent scriptSigs */
        uint8_t dig[32], ask[32], rsk[32];
        size_t sz = 4 + 1 + 1;
        for (int i = 0; i < r.nin; i++) sz += 1 + scl[i];
        sz += (size_t) r.nsig * 65;
        if (sz > cap) return ZEC_ERR_SPACE;
        if (r.nsig && (!k || !k->orchard_sk || orchard_ask(ask, k->orchard_sk))) return ZEC_ERR_NOKEY;
        sighash(&r, -1, dig);
        o = out;
        memcpy(o, "ZORS", 4); o += 4;
        *o++ = (uint8_t) r.nin;
        for (int i = 0; i < r.nin; i++) { *o++ = (uint8_t) scl[i]; memcpy(o, sc[i], scl[i]); o += scl[i]; }
        *o++ = (uint8_t) r.nsig;
        for (int i = 0; i < r.nsig; i++) {
            if (!orchard_key_fits(&r, i, ask, rsk)) { secure_zero(ask, 32); secure_zero(rsk, 32); return ZEC_ERR_NOKEY; }
            *o++ = r.sidx[i];
            redpallas_sign(o, rsk, dig);
            o += 64;
        }
        secure_zero(ask, 32); secure_zero(rsk, 32);
        *outlen = (size_t) (o - out);
        return ZEC_OK;
    }
    need = 100 + r.taillen + (size_t) (r.vout_end - r.vout);
    for (int i = 0; i < r.nin; i++) need += 41 + scl[i];
    if (need > cap) return ZEC_ERR_SPACE;
    o = out;
    wr32(o, r.header); o += 4;
    wr32(o, r.group); o += 4;
    if (r.ver == 5) { wr32(o, r.branch); wr32(o + 4, r.locktime); wr32(o + 8, r.expiry); o += 12; }
    o += cs_put(o, (uint64_t) r.nin);
    for (int i = 0; i < r.nin; i++) {
        memcpy(o, r.vin + 41 * i, 36); o += 36;
        o += cs_put(o, scl[i]);
        memcpy(o, sc[i], scl[i]); o += scl[i];
        memcpy(o, r.vin + 41 * i + 37, 4); o += 4;
    }
    o += cs_put(o, (uint64_t) r.nout);
    memcpy(o, r.vout, (size_t) (r.vout_end - r.vout)); o += r.vout_end - r.vout;
    memcpy(o, r.tail, r.taillen); o += r.taillen;
    *outlen = (size_t) (o - out);
    return ZEC_OK;
}
