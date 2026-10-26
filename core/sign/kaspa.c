#include "sign/kaspa.h"
#include <stdio.h>
#include <string.h>
#include "coin/chains.h"
#include "ec/secp256k1.h"
#include "hash/blake2b.h"
#include "util.h"
#include "tr.h"

typedef struct {
    const uint8_t *txid;
    uint32_t       index, change, kidx;
    uint64_t       sequence, amount;
    uint16_t       sver;
    const uint8_t *spk;
    uint8_t        sigops, spklen, ours;
} kin;

typedef struct {
    uint64_t       value;
    uint16_t       sver;
    const uint8_t *spk;
    uint8_t        spklen, chg;
    uint32_t       change, kidx;
} kout;

typedef struct {
    int      nin, nout;
    uint64_t lock;
    kin      in[KAS_MAX_IN];
    kout     out[KAS_MAX_OUT];
} ktx;

static const uint8_t KEY[] = "TransactionSigningHash";

static uint64_t rd_le(const uint8_t *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void put_le(blake2b_ctx *c, uint64_t v, int n)
{
    uint8_t b[8];
    for (int i = 0; i < n; i++) b[i] = (uint8_t) (v >> (8 * i));
    blake2b_update(c, b, (size_t) n);
}

static void h_init(blake2b_ctx *c) { blake2b_init(c, 32, KEY, sizeof KEY - 1, NULL, NULL); }

static int parse(ktx *t, const uint8_t *b, size_t len)
{
    size_t o = 0;

#define NEED(n) do { if ((size_t) (n) > len - o) return KAS_ERR_PARSE; } while (0)
    NEED(12);
    if (rd_le(b, 2) != 0) return KAS_ERR_UNSUPPORTED;                        /* only version 0 transactions */
    t->nin = b[2];
    t->nout = b[3];
    t->lock = rd_le(b + 4, 8);
    o = 12;
    if (t->nin < 1 || t->nin > KAS_MAX_IN || t->nout < 1 || t->nout > KAS_MAX_OUT) return KAS_ERR_PARSE;
    for (int i = 0; i < t->nin; i++) {
        kin *x = &t->in[i];
        NEED(32 + 4 + 8 + 1 + 8 + 2 + 1);
        x->txid = b + o;
        x->index = (uint32_t) rd_le(b + o + 32, 4);
        x->sequence = rd_le(b + o + 36, 8);
        x->sigops = b[o + 44];
        x->amount = rd_le(b + o + 45, 8);
        x->sver = (uint16_t) rd_le(b + o + 53, 2);
        x->spklen = b[o + 55];
        o += 56;
        NEED(x->spklen + 1);
        x->spk = b + o;
        o += x->spklen;
        x->ours = b[o++];
        if (x->ours > 1) return KAS_ERR_PARSE;
        x->change = x->kidx = 0;
        if (x->ours) { NEED(8); x->change = (uint32_t) rd_le(b + o, 4); x->kidx = (uint32_t) rd_le(b + o + 4, 4); o += 8; }
    }
    for (int i = 0; i < t->nout; i++) {
        kout *x = &t->out[i];
        NEED(8 + 2 + 1);
        x->value = rd_le(b + o, 8);
        x->sver = (uint16_t) rd_le(b + o + 8, 2);
        x->spklen = b[o + 10];
        o += 11;
        NEED(x->spklen + 1);
        x->spk = b + o;
        o += x->spklen;
        x->chg = b[o++];
        if (x->chg > 1) return KAS_ERR_PARSE;
        x->change = x->kidx = 0;
        if (x->chg) { NEED(8); x->change = (uint32_t) rd_le(b + o, 4); x->kidx = (uint32_t) rd_le(b + o + 4, 4); o += 8; }
    }
    if (o != len) return KAS_ERR_PARSE;
#undef NEED
    return KAS_OK;
}

/* the sub-hashes that all the inputs share */
static void common(const ktx *t, uint8_t prev[32], uint8_t seq[32], uint8_t sig[32], uint8_t outs[32])
{
    blake2b_ctx c;

    h_init(&c);
    for (int i = 0; i < t->nin; i++) { blake2b_update(&c, t->in[i].txid, 32); put_le(&c, t->in[i].index, 4); }
    blake2b_final(&c, prev);
    h_init(&c);
    for (int i = 0; i < t->nin; i++) put_le(&c, t->in[i].sequence, 8);
    blake2b_final(&c, seq);
    h_init(&c);
    for (int i = 0; i < t->nin; i++) put_le(&c, t->in[i].sigops, 1);
    blake2b_final(&c, sig);
    h_init(&c);
    for (int i = 0; i < t->nout; i++) {
        put_le(&c, t->out[i].value, 8);
        put_le(&c, t->out[i].sver, 2);
        put_le(&c, t->out[i].spklen, 8);                                   /* write_var_bytes: a u64 length, then the bytes */
        blake2b_update(&c, t->out[i].spk, t->out[i].spklen);
    }
    blake2b_final(&c, outs);
}

static void input_hash(const ktx *t, int i, const uint8_t prev[32], const uint8_t seq[32], const uint8_t sig[32], const uint8_t outs[32], uint8_t hash[32])
{
    static const uint8_t ZERO[32], NATIVE[20];
    const kin *x = &t->in[i];
    blake2b_ctx c;

    h_init(&c);
    put_le(&c, 0, 2);                                                       /* version */
    blake2b_update(&c, prev, 32);
    blake2b_update(&c, seq, 32);
    blake2b_update(&c, sig, 32);
    blake2b_update(&c, x->txid, 32);
    put_le(&c, x->index, 4);
    put_le(&c, x->sver, 2);
    put_le(&c, x->spklen, 8);
    blake2b_update(&c, x->spk, x->spklen);
    put_le(&c, x->amount, 8);
    put_le(&c, x->sequence, 8);
    put_le(&c, x->sigops, 1);
    blake2b_update(&c, outs, 32);
    put_le(&c, t->lock, 8);
    blake2b_update(&c, NATIVE, 20);                                         /* the native subnetwork */
    put_le(&c, 0, 8);                                                       /* gas */
    blake2b_update(&c, ZERO, 32);                                           /* the hash of an empty payload of a native transaction */
    put_le(&c, 1, 1);                                                       /* SIGHASH_ALL */
    blake2b_final(&c, hash);
}

int kaspa_sighash(const uint8_t *tx, size_t len, int i, uint8_t hash[32])
{
    static ktx t;
    uint8_t prev[32], seq[32], sig[32], outs[32];
    int e = parse(&t, tx, len);

    if (e) return e;
    if (i < 0 || i >= t.nin) return KAS_ERR_PARSE;
    common(&t, prev, seq, sig, outs);
    input_hash(&t, i, prev, seq, sig, outs, hash);
    return KAS_OK;
}

/* does the script spend to the schnorr key of (change, index)? Returns 1 / 0, or -1 if the key cannot be had */
static int key_matches(kas_key_fn kf, void *ctx, uint32_t change, uint32_t idx, const uint8_t *spk, size_t spklen, uint16_t sver)
{
    uint8_t key[32], x[32];
    int ok;

    if (kf(ctx, change, idx, key)) return -1;
    ok = !secp256k1_xonly_pubkey(x, NULL, key) && sver == 0 && spklen == 34 && spk[0] == 0x20 && spk[33] == 0xac && !memcmp(spk + 1, x, 32);
    secure_zero(key, sizeof key);
    return ok;
}

static void script_text(char *to, size_t cap, const uint8_t *spk, size_t n, uint16_t sver, uint32_t *warn)
{
    if (sver == 0 && n == 34 && spk[0] == 0x20 && spk[33] == 0xac) { kaspa_address_v(to, cap, "kaspa", 0, spk + 1, 32); return; }
    if (sver == 0 && n == 35 && spk[0] == 0x21 && spk[34] == 0xab) { kaspa_address_v(to, cap, "kaspa", 1, spk + 1, 33); return; }
    if (sver == 0 && n == 35 && spk[0] == 0xaa && spk[1] == 0x20 && spk[34] == 0x87) { kaspa_address_v(to, cap, "kaspa", 8, spk + 2, 32); return; }
    {
        static const char HX[] = "0123456789abcdef";
        size_t m = n < 20 ? n : 20, o = 0;
        o += (size_t) snprintf(to, cap, T(TXT_SCRIPT_V_N), (unsigned) sver);
        for (size_t i = 0; i < m && o + 3 < cap; i++) { to[o++] = HX[spk[i] >> 4]; to[o++] = HX[spk[i] & 15]; }
        to[o] = 0;
        *warn |= TXW_UNKNOWN_SCRIPT;
    }
}

int kaspa_summary(const uint8_t *tx, size_t len, kas_key_fn kf, void *ctx, tx_view *v)
{
    static ktx t;
    uint64_t in_sum = 0, out_sum = 0, sent = 0;
    int e = parse(&t, tx, len), nsign = 0;
    char line[96];

    txv_clear(v);
    if (e) return e;
    strcpy(v->title, T(TXT_KASPA_TRANSACTION));
    for (int i = 0; i < t.nin; i++) {
        in_sum += t.in[i].amount;
        if (t.in[i].ours) {
            int m = key_matches(kf, ctx, t.in[i].change, t.in[i].kidx, t.in[i].spk, t.in[i].spklen, t.in[i].sver);
            if (m < 0) return KAS_ERR_KEY;
            nsign += m;
        }
    }
    for (int j = 0; j < t.nout; j++) {
        const kout *x = &t.out[j];
        int mine = 0;
        out_sum += x->value;
        if (x->chg) {
            mine = key_matches(kf, ctx, x->change, x->kidx, x->spk, x->spklen, x->sver);
            if (mine < 0) return KAS_ERR_KEY;
        }
        if (!mine) sent += x->value;
        if (v->nout < TXV_OUTS) {
            txv_out *o = &v->out[v->nout++];
            script_text(o->to, sizeof o->to, x->spk, x->spklen, x->sver, &v->warn);
            txv_amount_u64(o->amount, sizeof o->amount, x->value, 8, "KAS");
            o->mine = (uint8_t) mine;
        } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
    }
    v->ninputs = t.nin;
    v->nsign = nsign;
    if (!nsign) v->warn |= TXW_NOT_MINE;
    txv_amount_u64(v->total, sizeof v->total, sent, 8, "KAS");
    if (in_sum >= out_sum) {
        txv_amount_u64(v->fee, sizeof v->fee, in_sum - out_sum, 8, "KAS");
        if (sent && (in_sum - out_sum) * 10 > sent) v->warn |= TXW_HIGH_FEE;
    } else v->warn |= TXW_NO_FEE;
    {
        char a[40], b[24];
        snprintf(a, sizeof a, TN(t.nin, TXT_COUNT_INPUT_OURS_ONE, TXT_COUNT_INPUT_OURS_MANY), t.nin, nsign);
        snprintf(b, sizeof b, TN(t.nout, TXT_COUNT_OUTPUT_ONE, TXT_COUNT_OUTPUT_MANY), t.nout);
        snprintf(line, sizeof line, "%s, %s", a, b);
    }
    txv_note(v, line);
    if (t.lock) { snprintf(line, sizeof line, T(TXT_LOCK_TIME_N), (unsigned long long) t.lock); txv_note(v, line); }
    return KAS_OK;
}

int kaspa_sign(const uint8_t *tx, size_t len, kas_key_fn kf, void *ctx, uint8_t *out, size_t cap, size_t *outlen)
{
    static ktx t;
    uint8_t prev[32], seq[32], sig[32], outs[32], key[32], h[32];
    size_t o = 6;
    int e = parse(&t, tx, len), n = 0;

    if (e) return e;
    if (cap < 6 + (size_t) t.nin * 68) return KAS_ERR_SPACE;
    common(&t, prev, seq, sig, outs);
    memcpy(out, "KSIG", 4);
    out[4] = 1;
    for (int i = 0; i < t.nin; i++) {
        if (!t.in[i].ours) continue;
        if (kf(ctx, t.in[i].change, t.in[i].kidx, key)) return KAS_ERR_KEY;
        {
            uint8_t x[32];
            if (secp256k1_xonly_pubkey(x, NULL, key) || t.in[i].sver != 0 || t.in[i].spklen != 34 || t.in[i].spk[0] != 0x20 || t.in[i].spk[33] != 0xac || memcmp(t.in[i].spk + 1, x, 32)) {
                secure_zero(key, sizeof key);
                return KAS_ERR_KEY;                                         /* the spent script is not the one of the key: not signed */
            }
        }
        input_hash(&t, i, prev, seq, sig, outs, h);
        out[o] = (uint8_t) i;
        out[o + 1] = 66;
        out[o + 2] = 0x41;                                                  /* OP_DATA_65: the push of the signature and the hash type */
        e = secp256k1_schnorr_sign(out + o + 3, key, h, NULL);
        secure_zero(key, sizeof key);
        if (e) return KAS_ERR_KEY;
        out[o + 67] = 0x01;
        o += 68;
        n++;
    }
    if (!n) return KAS_ERR_KEY;
    out[5] = (uint8_t) n;
    *outlen = o;
    return KAS_OK;
}
