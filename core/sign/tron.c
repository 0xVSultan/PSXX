#include "sign/tron.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "ec/secp256k1.h"
#include "hash/sha256.h"
#include "sign/pb.h"
#include "tr.h"

typedef struct {
    int      ncontracts;
    uint64_t type;
    const uint8_t *param; size_t paramlen;            /* the Any.value of the contract */
    uint64_t fee_limit;
} tron_tx;

static int tron_parse(tron_tx *t, const uint8_t *raw, size_t len)
{
    pb_reader r, c, a;
    uint32_t f, f2, f3;
    int wt, wt2, wt3, e;
    uint64_t v, v2, v3;
    const uint8_t *d, *d2, *d3;
    size_t dl, dl2, dl3;

    memset(t, 0, sizeof *t);
    pb_init(&r, raw, len);
    while ((e = pb_next(&r, &f, &wt, &v, &d, &dl)) == 1) {
        if (f == 11 && wt == 2) {
            t->ncontracts++;
            pb_init(&c, d, dl);
            while ((e = pb_next(&c, &f2, &wt2, &v2, &d2, &dl2)) == 1) {
                if (f2 == 1 && wt2 == 0) t->type = v2;
                else if (f2 == 2 && wt2 == 2) {                       /* Any { type_url, value } */
                    pb_init(&a, d2, dl2);
                    while ((e = pb_next(&a, &f3, &wt3, &v3, &d3, &dl3)) == 1)
                        if (f3 == 2 && wt3 == 2) { t->param = d3; t->paramlen = dl3; }
                    if (e < 0) return TRON_ERR_PARSE;
                }
            }
            if (e < 0) return TRON_ERR_PARSE;
        } else if (f == 18 && wt == 0) t->fee_limit = v;
    }
    if (e < 0) return TRON_ERR_PARSE;
    if (t->ncontracts != 1) return TRON_ERR_UNSUPPORTED;
    return TRON_OK;
}

static void tron_addr(char *out, size_t cap, const uint8_t *a, size_t n)
{
    if (n == 21 && a[0] == 0x41) {
        if (base58check_encode(a, 21, out, cap) < 0) out[0] = 0;
    } else snprintf(out, cap, "?");
}

static const char *res_name(uint64_t r) { return r == 1 ? "ENERGY" : r == 2 ? "TRON POWER" : "BANDWIDTH"; }

/* The keys of one Permission (field 7, Key { address = 1, weight = 2 }): a line each. Returns how many. */
static int perm_keys(tx_view *v, const char *who, const uint8_t *p, size_t n)
{
    pb_reader r, k;
    uint32_t f, f2;
    int wt, wt2, count = 0;
    uint64_t x, x2, thr = 0, w;
    const uint8_t *d, *d2;
    size_t dl, dl2;

    pb_init(&r, p, n);
    while (pb_next(&r, &f, &wt, &x, &d, &dl) == 1) if (f == 4 && wt == 0) thr = x;                  /* threshold */
    pb_init(&r, p, n);
    while (pb_next(&r, &f, &wt, &x, &d, &dl) == 1) {
        const uint8_t *ad = NULL;
        size_t adl = 0;

        if (f != 7 || wt != 2) continue;
        w = 0;
        pb_init(&k, d, dl);
        while (pb_next(&k, &f2, &wt2, &x2, &d2, &dl2) == 1) {
            if (f2 == 1 && wt2 == 2) { ad = d2; adl = dl2; }
            else if (f2 == 2 && wt2 == 0) w = x2;
        }
        count++;
        if (v->nout < TXV_OUTS) {
            char a[40];
            tron_addr(a, sizeof a, ad ? ad : (const uint8_t *) "", adl);
            snprintf(v->out[v->nout].to, sizeof v->out[0].to, T(TXT_N_KEY_N), who, a);
            snprintf(v->out[v->nout].amount, sizeof v->out[0].amount, T(TXT_WEIGHT_N_THRESHOLD_N), (unsigned long long) w, (unsigned long long) thr);
            v->nout++;
        } else { v->nmore++; v->warn |= TXW_TRUNCATED; }
    }
    return count;
}

/* Stake 2.0 (54 freeze, 55 unfreeze, 56 withdraw, 57 delegate a resource, 58 take it back) and 46 (change who can sign for the account): shown in full, not blind.
 * Returns 1 when the type was one of these. */
static int tron_special(const tron_tx *t, tx_view *v)
{
    pb_reader r;
    uint32_t f;
    int wt;
    uint64_t x, balance = 0, resource = 0, lock_period = 0;
    int lock = 0;
    const uint8_t *d, *receiver = NULL;
    size_t dl, recl = 0;
    char a[40], line[96];

    if (!((t->type >= 54 && t->type <= 58) || t->type == 46)) return 0;
    v->nout = 1;
    if (t->type == 46) {
        int perms = 0, keys = 0;
        pb_init(&r, t->param, t->paramlen);
        while (pb_next(&r, &f, &wt, &x, &d, &dl) == 1) {
            if (wt != 2 || (f != 2 && f != 3 && f != 4)) continue;                              /* owner, witness, actives */
            perms++;
            keys += perm_keys(v, f == 2 ? "Owner" : f == 3 ? "Witness" : "Active", d, dl);
        }
        snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_CHANGES_WHO_CAN_SIGN_FOR_THIS));
        {
            char a[24], b[24];
            snprintf(a, sizeof a, TN(keys, TXT_COUNT_KEY_IN_ONE, TXT_COUNT_KEY_IN_MANY), keys);
            snprintf(b, sizeof b, TN(perms, TXT_COUNT_PERMISSION_ONE, TXT_COUNT_PERMISSION_MANY), perms);
            snprintf(v->out[0].amount, sizeof v->out[0].amount, "%s %s", a, b);
        }
        txv_note(v, T(TXT_OWNER_AND_ACTIVE_KEYS_CAN_MOVE));
        v->warn |= TXW_DELEGATION;
        return 1;
    }
    pb_init(&r, t->param, t->paramlen);
    while (pb_next(&r, &f, &wt, &x, &d, &dl) == 1) {
        if (t->type == 54 || t->type == 55) {
            if (f == 2 && wt == 0) balance = x;
            else if (f == 3 && wt == 0) resource = x;
        } else if (t->type == 57 || t->type == 58) {
            if (f == 2 && wt == 0) resource = x;
            else if (f == 3 && wt == 0) balance = x;
            else if (f == 4 && wt == 2) { receiver = d; recl = dl; }
            else if (f == 5 && wt == 0) lock = x != 0;
            else if (f == 6 && wt == 0) lock_period = x;
        }
    }
    if (t->type == 56) {
        strcpy(v->out[0].to, T(TXT_WITHDRAW_THE_UNSTAKED_TRX));
        return 1;
    }
    txv_amount_u64(v->out[0].amount, sizeof v->out[0].amount, balance, 6, "TRX");
    if (t->type == 54) snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_STAKE_FOR_N), res_name(resource));
    else if (t->type == 55) snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_UNSTAKE_FROM_N), res_name(resource));
    else {
        tron_addr(a, sizeof a, receiver ? receiver : (const uint8_t *) "", recl);
        snprintf(v->out[0].to, sizeof v->out[0].to, "%s %s %s %s", t->type == 57 ? T(TXT_DELEGATE) : T(TXT_TAKE_BACK), res_name(resource), t->type == 57 ? "to" : "from", a);
        if (t->type == 57) {
            if (lock) snprintf(line, sizeof line, T(TXT_LOCKED_FOR_N_BLOCKS), (unsigned long long) lock_period);
            else snprintf(line, sizeof line, T(TXT_NOT_LOCKED));
            txv_note(v, line);
        }
    }
    return 1;
}

int tron_summary(const uint8_t *raw, size_t len, tx_view *v)
{
    tron_tx t;
    int e = tron_parse(&t, raw, len);
    pb_reader r;
    uint32_t f;
    int wt;
    uint64_t x, amount = 0, callvalue = 0;
    const uint8_t *d, *to = NULL, *data = NULL, *asset = NULL;
    size_t dl, tol = 0, datal = 0, assetl = 0;
    char line[96], a[40];

    txv_clear(v);
    if (e) return e;
    strcpy(v->title, T(TXT_TRON_TRANSACTION));
    if (tron_special(&t, v)) goto fee;
    pb_init(&r, t.param, t.paramlen);
    while (pb_next(&r, &f, &wt, &x, &d, &dl) == 1) {
        if (t.type == 1) {
            if (f == 2 && wt == 2) { to = d; tol = dl; }
            else if (f == 3 && wt == 0) amount = x;
        } else if (t.type == 2) {
            if (f == 1 && wt == 2) { asset = d; assetl = dl; }
            else if (f == 3 && wt == 2) { to = d; tol = dl; }
            else if (f == 4 && wt == 0) amount = x;
        } else if (t.type == 31) {
            if (f == 2 && wt == 2) { to = d; tol = dl; }
            else if (f == 3 && wt == 0) callvalue = x;
            else if (f == 4 && wt == 2) { data = d; datal = dl; }
        }
    }
    v->nout = 1;
    if (t.type == 1 && to) {
        tron_addr(v->out[0].to, sizeof v->out[0].to, to, tol);
        txv_amount_u64(v->out[0].amount, sizeof v->out[0].amount, amount, 6, "TRX");
        strcpy(v->total, v->out[0].amount);
    } else if (t.type == 2 && to) {
        char name[40];
        size_t n = assetl < sizeof name - 1 ? assetl : sizeof name - 1;
        for (size_t i = 0; i < n; i++) name[i] = (asset[i] >= 0x20 && asset[i] < 0x7f) ? (char) asset[i] : '?';
        name[n] = 0;
        tron_addr(v->out[0].to, sizeof v->out[0].to, to, tol);
        txv_amount_u64(v->out[0].amount, sizeof v->out[0].amount, amount, 0, NULL);
        strcat(v->out[0].amount, T(TXT_UNITS_OF_TRC_10_TOKEN));
        strncat(v->out[0].amount, name, sizeof v->out[0].amount - strlen(v->out[0].amount) - 1);
    } else if (t.type == 31 && to && data && datal == 68 && data[0] == 0xa9 && data[1] == 0x05 && data[2] == 0x9c && data[3] == 0xbb) {
        uint8_t dest[21];
        dest[0] = 0x41;
        memcpy(dest + 1, data + 16, 20);                       /* the last 20 bytes of the first argument */
        tron_addr(v->out[0].to, sizeof v->out[0].to, dest, 21);
        txv_amount_be(v->out[0].amount, sizeof v->out[0].amount - 12, data + 36, 32, 0, NULL);
        strcat(v->out[0].amount, T(TXT_TOKEN_UNITS));
        tron_addr(a, sizeof a, to, tol);
        snprintf(line, sizeof line, T(TXT_TRC_20_TRANSFER_TOKEN_CONTRACT), a);
        txv_note(v, line);
        v->warn |= TXW_DATA;
    } else if (t.type == 31 && to) {
        tron_addr(a, sizeof a, to, tol);
        snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_CONTRACT_N), a);
        txv_amount_u64(v->out[0].amount, sizeof v->out[0].amount, callvalue, 6, "TRX");
        snprintf(line, sizeof line, T(TXT_CONTRACT_CALL_N_BYTES_OF_DATA_2), (unsigned) datal);
        txv_note(v, line);
        v->warn |= TXW_DATA | TXW_BLIND;
    } else {
        snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_CONTRACT_TYPE_N), (unsigned) t.type);
        v->warn |= TXW_BLIND;
        txv_note(v, T(TXT_CANNOT_BE_SHOWN_ONLY_THE_HASH));
    }
fee:
    if (t.fee_limit) {
        char fl[44];
        txv_amount_u64(fl, sizeof fl, t.fee_limit, 6, "TRX");
        snprintf(line, sizeof line, T(TXT_FEE_LIMIT_N), fl);
        txv_note(v, line);
        strcpy(v->fee, fl);
    }
    return TRON_OK;
}

int tron_sign(const uint8_t *raw, size_t len, const uint8_t priv[32], uint8_t sig65[65], uint8_t txid[32])
{
    tron_tx t;
    uint8_t sig[64];
    int rec, e = tron_parse(&t, raw, len);

    if (e) return e;
    sha256(raw, len, txid);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, txid)) return TRON_ERR_KEY;
    memcpy(sig65, sig, 64);
    sig65[64] = (uint8_t) (rec & 1);
    return TRON_OK;
}
