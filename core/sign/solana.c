#include "sign/solana.h"
#include <stdio.h>
#include <string.h>
#include "coin/base58.h"
#include "ec/ed25519.h"
#include "tr.h"

typedef struct {
    int            version;                       /* 0 legacy, 1 = v0 */
    int            nsig, nro_signed, nro_unsigned;
    int            nacc;
    const uint8_t *acc;                           /* 32 bytes each */
    const uint8_t *blockhash;
    int            ninstr;
    const uint8_t *instr;                         /* the first instruction */
    const uint8_t *end;
} sol_msg;

static int cu16(const uint8_t **pp, const uint8_t *end, uint32_t *v)
{
    uint32_t x = 0;
    for (int i = 0; i < 3; i++) {
        if (*pp >= end) return -1;
        uint8_t b = *(*pp)++;
        x |= (uint32_t) (b & 0x7f) << (7 * i);
        if (!(b & 0x80)) { *v = x; return 0; }
    }
    return -1;
}

static int sol_parse(sol_msg *m, const uint8_t *b, size_t n)
{
    const uint8_t *p = b, *end = b + n;
    uint32_t c, k;

    memset(m, 0, sizeof *m);
    m->end = end;
    if (!n) return SOL_ERR_PARSE;
    if (b[0] & 0x80) {
        if ((b[0] & 0x7f) != 0) return SOL_ERR_PARSE;                 /* only version 0 exists */
        m->version = 1;
        p++;
    }
    if (end - p < 3) return SOL_ERR_PARSE;
    m->nsig = p[0]; m->nro_signed = p[1]; m->nro_unsigned = p[2];
    p += 3;
    if (cu16(&p, end, &c) || c < 1 || c > 256 || (size_t) (end - p) < (size_t) c * 32 + 32) return SOL_ERR_PARSE;
    m->nacc = (int) c;
    m->acc = p;
    p += (size_t) c * 32;
    if (m->nsig < 1 || m->nsig > m->nacc) return SOL_ERR_PARSE;
    m->blockhash = p;
    p += 32;
    if (cu16(&p, end, &c)) return SOL_ERR_PARSE;
    m->ninstr = (int) c;
    m->instr = p;
    for (uint32_t i = 0; i < c; i++) {                                  /* walk them once to check the bounds */
        if (p >= end) return SOL_ERR_PARSE;
        p++;                                                            /* program id index */
        if (cu16(&p, end, &k) || (size_t) (end - p) < k) return SOL_ERR_PARSE;
        p += k;
        if (cu16(&p, end, &k) || (size_t) (end - p) < k) return SOL_ERR_PARSE;
        p += k;
    }
    if (m->version) {                                                   /* address table lookups */
        if (cu16(&p, end, &c)) return SOL_ERR_PARSE;
        for (uint32_t i = 0; i < c; i++) {
            if (end - p < 32) return SOL_ERR_PARSE;
            p += 32;
            for (int w = 0; w < 2; w++) {
                if (cu16(&p, end, &k) || (size_t) (end - p) < k) return SOL_ERR_PARSE;
                p += k;
            }
        }
    }
    if (p != end) return SOL_ERR_PARSE;
    return SOL_OK;
}

static void b58(char *out, size_t cap, const uint8_t *k)
{
    if (base58_encode(k, 32, out, cap) < 0) out[0] = 0;
}

static uint32_t rd32(const uint8_t *p) { return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24; }

enum { P_SYSTEM, P_TOKEN, P_TOKEN22, P_BUDGET, P_MEMO, P_ATA, P_OTHER };

static int program_kind(const uint8_t *key)
{
    char s[48];
    int zero = 1;
    for (int i = 0; i < 32; i++) if (key[i]) { zero = 0; break; }
    if (zero) return P_SYSTEM;
    b58(s, sizeof s, key);
    if (!strcmp(s, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")) return P_TOKEN;
    if (!strcmp(s, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")) return P_TOKEN22;
    if (!strcmp(s, "ComputeBudget111111111111111111111111111111")) return P_BUDGET;
    if (!strcmp(s, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") || !strcmp(s, "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")) return P_MEMO;
    if (!strcmp(s, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")) return P_ATA;
    return P_OTHER;
}

int solana_summary(const uint8_t *msg, size_t len, tx_view *v)
{
    sol_msg m;
    int e = sol_parse(&m, msg, len);
    const uint8_t *p;
    uint64_t sent = 0, price = 0;
    uint32_t units = 0;
    char line[96], a[48], amt[64];
    int have_units = 0, nother = 0;

    txv_clear(v);
    if (e) return e;
    strcpy(v->title, T(TXT_SOLANA_TRANSACTION));
    p = m.instr;
    for (int i = 0; i < m.ninstr; i++) {
        uint32_t na = 0, nd = 0;
        const uint8_t *idx, *data;
        int pid = *p++, kind;
        cu16(&p, m.end, &na); idx = p; p += na;
        cu16(&p, m.end, &nd); data = p; p += nd;
        if (pid >= m.nacc) { v->warn |= TXW_UNKNOWN_SCRIPT | TXW_BLIND; nother++; continue; }
        kind = program_kind(m.acc + 32 * pid);
        if (kind == P_SYSTEM && nd == 12 && rd32(data) == 2 && na >= 2 && idx[1] < m.nacc) {
            uint64_t l = rd64(data + 4);
            b58(a, sizeof a, m.acc + 32 * idx[1]);
            txv_amount_u64(amt, sizeof amt, l, 9, "SOL");
            txv_add_out(v, a, amt);
            sent += l;
        } else if ((kind == P_TOKEN || kind == P_TOKEN22) && ((nd == 9 && data[0] == 3 && na >= 3) || (nd == 10 && data[0] == 12 && na >= 4))) {
            int checked = data[0] == 12;
            int di = checked ? 2 : 1;
            if (idx[di] < m.nacc) {
                b58(a, sizeof a, m.acc + 32 * idx[di]);
                if (checked) {
                    txv_amount_u64(amt, sizeof amt, rd64(data + 1), data[9], NULL);
                    strcat(amt, T(TXT_TOKEN));
                } else {
                    txv_amount_u64(amt, sizeof amt, rd64(data + 1), 0, NULL);
                    strcat(amt, T(TXT_TOKEN_UNITS));
                }
                txv_add_out(v, a, amt);
                if (checked && idx[1] < m.nacc) { b58(a, sizeof a, m.acc + 32 * idx[1]); snprintf(line, sizeof line, T(TXT_TOKEN_MINT_N), a); txv_note(v, line); }
                v->warn |= TXW_DATA;
            }
        } else if (kind == P_BUDGET && nd >= 5 && data[0] == 2) { units = rd32(data + 1); have_units = 1; }
        else if (kind == P_BUDGET && nd == 9 && data[0] == 3) price = rd64(data + 1);
        else if (kind == P_BUDGET) { }
        else if (kind == P_MEMO) {
            char memo[64];
            size_t n = nd < sizeof memo - 1 ? nd : sizeof memo - 1;
            for (size_t k = 0; k < n; k++) memo[k] = (data[k] >= 0x20 && data[k] < 0x7f) ? (char) data[k] : '?';
            memo[n] = 0;
            snprintf(line, sizeof line, T(TXT_MEMO_N), memo);
            txv_note(v, line);
        } else if (kind == P_ATA) {
            txv_note(v, T(TXT_CREATES_A_TOKEN_ACCOUNT));
        } else {
            b58(a, sizeof a, m.acc + 32 * pid);
            snprintf(line, sizeof line, T(TXT_PROGRAM_N), a);
            snprintf(amt, sizeof amt, T(TXT_INSTRUCTION_N_BYTES_OF_DATA), (unsigned) nd);
            txv_add_out(v, line, amt);
            v->warn |= TXW_DATA | TXW_BLIND;
            nother++;
        }
    }
    if (!v->nout) { txv_add_out(v, T(TXT_NO_TRANSFER), ""); }
    if (sent) txv_amount_u64(v->total, sizeof v->total, sent, 9, "SOL");
    {
        uint64_t fee = 5000ull * (uint64_t) m.nsig;
        if (price) {
            uint64_t u = have_units ? units : 200000u * (uint64_t) (m.ninstr > 0 ? m.ninstr : 1);
            fee += (u * price + 999999u) / 1000000u;
            snprintf(line, sizeof line, T(TXT_PRIORITY_FEE_N_MICRO_LAMPORTS), (unsigned long long) price, (unsigned long long) u);
            txv_note(v, line);
        }
        txv_amount_u64(v->fee, sizeof v->fee, fee, 9, "SOL");
    }
    if (m.version) { txv_note(v, T(TXT_VERSION_0_MESSAGE_SOME)); }
    (void) nother;
    return SOL_OK;
}

int solana_sign(const uint8_t *msg, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t *tx, size_t cap, size_t *txlen)
{
    sol_msg m;
    uint8_t pub[32];
    int e = sol_parse(&m, msg, len), slot = -1;

    if (e) return e;
    ed25519_pubkey_from_seed(pub, seed);
    for (int i = 0; i < m.nsig; i++) if (!memcmp(m.acc + 32 * i, pub, 32)) { slot = i; break; }
    if (slot < 0) return SOL_ERR_NOT_SIGNER;
    ed25519_sign(sig, seed, msg, len);
    if (tx) {
        size_t need = 1 + 64 * (size_t) m.nsig + len;
        if (m.nsig > 127 || need > cap) return SOL_ERR_SPACE;
        tx[0] = (uint8_t) m.nsig;
        memset(tx + 1, 0, 64 * (size_t) m.nsig);
        memcpy(tx + 1 + 64 * (size_t) slot, sig, 64);
        memcpy(tx + 1 + 64 * (size_t) m.nsig, msg, len);
        *txlen = need;
    }
    return SOL_OK;
}
