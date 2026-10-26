/* Ethereum / EVM transactions: RLP parser, summary for the screen, EIP-155 / EIP-2930 / EIP-1559 signing, EIP-191 and EIP-712 hashes. */
#include "sign/evm.h"
#include <stdio.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "hash/keccak.h"
#include "util.h"
#include "tr.h"

/* ---- RLP ---- */

typedef struct {
    const uint8_t *raw;  size_t rawlen;      /* the whole encoding of the item */
    const uint8_t *data; size_t len;         /* the payload */
    int            list;
} rlp_item;

static int rlp_next(const uint8_t **pp, const uint8_t *end, rlp_item *it)
{
    const uint8_t *p = *pp;
    size_t hl = 1, len, avail = (size_t) (end - p);
    uint8_t b;

    if (!avail) return -1;
    b = *p;
    it->list = b >= 0xc0;
    if (b < 0x80) { len = 1; hl = 0; }
    else if (b <= 0xb7) len = (size_t) (b - 0x80);
    else if (b <= 0xbf || (b >= 0xf8)) {
        size_t ll = b <= 0xbf ? (size_t) (b - 0xb7) : (size_t) (b - 0xf7);
        if (ll > 4 || avail < 1 + ll || p[1] == 0) return -1;      /* a length with a leading zero is not canonical */
        len = 0;
        for (size_t i = 0; i < ll; i++) len = (len << 8) | p[1 + i];
        if (len < 56) return -1;
        hl = 1 + ll;
    } else len = (size_t) (b - 0xc0);
    if (len > avail - hl) return -1;
    if (b > 0x80 && b <= 0xb7 && len == 1 && p[1] < 0x80) return -1; /* a single small byte must stand for itself */
    it->raw = p;
    it->rawlen = hl + len;
    it->data = p + hl;
    it->len = len;
    *pp = p + hl + len;
    return 0;
}

#define MAXF 12

typedef struct {
    int      type;                 /* 0 legacy, 1 EIP-2930, 2 EIP-1559, 4 EIP-7702 (set code) */
    rlp_item f[MAXF];
    int      nf;
    int      has_chain;
    uint64_t chain;
    rlp_item *nonce, *price, *gas, *to, *value, *data;
} evm_tx;

static int num_ok(const rlp_item *it, size_t max)
{
    return !it->list && it->len <= max && (it->len == 0 || it->data[0] != 0);
}

static uint64_t num_u64(const rlp_item *it)
{
    uint64_t v = 0;
    for (size_t i = 0; i < it->len; i++) v = (v << 8) | it->data[i];
    return v;
}

static int evm_parse(evm_tx *t, const uint8_t *tx, size_t len)
{
    const uint8_t *p = tx, *end = tx + len, *q;
    rlp_item top;

    memset(t, 0, sizeof *t);
    if (!len) return EVM_ERR_PARSE;
    if (tx[0] >= 0xc0) t->type = 0;
    else if (tx[0] == 0x01 || tx[0] == 0x02 || tx[0] == 0x04) { t->type = tx[0]; p++; }
    else if (tx[0] == 0x03) return EVM_ERR_UNSUPPORTED;                      /* blob transactions */
    else return EVM_ERR_PARSE;
    if (rlp_next(&p, end, &top) || !top.list || p != end) return EVM_ERR_PARSE;
    q = top.data;
    while (q < top.data + top.len) {
        if (t->nf >= MAXF || rlp_next(&q, top.data + top.len, &t->f[t->nf])) return EVM_ERR_PARSE;
        t->nf++;
    }
    switch (t->type) {
    case 0:
        if (t->nf != 6 && t->nf != 9) return EVM_ERR_PARSE;
        t->nonce = &t->f[0]; t->price = &t->f[1]; t->gas = &t->f[2]; t->to = &t->f[3]; t->value = &t->f[4]; t->data = &t->f[5];
        if (t->nf == 9) {                                              /* EIP-155: chain id, 0, 0 */
            if (t->f[7].list || t->f[7].len || t->f[8].list || t->f[8].len || !num_ok(&t->f[6], 8) || !t->f[6].len) return EVM_ERR_PARSE;
            t->has_chain = 1;
            t->chain = num_u64(&t->f[6]);
        }
        break;
    case 1:
        if (t->nf != 8 || !t->f[7].list) return EVM_ERR_PARSE;
        t->nonce = &t->f[1]; t->price = &t->f[2]; t->gas = &t->f[3]; t->to = &t->f[4]; t->value = &t->f[5]; t->data = &t->f[6];
        if (!num_ok(&t->f[0], 8)) return EVM_ERR_PARSE;
        t->has_chain = 1; t->chain = num_u64(&t->f[0]);
        break;
    default:                                                            /* 2 and 4: EIP-7702 is EIP-1559 plus the authorization list */
        if (t->nf != (t->type == 4 ? 10 : 9) || !t->f[8].list || !num_ok(&t->f[2], 32)) return EVM_ERR_PARSE;     /* priority fee: checked, not shown */
        if (t->type == 4 && (!t->f[9].list || !t->f[9].len)) return EVM_ERR_PARSE;                                /* the list may not be empty */
        t->nonce = &t->f[1]; t->price = &t->f[3]; t->gas = &t->f[4]; t->to = &t->f[5]; t->value = &t->f[6]; t->data = &t->f[7];
        if (!num_ok(&t->f[0], 8)) return EVM_ERR_PARSE;
        t->has_chain = 1; t->chain = num_u64(&t->f[0]);
        break;
    }
    if (!num_ok(t->nonce, 8) || !num_ok(t->price, 32) || !num_ok(t->gas, 8) || !num_ok(t->value, 32)) return EVM_ERR_PARSE;
    if (t->to->list || (t->to->len != 0 && t->to->len != 20) || t->data->list) return EVM_ERR_PARSE;
    if (t->type == 4 && t->to->len != 20) return EVM_ERR_PARSE;                                              /* a set-code transaction has a destination */
    return EVM_OK;
}

/* ---- EIP-7702 authorizations: [chain_id, address, nonce] (signed: + y_parity, r, s) ---- */

typedef struct {
    int      chain_zero, chain_big;    /* chain id 0 (valid on every chain), or too big for 64 bits */
    uint64_t chain, nonce;
    const uint8_t *addr;
} evm_auth;

static int auth_fields(evm_auth *a, const rlp_item *chain, const rlp_item *addr, const rlp_item *nonce)
{
    if (!num_ok(chain, 32) || addr->list || addr->len != 20 || !num_ok(nonce, 8)) return -1;
    a->chain_zero = chain->len == 0;
    a->chain_big = chain->len > 8;
    a->chain = a->chain_big ? 0 : num_u64(chain);
    a->nonce = num_u64(nonce);
    a->addr = addr->data;
    return 0;
}

/* the two lines that say what an authorization does: where the code of the account will point, and for which chain */
static void auth_text(char *to, size_t tocap, char *amount, size_t amcap, const evm_auth *a)
{
    static const uint8_t ZERO[20];
    char hex[43];

    if (!memcmp(a->addr, ZERO, 20)) snprintf(to, tocap, T(TXT_CLEARS_THE_DELEGATION_ADDRESS));
    else { evm_checksum_address(hex, a->addr); snprintf(to, tocap, T(TXT_DELEGATE_TO_N), hex); }
    if (a->chain_zero) snprintf(amount, amcap, T(TXT_EVERY_CHAIN_ID_0_NONCE_N), (unsigned long long) a->nonce);
    else if (a->chain_big) snprintf(amount, amcap, T(TXT_CHAIN_ID_ABOVE_2_64_NONCE_N), (unsigned long long) a->nonce);
    else snprintf(amount, amcap, T(TXT_CHAIN_ID_N_NONCE_N), (unsigned long long) a->chain, (unsigned long long) a->nonce);
}

/* ---- text ---- */

void evm_checksum_address(char out[43], const uint8_t a[20])
{
    static const char HX[] = "0123456789abcdef";
    char lower[40];
    uint8_t h[32];
    for (int i = 0; i < 20; i++) { lower[2 * i] = HX[a[i] >> 4]; lower[2 * i + 1] = HX[a[i] & 15]; }
    keccak256((const uint8_t *) lower, 40, h);
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < 40; i++) {
        char c = lower[i];
        int nib = (h[i >> 1] >> ((i & 1) ? 0 : 4)) & 15;
        if (c >= 'a' && nib >= 8) c = (char) (c - 32);
        out[2 + i] = c;
    }
    out[42] = 0;
}

static const struct { uint64_t id; const char *name, *sym; } CHAINS_EVM[] = {
    {1, "Ethereum", "ETH"}, {10, "Optimism", "ETH"}, {56, "BNB Chain", "BNB"}, {61, "Ethereum Classic", "ETC"}, {100, "Gnosis", "xDAI"},
    {137, "Polygon", "POL"}, {250, "Fantom", "FTM"}, {324, "zkSync Era", "ETH"}, {8453, "Base", "ETH"}, {42161, "Arbitrum One", "ETH"},
    {43114, "Avalanche C", "AVAX"}, {59144, "Linea", "ETH"}, {534352, "Scroll", "ETH"}, {17000, "Holesky", "ETH"}, {11155111, "Sepolia", "ETH"},
};

static void chain_names(const evm_tx *t, char *name, size_t ncap, const char **sym)
{
    *sym = "native";
    if (!t->has_chain) { snprintf(name, ncap, "EVM"); return; }
    for (size_t i = 0; i < sizeof CHAINS_EVM / sizeof CHAINS_EVM[0]; i++)
        if (CHAINS_EVM[i].id == t->chain) { snprintf(name, ncap, "%s", CHAINS_EVM[i].name); *sym = CHAINS_EVM[i].sym; return; }
    snprintf(name, ncap, T(TXT_CHAIN_N), (unsigned long long) t->chain);
}

/* gas * price as 32 bytes big endian; returns 0, or -1 if it does not fit */
static int mul_gas(uint8_t out[32], uint64_t gas, const rlp_item *price)
{
    uint32_t a[8] = {0}, r[10] = {0};
    uint64_t g[2] = {gas & 0xffffffffu, gas >> 32};
    for (size_t i = 0; i < price->len; i++) {                          /* big endian bytes -> little endian limbs */
        size_t bit = (price->len - 1 - i);
        a[bit / 4] |= (uint32_t) price->data[i] << (8 * (bit % 4));
    }
    for (int j = 0; j < 2; j++) {
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t cur = (uint64_t) r[i + j] + (uint64_t) a[i] * g[j] + carry;
            r[i + j] = (uint32_t) cur;
            carry = cur >> 32;
        }
        for (int k = 8 + j; carry && k < 10; k++) {
            uint64_t cur = (uint64_t) r[k] + carry;
            r[k] = (uint32_t) cur;
            carry = cur >> 32;
        }
    }
    if (r[8] || r[9]) return -1;
    for (int i = 0; i < 8; i++)
        for (int b = 0; b < 4; b++) out[31 - (4 * i + b)] = (uint8_t) (r[i] >> (8 * b));
    return 0;
}

static void hexn(char *out, const uint8_t *d, size_t n)
{
    static const char HX[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = HX[d[i] >> 4]; out[2 * i + 1] = HX[d[i] & 15]; }
    out[2 * n] = 0;
}

int evm_summary(const uint8_t *tx, size_t len, tx_view *v)
{
    evm_tx t;
    char name[30], line[96];
    const char *sym;
    uint8_t fee[32];
    int e = evm_parse(&t, tx, len);
    txv_out *o;

    txv_clear(v);
    if (e) return e;
    chain_names(&t, name, sizeof name, &sym);
    snprintf(v->title, sizeof v->title, t.type == 4 ? T(TXT_N_TRANSACTION_EIP_7702) : T(TXT_N_TRANSACTION), name);
    v->nout = 1;
    o = &v->out[0];
    if (t.to->len == 0) {
        strcpy(o->to, T(TXT_CONTRACT_CREATION));
        v->warn |= TXW_DATA;
    } else {
        evm_checksum_address(o->to, t.to->data);
    }
    txv_amount_be(o->amount, sizeof o->amount, t.value->data, t.value->len, 18, sym);
    txv_amount_be(v->total, sizeof v->total, t.value->data, t.value->len, 18, sym);

    if (t.data->len) {
        const char *const NAMES[] = {T(TXT_ERC_20_TRANSFER), T(TXT_ERC_20_APPROVE), T(TXT_ERC_20_TRANSFERFROM)};
        uint32_t sel = t.data->len >= 4 ? ((uint32_t) t.data->data[0] << 24 | (uint32_t) t.data->data[1] << 16 | (uint32_t) t.data->data[2] << 8 | t.data->data[3]) : 0;
        const uint8_t *d = t.data->data + 4;
        int kind = -1;
        v->warn |= TXW_DATA;
        if (sel == 0xa9059cbbu && t.data->len == 68) kind = 0;
        else if (sel == 0x095ea7b3u && t.data->len == 68) kind = 1;
        else if (sel == 0x23b872ddu && t.data->len == 100) kind = 2;
        if (kind >= 0) {
            static const uint8_t ALLF[32] = {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
                                             255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
            const uint8_t *who = d + (kind == 2 ? 32 : 0), *amt = d + (kind == 2 ? 64 : 32);
            char a[43], tok[43];
            evm_checksum_address(tok, t.to->data);
            evm_checksum_address(a, who + 12);
            snprintf(o->to, sizeof o->to, "%s %s", kind == 1 ? "spender" : "to", a);
            if (!memcmp(amt, ALLF, 32)) strcpy(o->amount, T(TXT_UNLIMITED_TOKEN_UNITS));
            else { int n = txv_amount_be(o->amount, sizeof o->amount - 14, amt, 32, 0, NULL); if (n > 0) strcat(o->amount, T(TXT_TOKEN_UNITS)); }
            snprintf(line, sizeof line, T(TXT_N_TOKEN_CONTRACT_N), NAMES[kind], tok);
            txv_note(v, line);
            if (kind == 2) { evm_checksum_address(a, d + 12); snprintf(line, sizeof line, T(TXT_FROM_N), a); txv_note(v, line); }
            v->total[0] = 0;
        } else {
            snprintf(line, sizeof line, T(TXT_CONTRACT_CALL_N_BYTES_OF_DATA), (unsigned) sel, (unsigned) t.data->len);
            txv_note(v, line);
        }
    }
    if (!mul_gas(fee, num_u64(t.gas), t.price)) txv_amount_be(v->fee, sizeof v->fee, fee, 32, 18, sym);
    else v->warn |= TXW_NO_FEE;
    snprintf(line, sizeof line, T(TXT_NONCE_N_GAS_LIMIT_N), (unsigned long long) num_u64(t.nonce), (unsigned long long) num_u64(t.gas),
             t.type >= 2 ? T(TXT_FEE_MAX_FEE) : "");
    txv_note(v, line);
    if (!t.has_chain) txv_note(v, T(TXT_NO_CHAIN_ID_THE_SIGNATURE));
    else { snprintf(line, sizeof line, T(TXT_CHAIN_ID_N), (unsigned long long) t.chain); txv_note(v, line); }
    if (t.type == 4) {                                                  /* every signed authorization sets the code of an account: list them all */
        const uint8_t *q = t.f[9].data, *end = t.f[9].data + t.f[9].len;
        rlp_item it, g[6];
        v->warn |= TXW_DELEGATION;
        while (q < end) {
            const uint8_t *r;
            evm_auth a;
            int n = 0;
            if (rlp_next(&q, end, &it) || !it.list) return EVM_ERR_PARSE;
            r = it.data;
            while (r < it.data + it.len) { if (n >= 6 || rlp_next(&r, it.data + it.len, &g[n])) return EVM_ERR_PARSE; n++; }
            if (n != 6 || auth_fields(&a, &g[0], &g[1], &g[2]) || !num_ok(&g[3], 1) || !num_ok(&g[4], 32) || !num_ok(&g[5], 32)) return EVM_ERR_PARSE;
            if (v->nout < TXV_OUTS) { auth_text(v->out[v->nout].to, sizeof v->out[0].to, v->out[v->nout].amount, sizeof v->out[0].amount, &a); v->nout++; }
            else { v->nmore++; v->warn |= TXW_TRUNCATED; }
        }
    }
    return EVM_OK;
}

/* ---- signing ---- */

static size_t rlp_header(uint8_t *o, size_t len, int list)
{
    uint8_t base = list ? 0xc0 : 0x80;
    if (len < 56) { o[0] = (uint8_t) (base + len); return 1; }
    if (len < 256) { o[0] = (uint8_t) (base + 55 + 1); o[1] = (uint8_t) len; return 2; }
    o[0] = (uint8_t) (base + 55 + 2); o[1] = (uint8_t) (len >> 8); o[2] = (uint8_t) len;
    return 3;
}

/* RLP of an integer given as bytes (leading zeros cut) */
static size_t rlp_int(uint8_t *o, const uint8_t *be, size_t n)
{
    size_t skip = 0;
    while (skip < n && be[skip] == 0) skip++;
    n -= skip;
    if (n == 1 && be[skip] < 0x80) { o[0] = be[skip]; return 1; }
    size_t h = rlp_header(o, n, 0);
    memcpy(o + h, be + skip, n);
    return h + n;
}

int evm_sign_tx(const uint8_t *tx, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap, size_t *outlen, uint8_t sig65[65])
{
    evm_tx t;
    uint8_t h[32], sig[64], vbytes[9], enc[3 * 40];
    int rec, e = evm_parse(&t, tx, len), nkeep;
    size_t payload = 0, pos = 0, vl, el;
    uint8_t hdr[4];

    if (e) return e;
    keccak256(tx, len, h);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, h)) return EVM_ERR_KEY;
    rec &= 1;
    if (sig65) { memcpy(sig65, sig, 64); sig65[64] = (uint8_t) rec; }
    nkeep = t.type == 0 ? 6 : t.nf;                                   /* legacy: the first six fields, then v r s */
    for (int i = 0; i < nkeep; i++) payload += t.f[i].rawlen;
    if (t.type == 0) {
        uint64_t v;
        if (t.has_chain) {
            if (t.chain > 0x7fffffffffffffull) return EVM_ERR_UNSUPPORTED;
            v = t.chain * 2 + 35 + (uint64_t) rec;
        } else v = 27 + (uint64_t) rec;
        for (int i = 0; i < 8; i++) vbytes[i] = (uint8_t) (v >> (56 - 8 * i));
        vl = rlp_int(enc, vbytes, 8);
    } else {
        vbytes[0] = (uint8_t) rec;
        vl = rlp_int(enc, vbytes, 1);
    }
    el = vl;
    el += rlp_int(enc + el, sig, 32);
    el += rlp_int(enc + el, sig + 32, 32);
    payload += el;
    {
        size_t hl = rlp_header(hdr, payload, 1);
        if (hl + payload + (t.type ? 1 : 0) > cap) return EVM_ERR_SPACE;
        if (t.type) out[pos++] = (uint8_t) t.type;
        memcpy(out + pos, hdr, hl); pos += hl;
        for (int i = 0; i < nkeep; i++) { memcpy(out + pos, t.f[i].raw, t.f[i].rawlen); pos += t.f[i].rawlen; }
        memcpy(out + pos, enc, el); pos += el;
    }
    *outlen = pos;
    return EVM_OK;
}

/* ---- the authorization alone (EIP-7702): the signature that delegates the signer's own account ---- */

static int auth_parse(evm_auth *a, const uint8_t *pl, size_t len)
{
    const uint8_t *p = pl, *q;
    rlp_item top, g[3];
    int n = 0;

    if (rlp_next(&p, pl + len, &top) || !top.list || p != pl + len) return EVM_ERR_PARSE;
    q = top.data;
    while (q < top.data + top.len) { if (n >= 3 || rlp_next(&q, top.data + top.len, &g[n])) return EVM_ERR_PARSE; n++; }
    if (n != 3 || auth_fields(a, &g[0], &g[1], &g[2])) return EVM_ERR_PARSE;
    return EVM_OK;
}

int evm_auth_summary(const uint8_t *pl, size_t len, tx_view *v)
{
    evm_auth a;
    int e = auth_parse(&a, pl, len);

    txv_clear(v);
    if (e) return e;
    strcpy(v->title, T(TXT_DELEGATE_THIS_ACCOUNT_EIP_7702));
    v->nout = 1;
    auth_text(v->out[0].to, sizeof v->out[0].to, v->out[0].amount, sizeof v->out[0].amount, &a);
    v->warn |= TXW_DELEGATION;
    txv_note(v, T(TXT_HANDS_THE_CODE_OF_YOUR_ACCOUNT));
    txv_note(v, T(TXT_ANYONE_WHO_SENDS_IT_IN_A));
    return EVM_OK;
}

int evm_auth_sign(const uint8_t *pl, size_t len, const uint8_t priv[32], uint8_t sig65[65])
{
    static uint8_t buf[160];
    evm_auth a;
    uint8_t h[32], sig[64];
    int rec;

    if (auth_parse(&a, pl, len) || len > sizeof buf - 1) return EVM_ERR_PARSE;
    buf[0] = 0x05;                                                      /* MAGIC */
    memcpy(buf + 1, pl, len);
    keccak256(buf, len + 1, h);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, h)) return EVM_ERR_KEY;
    memcpy(sig65, sig, 64);
    sig65[64] = (uint8_t) (rec & 1);                                    /* y_parity */
    return EVM_OK;
}

/* ---- messages ---- */

void evm_message_summary(const uint8_t *msg, size_t len, tx_view *v)
{
    char line[64];
    int text = 1;

    txv_clear(v);
    strcpy(v->title, T(TXT_SIGN_MESSAGE_EIP_191));
    for (size_t i = 0; i < len; i++) if (!((msg[i] >= 0x20 && msg[i] < 0x7f) || msg[i] == '\n')) { text = 0; break; }
    v->nout = 1;
    if (text) {
        size_t n = len < sizeof v->out[0].to - 1 ? len : sizeof v->out[0].to - 1;
        memcpy(v->out[0].to, msg, n);
        v->out[0].to[n] = 0;
    } else {
        size_t n = len < 40 ? len : 40;
        hexn(v->out[0].to, msg, n);
        v->warn |= TXW_DATA;
    }
    snprintf(line, sizeof line, T(TXT_N_BYTES_N), (unsigned) len, text ? "" : T(TXT_BINARY_SHOWN_IN_HEX));
    txv_note(v, line);
}

int evm_personal_sign(const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t sig65[65])
{
    static const char P[] = "\x19" "Ethereum Signed Message:\n";
    uint8_t h[32], sig[64];
    char num[12];
    size_t pl = sizeof P - 1, nl = 0, tmp = len;
    int rec;
    /* Keccak over prefix || length || message without a second buffer: absorb in one piece through a small struct */
    static uint8_t buf[2048];
    if (len > sizeof buf - 40) return EVM_ERR_SPACE;
    do { num[nl++] = (char) ('0' + tmp % 10); tmp /= 10; } while (tmp);
    memcpy(buf, P, pl);
    for (size_t i = 0; i < nl; i++) buf[pl + i] = (uint8_t) num[nl - 1 - i];
    memcpy(buf + pl + nl, msg, len);
    keccak256(buf, pl + nl + len, h);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, h)) return EVM_ERR_KEY;
    memcpy(sig65, sig, 64);
    sig65[64] = (uint8_t) (27 + (rec & 1));
    return EVM_OK;
}

void evm_typed_summary(tx_view *v)
{
    txv_clear(v);
    strcpy(v->title, T(TXT_SIGN_TYPED_DATA_EIP_712));
    v->warn |= TXW_BLIND;
    txv_note(v, T(TXT_ONLY_THE_TWO_HASHES_ARE_KNOWN));
}

int evm_typed_sign(const uint8_t domain[32], const uint8_t struct_hash[32], const uint8_t priv[32], uint8_t sig65[65])
{
    uint8_t buf[66], h[32], sig[64];
    int rec;
    buf[0] = 0x19; buf[1] = 0x01;
    memcpy(buf + 2, domain, 32);
    memcpy(buf + 34, struct_hash, 32);
    keccak256(buf, 66, h);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, h)) return EVM_ERR_KEY;
    memcpy(sig65, sig, 64);
    sig65[64] = (uint8_t) (27 + (rec & 1));
    return EVM_OK;
}
