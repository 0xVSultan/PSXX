#include "sign/dispatch.h"
#include <string.h>
#include "coin/bip32.h"
#include "coin/orchard.h"
#include "coin/path.h"
#include "coin/substrate.h"
#include "sign/ada.h"
#include "sign/btc.h"
#include "sign/btcmsg.h"
#include "b64.h"
#include "sign/cosmos.h"
#include "sign/evm.h"
#include "sign/kaspa.h"
#include "sign/near.h"
#include "sign/nostr.h"
#include "sign/polkadot.h"
#include "sign/solana.h"
#include "sign/stellar.h"
#include "sign/ton.h"
#include "sign/tron.h"
#include "sign/xrp.h"
#include "sign/xmr.h"
#include "sign/zec.h"
#include "util.h"
#include "tr.h"

static const chain_def XMR_DEF = {"xmr", TXT_MONERO, CV_ED25519, K_MONERO, 0, NULL, "", 3};

int sign_req_parse(sign_req *q, const uint8_t *b, size_t n)
{
    char id[9];
    size_t pl, o;
    uint32_t plen;

    memset(q, 0, sizeof *q);
    if (n < 4 + 1 + 1 + 8 + 1 || memcmp(b, "PSXQ", 4) || b[4] != 1) return SIGN_ERR_FORMAT;
    q->kind = b[5];
    if (q->kind > SREQ_AUTH) return SIGN_ERR_KIND;
    memcpy(id, b + 6, 8);
    id[8] = 0;
    q->chain = chain_find(id);
    if (!q->chain && !strcmp(id, "xmr")) q->chain = &XMR_DEF;
    pl = b[14];
    o = 15;
    if (pl >= sizeof q->path || n < o + pl + 4) return SIGN_ERR_FORMAT;
    memcpy(q->path, b + o, pl);
    q->path[pl] = 0;
    o += pl;
    plen = (uint32_t) b[o] | (uint32_t) b[o + 1] << 8 | (uint32_t) b[o + 2] << 16 | (uint32_t) b[o + 3] << 24;
    o += 4;
    if (n - o != plen) return SIGN_ERR_FORMAT;
    q->payload = b + o;
    q->plen = plen;
    return q->chain ? SIGN_OK : SIGN_ERR_CHAIN;
}

const char *sign_error_text(int e)
{
    switch (e) {
    case SIGN_ERR_FORMAT: return T(TXT_NOT_A_SIGNING_REQUEST);
    case SIGN_ERR_CHAIN: return T(TXT_UNKNOWN_COIN);
    case SIGN_ERR_PATH: return T(TXT_BAD_PATH);
    case SIGN_ERR_KIND: return T(TXT_NOT_POSSIBLE_FOR_THIS_COIN);
    case SIGN_ERR_PARSE: return T(TXT_THE_TRANSACTION_IS_NOT_VALID);
    case SIGN_ERR_KEY: return T(TXT_THE_KEY_DOES_NOT_FIT_THE);
    case SIGN_ERR_NOTMINE: return T(TXT_NOTHING_IN_IT_BELONGS_TO_THIS);
    case SIGN_ERR_SPACE: return T(TXT_TOO_BIG);
    case SIGN_ERR_UNSUPPORTED: return T(TXT_NOT_SUPPORTED_HERE);
    case SIGN_ERR_UTXO: return T(TXT_PREVIOUS_TRANSACTION_MISSING);
    case SIGN_ERR_MISMATCH: return T(TXT_THE_OUTPUTS_OR_AMOUNTS_DO_NOT);
    case SIGN_ERR_NOSEED: return T(TXT_THAT_SEED_IS_NOT_LOADED_LOAD);
    case SIGN_ERR_MSGSIZE: return T(TXT_THE_MESSAGE_IS_OVER_4096_BYTES_TOO);
    default: return T(TXT_ERROR_2);
    }
}

static int map_btc(int e)
{
    switch (e) {
    case BTC_OK: return SIGN_OK;
    case BTC_ERR_PARSE: return SIGN_ERR_PARSE;
    case BTC_ERR_UNSUPPORTED: return SIGN_ERR_UNSUPPORTED;
    case BTC_ERR_UTXO: return SIGN_ERR_UTXO;
    case BTC_ERR_SIGHASH: return SIGN_ERR_UNSUPPORTED;
    case BTC_ERR_NOKEY: return SIGN_ERR_NOTMINE;
    case BTC_ERR_SPACE: return SIGN_ERR_SPACE;
    default: return SIGN_ERR_KEY;
    }
}

static int map_zec(int e)
{
    switch (e) {
    case ZEC_OK: return SIGN_OK;
    case ZEC_ERR_PARSE: return SIGN_ERR_PARSE;
    case ZEC_ERR_UNSUPPORTED: return SIGN_ERR_UNSUPPORTED;
    case ZEC_ERR_NOKEY: return SIGN_ERR_NOTMINE;
    case ZEC_ERR_SPACE: return SIGN_ERR_SPACE;
    case ZEC_ERR_MISMATCH: return SIGN_ERR_MISMATCH;
    default: return SIGN_ERR_KEY;
    }
}

static int map_xmr(int e)
{
    switch (e) {
    case XMR_OK: return SIGN_OK;
    case XMR_ERR_UNSUPPORTED: return SIGN_ERR_UNSUPPORTED;
    case XMR_ERR_KEY: return SIGN_ERR_KEY;
    case XMR_ERR_AMOUNT: case XMR_ERR_OUTPUT: case XMR_ERR_BALANCE: return SIGN_ERR_MISMATCH;
    case XMR_ERR_SPACE: return SIGN_ERR_SPACE;
    default: return SIGN_ERR_PARSE;
    }
}

/* the usual error of a module whose only failures are "bad payload", "wrong key", "no space": negative = parse unless it is key / space */
static int map_generic(int e, int key_code, int space_code)
{
    if (e == 0) return SIGN_OK;
    if (e == key_code) return SIGN_ERR_KEY;
    if (e == space_code) return SIGN_ERR_SPACE;
    return SIGN_ERR_PARSE;
}

/* Nostr: the usual three, and a message over the limit of the encryption */
static int map_nostr(int e)
{
    return e == NOSTR_ERR_SIZE ? SIGN_ERR_MSGSIZE : map_generic(e, NOSTR_ERR_KEY, NOSTR_ERR_SPACE);
}

/* the Orchard spending key (ZIP-32) of the account named by the request path, m/32'/133'/account' */
static int orchard_sk_for(uint8_t sk[32], const sign_req *q, const hd_secret *s)
{
    hd_path p;
    uint8_t chain[32];
    if (s->raw_curve == 4) { memcpy(sk, s->raw, 32); return SIGN_OK; }                    /* a spending key as given */
    if (path_parse(&p, q->path) || !p.n || !path_all_hardened(&p)) return SIGN_ERR_PATH;
    orchard_master(sk, chain, s->seed, 64);
    for (int i = 0; i < p.n; i++) orchard_child(sk, chain, p.idx[i]);
    secure_zero(chain, sizeof chain);
    return SIGN_OK;
}

/* Kaspa: the account path of the request plus (change, index) of an input or output; a raw key has no path */
typedef struct { const hd_secret *s; const chain_def *c; hd_path acct; } kas_ctx;

static int kas_key(void *vctx, uint32_t change, uint32_t index, uint8_t key[32])
{
    kas_ctx *k = vctx;
    hd_path p = k->acct;
    uint8_t full[96];
    int r;

    if (!k->s->raw_curve) {
        if (p.n + 2 > PATH_MAX_DEPTH || change > 0x7fffffffu || index > 0x7fffffffu) return -1;
        p.idx[p.n++] = change;
        p.idx[p.n++] = index;
    }
    r = chain_signing_key(full, k->c, k->s, &p, NULL);
    if (r != 32) { secure_zero(full, sizeof full); return -1; }
    memcpy(key, full, 32);
    secure_zero(full, sizeof full);
    return 0;
}

static int kas_setup(kas_ctx *k, const sign_req *q, const hd_secret *s)
{
    memset(k, 0, sizeof *k);
    k->s = s;
    k->c = q->chain;
    if (s->raw_curve) return 0;
    return path_parse(&k->acct, q->path) ? SIGN_ERR_PATH : 0;
}

static int map_kas(int e)
{
    switch (e) {
    case KAS_OK: return SIGN_OK;
    case KAS_ERR_UNSUPPORTED: return SIGN_ERR_UNSUPPORTED;
    case KAS_ERR_KEY: return SIGN_ERR_KEY;
    case KAS_ERR_SPACE: return SIGN_ERR_SPACE;
    default: return SIGN_ERR_PARSE;
    }
}

/* the key of the request path */
static int key_for(uint8_t key[96], const sign_req *q, const hd_secret *s, int *klen)
{
    hd_path p;
    int r;
    memset(&p, 0, sizeof p);
    if (s->raw_curve && q->chain->curve != CV_SR25519) r = chain_signing_key(key, q->chain, s, &p, NULL);       /* a raw key has no path (sr25519: the junctions still apply) */
    else if (q->chain->curve == CV_SR25519) r = chain_signing_key(key, q->chain, s, &p, q->path);
    else {
        char first[48];
        const char *semi = strchr(q->path, ';');
        size_t n = semi ? (size_t) (semi - q->path) : strlen(q->path);
        if (n >= sizeof first) return SIGN_ERR_PATH;
        memcpy(first, q->path, n);
        first[n] = 0;
        if (path_parse(&p, first)) return SIGN_ERR_PATH;
        r = chain_signing_key(key, q->chain, s, &p, NULL);
    }
    if (r < 0) return r == CHAIN_ERR_PATH ? SIGN_ERR_PATH : SIGN_ERR_KEY;
    *klen = r;
    return SIGN_OK;
}

/* the node whose keys sign a Bitcoin family PSBT: the master of the seed, or, for a raw secp256k1 key, a node of depth 0 that holds the key (btc.h psbt_raw_key); btc_node_done clears both */
static int btc_node(bip32_node *m, const hd_secret *s)
{
    if (!s->raw_curve) return bip32_master(m, s->seed, 64);
    if (s->raw_curve != 2) return -1;
    memset(m, 0, sizeof *m);
    memcpy(m->key, s->raw, 32);
    return psbt_raw_key(s->raw) == BTC_OK ? 0 : -1;
}

static void btc_node_done(bip32_node *m)
{
    secure_zero(m, sizeof *m);
    psbt_raw_key(NULL);
}

int sign_summary(const sign_req *q, const hd_secret *s, tx_view *v)
{
    const chain_def *c = q->chain;
    int e;

    txv_clear(v);
    if (c->kind != K_MONERO && s->no_bip && !chain_raw_ok(c, s)) return SIGN_ERR_NOSEED;
    switch (c->kind) {
    case K_P2PKH: case K_P2SH_WPKH: case K_P2WPKH: case K_P2TR: case K_CASHADDR: {
        psbt p;
        bip32_node m;
        const btc_net *net = btc_net_for(c);
        if (q->kind == SREQ_MSG && net) {                                       /* sign message: the address of the path is shown */
            char addr[100];
            if (chain_address_str(addr, sizeof addr, c, s, q->path) <= 0) return SIGN_ERR_PATH;
            btcmsg_summary(net, addr, q->payload, q->plen, v);
            return SIGN_OK;
        }
        if (q->kind != SREQ_TX || !net) return SIGN_ERR_KIND;
        e = psbt_parse(&p, q->payload, q->plen);
        if (e) return map_btc(e);
        if (btc_node(&m, s)) return SIGN_ERR_KEY;
        e = psbt_summary(&p, net, &m, v);
        btc_node_done(&m);
        return map_btc(e);
    }
    case K_ZEC_T: case K_ORCHARD: {
        zec_keys zk = {NULL, NULL, NULL};
        uint8_t sk[32];
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        if (c->kind == K_ORCHARD) {
            e = orchard_sk_for(sk, q, s);
            if (e) return e;
            zk.orchard_sk = sk;
        }
        e = zec_summary(q->payload, q->plen, &zk, v);
        secure_zero(sk, sizeof sk);
        return map_zec(e);
    }
    case K_MONERO:
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        if (!s->xmr_ok) return SIGN_ERR_NOSEED;
        return map_xmr(xmr_tx_summary(q->payload, q->plen, s->xmr_seed, v));
    case K_KASPA: {
        kas_ctx k;
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        e = kas_setup(&k, q, s);
        return e ? e : map_kas(kaspa_summary(q->payload, q->plen, kas_key, &k, v));
    }
    case K_NOSTR:
        if (q->kind == SREQ_MSG) {                                              /* decrypt a message: the text is shown */
            uint8_t key[96];
            int klen = 0;
            e = key_for(key, q, s, &klen);
            if (e) return e;
            e = nostr_decrypt_summary((const char *) q->payload, q->plen, key, v);
            secure_zero(key, sizeof key);
            return map_nostr(e);
        }
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        return map_nostr(nostr_summary((const char *) q->payload, q->plen, v));
    case K_EVM:
        if (q->kind == SREQ_MSG) { evm_message_summary(q->payload, q->plen, v); return SIGN_OK; }
        if (q->kind == SREQ_TYPED) { if (q->plen != 64) return SIGN_ERR_PARSE; evm_typed_summary(v); return SIGN_OK; }
        if (q->kind == SREQ_AUTH) return evm_auth_summary(q->payload, q->plen, v) ? SIGN_ERR_PARSE : SIGN_OK;
        e = evm_summary(q->payload, q->plen, v);
        return e == EVM_ERR_UNSUPPORTED ? SIGN_ERR_UNSUPPORTED : e ? SIGN_ERR_PARSE : SIGN_OK;
    default: break;
    }
    if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
    switch (c->kind) {
    case K_TRON: e = tron_summary(q->payload, q->plen, v); return e == TRON_ERR_UNSUPPORTED ? SIGN_ERR_UNSUPPORTED : e ? SIGN_ERR_PARSE : SIGN_OK;
    case K_XRP: return map_generic(xrp_summary(q->payload, q->plen, v), 99, 99);
    case K_COSMOS: return map_generic(cosmos_summary(q->payload, q->plen, v), 99, 99);
    case K_SOLANA: return map_generic(solana_summary(q->payload, q->plen, v), 99, 99);
    case K_STELLAR:
        if (!q->plen || q->plen < 1u + q->payload[0]) return SIGN_ERR_PARSE;
        return map_generic(stellar_summary(q->payload + 1 + q->payload[0], q->plen - 1 - q->payload[0], v), 99, 99);
    case K_NEAR: return map_generic(near_summary(q->payload, q->plen, v), 99, 99);
    case K_SS58_ED: return map_generic(polkadot_summary(q->payload, q->plen, DOT_CHAIN_POLKADOT, v), 99, 99);
    case K_SS58_SR: return map_generic(polkadot_summary(q->payload, q->plen, c->param == 2 ? DOT_CHAIN_KUSAMA : DOT_CHAIN_POLKADOT, v), 99, 99);
    case K_TON: return map_generic(ton_summary(q->payload, q->plen, v), 99, 99);
    case K_CARDANO: return map_generic(ada_summary(q->payload, q->plen, v), 99, 99);
    default: return SIGN_ERR_UNSUPPORTED;
    }
}

int sign_execute(const sign_req *q, const hd_secret *s, sign_result *r)
{
    const chain_def *c = q->chain;
    uint8_t key[96], sig[65], tmp[64];
    int klen = 0, e;

    r->len = 0;
    r->text = 0;
    if (c->kind != K_MONERO && s->no_bip && !chain_raw_ok(c, s)) return SIGN_ERR_NOSEED;
    r->label = "";
    switch (c->kind) {
    case K_P2PKH: case K_P2SH_WPKH: case K_P2WPKH: case K_P2TR: case K_CASHADDR: {
        psbt p;
        bip32_node m;
        const btc_net *net = btc_net_for(c);
        size_t plen = 0, txlen = 0;
        int ns = 0;
        if (q->kind == SREQ_MSG && net) {
            hd_path hp;
            uint8_t full[96], sig65[65];
            int kl;
            if (r->cap < 100) return SIGN_ERR_SPACE;
            if (path_parse(&hp, q->path)) return SIGN_ERR_PATH;
            kl = chain_signing_key(full, c, s, &hp, NULL);
            if (kl != 32) { secure_zero(full, sizeof full); return SIGN_ERR_KEY; }
            if (c->kind == K_P2TR) {                                           /* BIP322 simple: "smp" and the Base64 of the witness */
                uint8_t wit[66];
                e = btcmsg_sign322(K_P2TR, q->payload, q->plen, full, wit, sizeof wit);
                secure_zero(full, sizeof full);
                if (e < 0) return e == BMSG_ERR_UNSUPPORTED ? SIGN_ERR_UNSUPPORTED : SIGN_ERR_KEY;
                memcpy(r->buf, "smp", 3);
                b64_encode(wit, (size_t) e, (char *) r->buf + 3, r->cap - 3);
                r->len = 3 + 88;
                r->text = 1;
                r->label = T(TXT_MESSAGE_SIGNATURE_BIP322);
                return SIGN_OK;
            }
            e = btcmsg_sign(net, c->kind, q->payload, q->plen, full, sig65);
            secure_zero(full, sizeof full);
            if (e == BMSG_ERR_UNSUPPORTED) return SIGN_ERR_UNSUPPORTED;
            if (e) return SIGN_ERR_KEY;
            b64_encode(sig65, 65, (char *) r->buf, r->cap);
            r->len = 88;
            r->text = 1;
            r->label = T(TXT_MESSAGE_SIGNATURE_BASE64);
            return SIGN_OK;
        }
        if (q->kind != SREQ_TX || !net) return SIGN_ERR_KIND;
        e = psbt_parse(&p, q->payload, q->plen);
        if (e) return map_btc(e);
        if (btc_node(&m, s)) return SIGN_ERR_KEY;
        e = psbt_sign(&p, net, &m, r->scratch, r->scap / 2, &plen, r->scratch + r->scap / 2, r->scap - r->scap / 2, &txlen, &ns);
        btc_node_done(&m);
        if (e) return map_btc(e);
        if (txlen && txlen <= r->cap) { memcpy(r->buf, r->scratch + r->scap / 2, txlen); r->len = txlen; r->label = T(TXT_SIGNED_TRANSACTION); }
        else if (plen <= r->cap) { memcpy(r->buf, r->scratch, plen); r->len = plen; r->label = T(TXT_PSBT_WITH_THE_NEW_SIGNATURES); }
        else return SIGN_ERR_SPACE;
        return SIGN_OK;
    }
    case K_ZEC_T: case K_ORCHARD: {
        bip32_node m;
        zec_keys zk;
        uint8_t sk[32];
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        if (s->raw_curve) memset(&m, 0, sizeof m);                                   /* a raw key: an Orchard spending key signs no transparent input, a secp256k1 key signs only those */
        else if (bip32_master(&m, s->seed, 64)) return SIGN_ERR_KEY;
        zk.master = s->raw_curve ? NULL : &m;
        zk.raw = s->raw_curve == 2 ? s->raw : NULL;
        zk.orchard_sk = NULL;
        if (c->kind == K_ORCHARD) {
            e = orchard_sk_for(sk, q, s);
            if (e) { secure_zero(&m, sizeof m); return e; }
            zk.orchard_sk = sk;
        }
        e = zec_sign(q->payload, q->plen, &zk, r->buf, r->cap, &r->len);
        secure_zero(&m, sizeof m);
        secure_zero(sk, sizeof sk);
        r->label = (r->len >= 4 && !memcmp(r->buf, "ZORS", 4)) ? T(TXT_SIGNATURES_ZORS) : T(TXT_SIGNED_TRANSACTION);
        return map_zec(e);
    }
    case K_MONERO:
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        if (!s->xmr_ok) return SIGN_ERR_NOSEED;
        e = xmr_tx_sign(q->payload, q->plen, s->xmr_seed, r->buf, r->cap, &r->len);
        r->label = T(TXT_SIGNATURES_XMRS);
        return map_xmr(e);
    case K_KASPA: {
        kas_ctx k;
        if (q->kind != SREQ_TX) return SIGN_ERR_KIND;
        e = kas_setup(&k, q, s);
        if (e) return e;
        e = map_kas(kaspa_sign(q->payload, q->plen, kas_key, &k, r->buf, r->cap, &r->len));
        r->label = T(TXT_SIGNATURE_SCRIPTS_KSIG);
        return e;
    }
    default: break;
    }
    if (c->kind == K_PUBHEX) return SIGN_ERR_UNSUPPORTED;
    e = key_for(key, q, s, &klen);
    if (e) return e;
    e = SIGN_ERR_KIND;
    switch (c->kind) {
    case K_EVM:
        if (q->kind == SREQ_TX) {
            int x = evm_sign_tx(q->payload, q->plen, key, r->buf, r->cap, &r->len, sig);
            e = x == EVM_ERR_UNSUPPORTED ? SIGN_ERR_UNSUPPORTED : x == EVM_ERR_SPACE ? SIGN_ERR_SPACE : x == EVM_ERR_KEY ? SIGN_ERR_KEY : x ? SIGN_ERR_PARSE : SIGN_OK;
            r->label = T(TXT_SIGNED_TRANSACTION);
        } else if (q->kind == SREQ_MSG) {
            e = evm_personal_sign(q->payload, q->plen, key, sig) ? SIGN_ERR_PARSE : SIGN_OK;
            if (!e) { memcpy(r->buf, sig, 65); r->len = 65; r->label = T(TXT_SIGNATURE_R_S_V); }
        } else if (q->kind == SREQ_AUTH) {
            int x = evm_auth_sign(q->payload, q->plen, key, sig);
            e = x == EVM_ERR_KEY ? SIGN_ERR_KEY : x ? SIGN_ERR_PARSE : SIGN_OK;
            if (!e) { memcpy(r->buf, sig, 65); r->len = 65; r->label = T(TXT_AUTHORIZATION_SIGNATURE_R_S); }
        } else if (q->plen == 64) {
            e = evm_typed_sign(q->payload, q->payload + 32, key, sig) ? SIGN_ERR_KEY : SIGN_OK;
            if (!e) { memcpy(r->buf, sig, 65); r->len = 65; r->label = T(TXT_SIGNATURE_R_S_V); }
        } else e = SIGN_ERR_PARSE;
        break;
    case K_TRON:
        if (q->kind != SREQ_TX) break;
        e = tron_sign(q->payload, q->plen, key, sig, tmp);
        e = e == TRON_ERR_UNSUPPORTED ? SIGN_ERR_UNSUPPORTED : e == TRON_ERR_KEY ? SIGN_ERR_KEY : e ? SIGN_ERR_PARSE : SIGN_OK;
        if (!e) { memcpy(r->buf, sig, 65); r->len = 65; r->label = T(TXT_SIGNATURE_R_S_RECOVERY_ID); }
        break;
    case K_XRP:
        if (q->kind != SREQ_TX) break;
        e = xrp_sign(q->payload, q->plen, key, r->buf, r->cap, &r->len);
        e = e == XRP_ERR_SPACE ? SIGN_ERR_SPACE : (e == XRP_ERR_KEY || e == XRP_ERR_PUBKEY) ? SIGN_ERR_KEY : e ? SIGN_ERR_PARSE : SIGN_OK;
        r->label = T(TXT_SIGNED_TRANSACTION_BLOB);
        break;
    case K_COSMOS:
        if (q->kind != SREQ_TX) break;
        e = cosmos_sign(q->payload, q->plen, key, sig, r->buf, r->cap, &r->len);
        e = map_generic(e, COS_ERR_KEY, COS_ERR_SPACE);
        r->label = T(TXT_SIGNED_TXRAW);
        break;
    case K_NOSTR:
        if (q->kind == SREQ_MSG) {
            e = nostr_decrypt((const char *) q->payload, q->plen, key, (char *) r->scratch, r->scap, (char *) r->buf, r->cap, &r->len);
            r->label = T(TXT_NOSTR_DECRYPTED_MESSAGE);
        } else if (q->kind == SREQ_TX) {
            e = nostr_sign((const char *) q->payload, q->plen, key, (char *) r->scratch, r->scap, (char *) r->buf, r->cap, &r->len);
            r->label = T(TXT_SIGNED_EVENT);
        } else break;
        e = map_nostr(e);
        r->text = 1;
        break;
    case K_SOLANA:
        if (q->kind != SREQ_TX) break;
        e = solana_sign(q->payload, q->plen, key, sig, r->buf, r->cap, &r->len);
        e = e == SOL_ERR_NOT_SIGNER ? SIGN_ERR_KEY : e == SOL_ERR_SPACE ? SIGN_ERR_SPACE : e ? SIGN_ERR_PARSE : SIGN_OK;
        r->label = T(TXT_SIGNED_TRANSACTION);
        break;
    case K_STELLAR: {
        uint8_t hint[4];
        char pass[96];
        size_t pl;
        if (q->kind != SREQ_TX) break;
        if (!q->plen || (pl = q->payload[0]) >= sizeof pass || q->plen < 1 + pl) { e = SIGN_ERR_PARSE; break; }
        memcpy(pass, q->payload + 1, pl);
        pass[pl] = 0;
        e = stellar_sign(q->payload + 1 + pl, q->plen - 1 - pl, pass, key, sig, hint) ? SIGN_ERR_PARSE : SIGN_OK;
        if (!e && r->cap >= 72) {                                   /* DecoratedSignature: hint, then the signature as opaque<64> */
            memcpy(r->buf, hint, 4);
            r->buf[4] = 0; r->buf[5] = 0; r->buf[6] = 0; r->buf[7] = 64;
            memcpy(r->buf + 8, sig, 64);
            r->len = 72;
            r->label = T(TXT_DECORATED_SIGNATURE_XDR);
        } else if (!e) e = SIGN_ERR_SPACE;
        break;
    }
    case K_NEAR:
        if (q->kind != SREQ_TX) break;
        e = near_sign(q->payload, q->plen, key, sig, r->buf, r->cap, &r->len);
        e = e == NEAR_ERR_KEY ? SIGN_ERR_KEY : e == NEAR_ERR_SPACE ? SIGN_ERR_SPACE : e ? SIGN_ERR_PARSE : SIGN_OK;
        r->label = T(TXT_SIGNED_TRANSACTION);
        break;
    case K_SS58_ED: case K_SS58_SR: {
        if (q->kind != SREQ_TX) break;
        if (q->plen < 3) { e = SIGN_ERR_PARSE; break; }
        if (c->kind == K_SS58_ED) polkadot_sign_ed25519(sig, key, q->payload, q->plen);
        else polkadot_sign_sr25519(sig, key, q->payload, q->plen);
        memcpy(r->buf, sig, 65);
        r->len = 65;
        r->label = T(TXT_SIGNATURE_MULTISIGNATURE);
        e = SIGN_OK;
        break;
    }
    case K_TON:
        if (q->kind != SREQ_TX) break;
        e = ton_sign(q->payload, q->plen, key, sig, tmp) ? SIGN_ERR_PARSE : SIGN_OK;
        if (!e) { memcpy(r->buf, sig, 64); r->len = 64; r->label = T(TXT_SIGNATURE_64_BYTES); }
        break;
    case K_CARDANO: {
        uint8_t vk[4][32], sg[4][64], h[32];
        int n = 0;
        const char *p = q->path;
        if (q->kind != SREQ_TX) break;
        while (p && n < (s->raw_curve ? 1 : 4)) {                     /* the payment key, and the stake key after a ';' (a raw key is the payment key only) */
            hd_path hp;
            char one[48];
            const char *semi = strchr(p, ';');
            size_t l = semi ? (size_t) (semi - p) : strlen(p);
            uint8_t node[96];
            int x;
            if (l >= sizeof one) { e = SIGN_ERR_PATH; goto ada_done; }
            memcpy(one, p, l);
            one[l] = 0;
            if (path_parse(&hp, one)) { e = SIGN_ERR_PATH; goto ada_done; }
            if (chain_signing_key(node, c, s, &hp, NULL) != 96) { e = SIGN_ERR_KEY; goto ada_done; }
            x = ada_sign(q->payload, q->plen, node, vk[n], sg[n], h);
            secure_zero(node, sizeof node);
            if (x) { e = SIGN_ERR_PARSE; goto ada_done; }
            n++;
            p = semi ? semi + 1 : NULL;
        }
        if (r->cap < 3 + 102u * (size_t) n) { e = SIGN_ERR_SPACE; break; }
        r->len = ada_witness_set(r->buf, n, (const uint8_t (*)[32]) vk, (const uint8_t (*)[64]) sg);
        r->label = T(TXT_WITNESS_SET_CBOR);
        e = SIGN_OK;
    ada_done:
        break;
    }
    default: e = SIGN_ERR_UNSUPPORTED;
    }
    secure_zero(key, sizeof key);
    secure_zero(sig, sizeof sig);
    return e;
}
