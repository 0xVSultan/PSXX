#include "sign/btcmsg.h"
#include <stdio.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "hash/ripemd160.h"
#include "hash/sha256.h"
#include "util.h"
#include "tr.h"

static const char *magic_of(const btc_net *net)
{
    if (!strcmp(net->sym, "LTC")) return "Litecoin Signed Message:\n";
    if (!strcmp(net->sym, "DOGE")) return "Dogecoin Signed Message:\n";
    if (!strcmp(net->sym, "DASH")) return "DarkCoin Signed Message:\n";
    return "Bitcoin Signed Message:\n";                                    /* Bitcoin and Bitcoin Cash */
}

static void put_varint(sha256_ctx *c, size_t n)
{
    uint8_t b[3];
    if (n < 0xfd) { b[0] = (uint8_t) n; sha256_update(c, b, 1); }
    else { b[0] = 0xfd; b[1] = (uint8_t) n; b[2] = (uint8_t) (n >> 8); sha256_update(c, b, 3); }
}

void btcmsg_hash(const btc_net *net, const uint8_t *msg, size_t len, uint8_t hash[32])
{
    const char *m = magic_of(net);
    sha256_ctx c;
    uint8_t first[32];

    sha256_init(&c);
    put_varint(&c, strlen(m));
    sha256_update(&c, (const uint8_t *) m, strlen(m));
    put_varint(&c, len);
    sha256_update(&c, msg, len);
    sha256_final(&c, first);
    sha256(first, 32, hash);
}

void btcmsg_summary(const btc_net *net, const char *address, const uint8_t *msg, size_t len, tx_view *v)
{
    char line[96];
    int text = 1;

    txv_clear(v);
    snprintf(v->title, sizeof v->title, T(TXT_SIGN_MESSAGE_N), net->name);
    for (size_t i = 0; i < len; i++) if (!((msg[i] >= 0x20 && msg[i] < 0x7f) || msg[i] == '\n')) { text = 0; break; }
    v->nout = 1;
    if (text) {
        size_t n = len < sizeof v->out[0].to - 1 ? len : sizeof v->out[0].to - 1;
        memcpy(v->out[0].to, msg, n);
        v->out[0].to[n] = 0;
    } else {
        static const char HX[] = "0123456789abcdef";
        size_t n = len < 40 ? len : 40;
        for (size_t i = 0; i < n; i++) { v->out[0].to[2 * i] = HX[msg[i] >> 4]; v->out[0].to[2 * i + 1] = HX[msg[i] & 15]; }
        v->out[0].to[2 * n] = 0;
        v->warn |= TXW_DATA;
    }
    snprintf(line, sizeof line, T(TXT_N_BYTES_N), (unsigned) len, text ? "" : T(TXT_BINARY_SHOWN_IN_HEX));
    txv_note(v, line);
    snprintf(line, sizeof line, T(TXT_SIGNS_AS_N), address);
    txv_note(v, line);
    txv_note(v, T(TXT_IT_PROVES_YOU_HOLD_THIS));
}

int btcmsg_sign(const btc_net *net, int kind, const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t sig65[65])
{
    uint8_t h[32], sig[64];
    int rec, base;

    switch (kind) {
    case K_P2PKH: case K_CASHADDR: base = 31; break;
    case K_P2SH_WPKH: base = 35; break;
    case K_P2WPKH: base = 39; break;
    default: return BMSG_ERR_UNSUPPORTED;                                   /* taproot: btcmsg_sign322 */
    }
    btcmsg_hash(net, msg, len, h);
    if (secp256k1_ecdsa_sign(sig, &rec, priv, h)) return BMSG_ERR_KEY;
    sig65[0] = (uint8_t) (base + (rec & 3));
    memcpy(sig65 + 1, sig, 64);
    return BMSG_OK;
}

/* ---- BIP322, simple ---- */

static void sha256d(const uint8_t *in, size_t n, uint8_t out[32])
{
    sha256(in, n, out);
    sha256(out, 32, out);
}

void btcmsg322_hash(const uint8_t *msg, size_t len, uint8_t hash[32])
{
    sha256_ctx c;
    sha256_tagged_init(&c, "BIP0322-signed-message");
    sha256_update(&c, msg, len);
    sha256_final(&c, hash);
}

/* to_spend: version 0, one input (the null outpoint 0xFFFFFFFF, scriptSig OP_0 <message hash>, sequence 0), one output (value 0, the script of the address), lock time 0 */
void btcmsg322_spend_txid(const uint8_t *spk, size_t spklen, const uint8_t mh[32], uint8_t txid[32])
{
    uint8_t raw[4 + 1 + 36 + 1 + 34 + 4 + 1 + 8 + 1 + 34 + 4];
    size_t o = 0;

    memset(raw, 0, sizeof raw);
    o += 4;                                         /* version 0 */
    raw[o++] = 1;
    o += 32;                                        /* the null outpoint hash */
    memset(raw + o, 0xff, 4);
    o += 4;
    raw[o++] = 34;
    raw[o++] = 0x00;                                /* OP_0 */
    raw[o++] = 0x20;                                /* push 32 bytes */
    memcpy(raw + o, mh, 32);
    o += 32;
    o += 4;                                         /* sequence 0 */
    raw[o++] = 1;
    o += 8;                                         /* value 0 */
    raw[o++] = (uint8_t) spklen;
    memcpy(raw + o, spk, spklen);
    o += spklen;
    o += 4;                                         /* lock time 0 */
    sha256d(raw, o, txid);
}

/* to_sign spends to_spend:0 and has one output: value 0, the script OP_RETURN */
static const uint8_t TO_SIGN_OUT[10] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a};

/* BIP143 signature hash of the P2WPKH input of to_sign (amount 0, SIGHASH_ALL) */
static void sighash_wpkh(uint8_t sh[32], const uint8_t txid[32], const uint8_t h160[20])
{
    static const uint8_t Z4[4] = {0, 0, 0, 0}, ALL[4] = {1, 0, 0, 0};
    uint8_t pre[4 + 32 + 32 + 36 + 4 + 20 + 2 + 8 + 4 + 32 + 4 + 4], prev[36], *p = pre;

    memcpy(prev, txid, 32);
    memset(prev + 32, 0, 4);
    memset(p, 0, 4); p += 4;                        /* version 0 */
    sha256d(prev, 36, p); p += 32;                  /* hashPrevouts */
    sha256d(Z4, 4, p); p += 32;                     /* hashSequence */
    memcpy(p, prev, 36); p += 36;                   /* the outpoint */
    memcpy(p, "\x19\x76\xa9\x14", 4); p += 4;       /* the script code: the P2PKH script of the key */
    memcpy(p, h160, 20); p += 20;
    memcpy(p, "\x88\xac", 2); p += 2;
    memset(p, 0, 8); p += 8;                        /* the amount */
    memset(p, 0, 4); p += 4;                        /* the sequence */
    sha256d(TO_SIGN_OUT, sizeof TO_SIGN_OUT, p); p += 32;   /* hashOutputs */
    memset(p, 0, 4); p += 4;                        /* lock time */
    memcpy(p, ALL, 4); p += 4;
    sha256d(pre, (size_t) (p - pre), sh);
}

/* BIP341 signature hash of the key path input of to_sign (amount 0, SIGHASH_DEFAULT, no annex) */
static void sighash_tr(uint8_t sh[32], const uint8_t txid[32], const uint8_t spk[34])
{
    uint8_t m[1 + 1 + 4 + 4 + 5 * 32 + 1 + 4], prev[36], z8[8] = {0}, sp[35], *p = m;
    sha256_ctx c;

    memcpy(prev, txid, 32);
    memset(prev + 32, 0, 4);
    memset(m, 0, sizeof m);
    p += 1 + 1 + 4 + 4;                             /* epoch 0, hash type 0, version 0, lock time 0 */
    sha256(prev, 36, p); p += 32;                   /* sha_prevouts */
    sha256(z8, 8, p); p += 32;                      /* sha_amounts */
    sp[0] = 34;
    memcpy(sp + 1, spk, 34);
    sha256(sp, 35, p); p += 32;                     /* sha_scriptpubkeys */
    sha256(z8, 4, p); p += 32;                      /* sha_sequences */
    sha256(TO_SIGN_OUT, sizeof TO_SIGN_OUT, p); p += 32;    /* sha_outputs */
    p += 1 + 4;                                     /* spend type 0, input index 0 */
    sha256_tagged_init(&c, "TapSighash");
    sha256_update(&c, m, (size_t) (p - m));
    sha256_final(&c, sh);
}

int btcmsg_sign322(int kind, const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap)
{
    uint8_t mh[32], txid[32], sh[32], sig[64];
    int r = BMSG_ERR_KEY;

    btcmsg322_hash(msg, len, mh);
    if (kind == K_P2WPKH) {
        uint8_t pub[33], h160[20], spk[22], der[73];
        size_t o = 0, dl;
        if (cap < 110) return BMSG_ERR_SPACE;
        if (secp256k1_pubkey_create(pub, priv)) return BMSG_ERR_KEY;
        hash160(pub, 33, h160);
        spk[0] = 0x00;
        spk[1] = 0x14;
        memcpy(spk + 2, h160, 20);
        btcmsg322_spend_txid(spk, sizeof spk, mh, txid);
        sighash_wpkh(sh, txid, h160);
        if (secp256k1_ecdsa_sign(sig, NULL, priv, sh)) goto out;
        dl = (size_t) secp256k1_sig_to_der(der, sig);
        out[o++] = 2;                               /* two witness items: the signature and the key */
        out[o++] = (uint8_t) (dl + 1);
        memcpy(out + o, der, dl);
        o += dl;
        out[o++] = 1;                               /* SIGHASH_ALL */
        out[o++] = 33;
        memcpy(out + o, pub, 33);
        o += 33;
        r = (int) o;
    } else if (kind == K_P2TR) {
        uint8_t tk[32], spk[34];
        if (cap < 66) return BMSG_ERR_SPACE;
        if (secp256k1_taproot_tweak_seckey(tk, priv, NULL, 0) || secp256k1_xonly_pubkey(spk + 2, NULL, tk)) goto out;
        spk[0] = 0x51;
        spk[1] = 0x20;
        btcmsg322_spend_txid(spk, sizeof spk, mh, txid);
        sighash_tr(sh, txid, spk);
        if (!secp256k1_schnorr_sign(sig, tk, sh, NULL)) {
            out[0] = 1;                             /* one witness item: the 64 byte signature */
            out[1] = 64;
            memcpy(out + 2, sig, 64);
            r = 66;
        }
        secure_zero(tk, sizeof tk);
    } else {
        return BMSG_ERR_UNSUPPORTED;
    }
out:
    secure_zero(sig, sizeof sig);
    return r;
}
