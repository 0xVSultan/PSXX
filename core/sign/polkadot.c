#include "sign/polkadot.h"
#include <stdio.h>
#include <string.h>
#include "coin/chains.h"
#include "coin/substrate.h"
#include "ec/ed25519.h"
#include "hash/blake2b.h"
#include "tr.h"

/* the message that is signed: the payload, or its hash when it is longer than 256 bytes */
static const uint8_t *signed_bytes(const uint8_t *p, size_t n, uint8_t h[32], size_t *outn)
{
    if (n > 256) { blake2b(h, 32, p, n); *outn = 32; return h; }
    *outn = n;
    return p;
}

void polkadot_sign_ed25519(uint8_t sig65[65], const uint8_t seed[32], const uint8_t *payload, size_t len)
{
    uint8_t h[32];
    size_t n;
    const uint8_t *m = signed_bytes(payload, len, h, &n);
    sig65[0] = 0x00;
    ed25519_sign(sig65 + 1, seed, m, n);
}

void polkadot_sign_sr25519(uint8_t sig65[65], const uint8_t scalar[32], const uint8_t *payload, size_t len)
{
    uint8_t h[32];
    size_t n;
    const uint8_t *m = signed_bytes(payload, len, h, &n);
    sig65[0] = 0x01;
    sr25519_sign(sig65 + 1, scalar, m, n);
}

/* SCALE compact integer: returns the bytes used, or 0; the value as up to 16 little endian bytes in le */
static size_t compact(const uint8_t *p, size_t n, uint8_t le[16])
{
    size_t k;
    memset(le, 0, 16);
    if (!n) return 0;
    switch (p[0] & 3) {
    case 0: le[0] = (uint8_t) (p[0] >> 2); return 1;
    case 1: if (n < 2) return 0; { uint32_t v = ((uint32_t) p[0] | (uint32_t) p[1] << 8) >> 2; le[0] = (uint8_t) v; le[1] = (uint8_t) (v >> 8); } return 2;
    case 2: if (n < 4) return 0; { uint32_t v = ((uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24) >> 2; for (int i = 0; i < 4; i++) le[i] = (uint8_t) (v >> (8 * i)); } return 4;
    default:
        k = (size_t) (p[0] >> 2) + 4;
        if (k > 16 || n < 1 + k) return 0;
        memcpy(le, p + 1, k);
        return 1 + k;
    }
}

int polkadot_summary(const uint8_t *payload, size_t len, int chain, tx_view *v)
{
    uint8_t amt_le[16], amt_be[16];
    size_t cl;
    char line[96];
    static const char *const HX = "0123456789abcdef";

    txv_clear(v);
    if (len < 3) return DOT_ERR_PARSE;
    snprintf(v->title, sizeof v->title, T(TXT_N_EXTRINSIC), chain == DOT_CHAIN_KUSAMA ? "Kusama" : "Polkadot");
    v->nout = 1;
    if (payload[0] == (chain == DOT_CHAIN_KUSAMA ? 4 : 5) && (payload[1] == 0 || payload[1] == 3) && payload[2] == 0x00 && len >= 35 &&
        (cl = compact(payload + 35, len - 35, amt_le)) > 0) {
        char addr[60];
        for (int i = 0; i < 16; i++) amt_be[i] = amt_le[15 - i];
        if (ss58_encode(addr, sizeof addr, chain == DOT_CHAIN_KUSAMA ? 2 : 0, payload + 3) < 0) addr[0] = 0;
        snprintf(v->out[0].to, sizeof v->out[0].to, "%s", addr);
        txv_amount_be(v->out[0].amount, sizeof v->out[0].amount, amt_be, 16, chain == DOT_CHAIN_KUSAMA ? 12 : 10, chain == DOT_CHAIN_KUSAMA ? "KSM" : "DOT");
        snprintf(v->total, sizeof v->total, "%.43s", v->out[0].amount);
        snprintf(line, sizeof line, T(TXT_BALANCES_CALL_N_DECODED_FROM), payload[0], payload[1]);
        txv_note(v, line);
        v->warn |= TXW_UNVERIFIED;
    } else {
        snprintf(v->out[0].to, sizeof v->out[0].to, T(TXT_CALL_N), HX[payload[0] >> 4], HX[payload[0] & 15], HX[payload[1] >> 4], HX[payload[1] & 15]);
        snprintf(v->out[0].amount, sizeof v->out[0].amount, T(TXT_N_BYTES_OF_PAYLOAD), (unsigned) len);
        txv_note(v, T(TXT_THE_CALL_CANNOT_BE_DECODED));
        v->warn |= TXW_BLIND | TXW_DATA;
    }
    if (len > 256) txv_note(v, T(TXT_MORE_THAN_256_BYTES_ITS));
    return DOT_OK;
}
