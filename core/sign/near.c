#include "sign/near.h"
#include <stdio.h>
#include <string.h>
#include "ec/ed25519.h"
#include "hash/sha256.h"
#include "tr.h"

typedef struct { const uint8_t *p, *end; int err; } br;

static uint32_t b32(br *r)
{
    uint32_t v = 0;
    if (r->end - r->p < 4) { r->err = 1; return 0; }
    for (int i = 3; i >= 0; i--) v = (v << 8) | r->p[i];
    r->p += 4;
    return v;
}

static uint64_t b64(br *r)
{
    uint64_t v = 0;
    if (r->end - r->p < 8) { r->err = 1; return 0; }
    for (int i = 7; i >= 0; i--) v = (v << 8) | r->p[i];
    r->p += 8;
    return v;
}

static const uint8_t *bn(br *r, size_t n)
{
    const uint8_t *p = r->p;
    if ((size_t) (r->end - r->p) < n) { r->err = 1; return NULL; }
    r->p += n;
    return p;
}

static uint8_t b8(br *r) { const uint8_t *p = bn(r, 1); return p ? *p : 0; }

/* a string: returns a pointer and the length */
static const uint8_t *bstr(br *r, size_t *n)
{
    uint32_t l = b32(r);
    *n = l;
    return r->err ? NULL : bn(r, l);
}

static void text(char *out, size_t cap, const uint8_t *s, size_t n)
{
    if (n > cap - 1) n = cap - 1;
    for (size_t i = 0; i < n; i++) out[i] = (s[i] >= 0x20 && s[i] < 0x7f) ? (char) s[i] : '?';
    out[n] = 0;
}

/* u128 (16 bytes little endian) -> NEAR text with 24 decimals */
static void near_amount(char *out, size_t cap, const uint8_t le[16])
{
    uint8_t be[16];
    for (int i = 0; i < 16; i++) be[i] = le[15 - i];
    txv_amount_be(out, cap, be, 16, 24, "NEAR");
}

/* the header: signer, public key, nonce, receiver, block hash; leaves the reader at the action list */
static int header(br *r, char *signer, size_t scap, const uint8_t **pub, uint64_t *nonce, char *recv, size_t rcap)
{
    size_t n;
    const uint8_t *s = bstr(r, &n);
    if (!s) return -1;
    text(signer, scap, s, n);
    if (b8(r) != 0) return -1;                                        /* ed25519 keys only */
    *pub = bn(r, 32);
    *nonce = b64(r);
    s = bstr(r, &n);
    if (!s) return -1;
    text(recv, rcap, s, n);
    bn(r, 32);                                                            /* block hash */
    return r->err ? -1 : 0;
}

int near_summary(const uint8_t *tx, size_t len, tx_view *v)
{
    br r = {tx, tx + len, 0};
    char signer[70], recv[70], line[96], amt[80], to[112];
    const uint8_t *pub;
    uint64_t nonce;
    uint32_t na;

    txv_clear(v);
    if (len < 70 || header(&r, signer, sizeof signer, &pub, &nonce, recv, sizeof recv)) return NEAR_ERR_PARSE;
    strcpy(v->title, T(TXT_NEAR_TRANSACTION));
    na = b32(&r);
    if (r.err || na == 0 || na > 32) return NEAR_ERR_PARSE;
    for (uint32_t i = 0; i < na && !r.err; i++) {
        uint8_t act = b8(&r);
        if (r.err) break;
        switch (act) {
        case 0: snprintf(to, sizeof to, "%s", recv); txv_add_out(v, to, T(TXT_CREATE_ACCOUNT)); break;
        case 1: { size_t n = b32(&r); bn(&r, n); snprintf(to, sizeof to, "%s", recv); snprintf(amt, sizeof amt, T(TXT_DEPLOY_CONTRACT_N_BYTES), (unsigned) n); txv_add_out(v, to, amt); v->warn |= TXW_DATA; break; }
        case 2: {
            size_t mn, an;
            const uint8_t *m = bstr(&r, &mn), *a;
            char method[48];
            const uint8_t *dep;
            (void) a;
            if (!m) break;
            text(method, sizeof method, m, mn);
            a = bstr(&r, &an);
            { uint64_t gas = b64(&r); dep = bn(&r, 16); if (r.err) break;
              near_amount(amt, sizeof amt, dep);
              snprintf(to, sizeof to, "%s", recv);
              txv_add_out(v, to, amt);
              snprintf(line, sizeof line, T(TXT_CALL_N_BYTES_OF_ARGUMENTS_N), method, (unsigned) an, (unsigned long long) gas);
              txv_note(v, line);
              v->warn |= TXW_DATA; }
            break;
        }
        case 3: { const uint8_t *d = bn(&r, 16); if (r.err) break; near_amount(amt, sizeof amt, d); snprintf(to, sizeof to, "%s", recv); txv_add_out(v, to, amt); snprintf(v->total, sizeof v->total, "%.43s", amt); break; }
        case 4: { bn(&r, 16); if (b8(&r) != 0) { r.err = 1; break; } bn(&r, 32); txv_add_out(v, T(TXT_STAKE), T(TXT_STAKING_ACTION)); v->warn |= TXW_DATA | TXW_BLIND; break; }
        case 5: {
            uint8_t kt = b8(&r);
            bn(&r, 32);
            if (kt != 0) { r.err = 1; break; }
            b64(&r);
            if (r.err) break;
            if (b8(&r) == 1) { txv_add_out(v, T(TXT_ADD_A_KEY_WITH_FULL_ACCESS), T(TXT_GIVES_COMPLETE_CONTROL_OF_THE)); v->warn |= TXW_DATA | TXW_BLIND; }
            else {
                size_t n;
                if (b8(&r)) bn(&r, 16);                                  /* allowance */
                bstr(&r, &n);
                { uint32_t nm = b32(&r); for (uint32_t k = 0; k < nm && !r.err; k++) bstr(&r, &n); }
                txv_add_out(v, T(TXT_ADD_A_FUNCTION_CALL_KEY), T(TXT_LIMITED_ACCESS));
                v->warn |= TXW_DATA;
            }
            break;
        }
        case 6: { uint8_t kt = b8(&r); bn(&r, 32); if (kt != 0) { r.err = 1; break; } txv_add_out(v, T(TXT_DELETE_A_KEY), ""); v->warn |= TXW_DATA; break; }
        case 7: { size_t n; const uint8_t *b = bstr(&r, &n); if (!b) break; text(to, sizeof to, b, n); snprintf(line, sizeof line, T(TXT_DELETE_ACCOUNT_FUNDS_GO_TO_N), to); txv_add_out(v, line, "everything"); v->warn |= TXW_DATA; break; }
        default: r.err = 1; break;
        }
    }
    if (r.err || r.p != r.end) return NEAR_ERR_PARSE;
    snprintf(line, sizeof line, T(TXT_SIGNER_N_NONCE_N), signer, (unsigned long long) nonce);
    txv_note(v, line);
    snprintf(line, sizeof line, T(TXT_RECEIVER_N), recv);
    txv_note(v, line);
    return NEAR_OK;
}

int near_sign(const uint8_t *tx, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t *out, size_t cap, size_t *outlen)
{
    br r = {tx, tx + len, 0};
    char signer[70], recv[70];
    const uint8_t *pub;
    uint64_t nonce;
    uint8_t mine[32], h[32];

    if (near_summary(tx, len, &txv_shared)) return NEAR_ERR_PARSE;
    header(&r, signer, sizeof signer, &pub, &nonce, recv, sizeof recv);
    ed25519_pubkey_from_seed(mine, seed);
    if (memcmp(mine, pub, 32)) return NEAR_ERR_KEY;
    sha256(tx, len, h);
    ed25519_sign(sig, seed, h, 32);
    if (out) {
        if (len + 65 > cap) return NEAR_ERR_SPACE;
        memcpy(out, tx, len);
        out[len] = 0;
        memcpy(out + len + 1, sig, 64);
        *outlen = len + 65;
    }
    return NEAR_OK;
}
