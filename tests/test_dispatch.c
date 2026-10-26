/* The request container and the dispatcher (core/sign/dispatch.c).
 *  - Bitcoin family and Zcash: the vectors of tests/btc_vectors.txt and tests/txsign_vectors.txt carry their seeds, so the result
 *    must be exactly the expected transaction.
 *  - The other coins: the payloads of tests/txsign_vectors.txt are signed through the dispatcher with a fixed test seed and the
 *    same key is used to call the signer module directly: the two results must be identical (the plumbing: path, key, buffers).
 * Usage: test_dispatch <btc_vectors.txt> <txsign_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/dispatch.h"
#include "sign/ada.h"
#include "sign/cosmos.h"
#include "sign/evm.h"
#include "sign/kaspa.h"
#include "ec/secp256k1.h"
#include "sign/near.h"
#include "sign/nostr.h"
#include "sign/polkadot.h"
#include "sign/solana.h"
#include "sign/stellar.h"
#include "sign/ton.h"
#include "sign/tron.h"
#include "sign/xrp.h"
#include "coin/substrate.h"
#include "coin/bip32.h"
#include "coin/path.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (!strcmp(s, "-")) return 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t) v;
    }
    return n;
}

static size_t make_req(uint8_t *o, int kind, const char *chain, const char *path, const uint8_t *payload, size_t plen)
{
    size_t n = 0, pl = strlen(path);
    memcpy(o, "PSXQ", 4); o[4] = 1; o[5] = (uint8_t) kind;
    memset(o + 6, 0, 8);
    memcpy(o + 6, chain, strlen(chain));
    o[14] = (uint8_t) pl;
    memcpy(o + 15, path, pl);
    n = 15 + pl;
    for (int i = 0; i < 4; i++) o[n++] = (uint8_t) (plen >> (8 * i));
    memcpy(o + n, payload, plen);
    return n + plen;
}

static uint8_t req[40000], pay[30000], want[30000], res[30000], scratch[16000], tmp[30000];
static hd_secret S;

static int run(const char *chain, int kind, const char *path, const uint8_t *payload, size_t plen, size_t *len, int *text)
{
    sign_req q;
    sign_result r;
    size_t n = make_req(req, kind, chain, path, payload, plen);
    int e = sign_req_parse(&q, req, n);
    if (e) return e;
    r.buf = res; r.cap = sizeof res; r.scratch = scratch; r.scap = sizeof scratch;
    e = sign_execute(&q, &S, &r);
    *len = r.len;
    if (text) *text = r.text;
    return e;
}

static int key_of(const char *chain, const char *path, uint8_t key[96])
{
    const chain_def *c = chain_find(chain);
    hd_path p;
    memset(&p, 0, sizeof p);
    if (c->curve == CV_SR25519) return chain_signing_key(key, c, &S, &p, path);
    if (path_parse(&p, path)) return -1;
    return chain_signing_key(key, c, &S, &p, NULL);
}

int main(int argc, char **argv)
{
    FILE *f;
    static char line[60000];
    char *tok[200];
    int fails = 0, total = 0, ln;

    for (int i = 0; i < 64; i++) S.seed[i] = (uint8_t) (i * 7 + 3);
    S.entlen = 16;
    for (int i = 0; i < 16; i++) S.entropy[i] = (uint8_t) (i * 11 + 5);
    S.passphrase = "";

    f = fopen(argc > 1 ? argv[1] : "tests/btc_vectors.txt", "r");
    if (!f) { printf("cannot open the Bitcoin vectors\n"); return 2; }
    ln = 0;
    while (fgets(line, sizeof line, f)) {
        int nt = 0;
        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 200; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 5 || (strcmp(tok[0], "psbt") && strcmp(tok[0], "perr"))) continue;
        {
            static const char *const NAMES[] = {"btc", "ltc", "doge", "dash", "bch"}, *const IDS[] = {"btc84", "ltc84", "doge", "dash", "bch"};
            const char *id = "btc84";
            size_t pl = unhex(tok[3], pay, sizeof pay), len = 0;
            int e;
            for (int i = 0; i < 5; i++) if (!strcmp(tok[1], NAMES[i])) id = IDS[i];
            unhex(tok[2], S.seed, 64);
            total++;
            e = run(id, 0, "", pay, pl, &len, NULL);
            if (!strcmp(tok[0], "perr")) { if (e != SIGN_ERR_UTXO) { fails++; printf("FAIL perr line %d: %d\n", ln, e); } continue; }
            if (atoi(tok[6]) == 0) { if (e != SIGN_ERR_NOTMINE) { fails++; printf("FAIL notmine line %d: %d\n", ln, e); } continue; }
            {
                size_t wl = unhex(tok[5], want, sizeof want);
                if (!wl) wl = unhex(tok[4], want, sizeof want);
                if (e || len != wl || memcmp(res, want, wl)) { fails++; printf("FAIL btc line %d: %d len %zu/%zu\n", ln, e, len, wl); }
            }
        }
    }
    fclose(f);
    for (int i = 0; i < 64; i++) S.seed[i] = (uint8_t) (i * 7 + 3);

    f = fopen(argc > 2 ? argv[2] : "tests/txsign_vectors.txt", "r");
    if (!f) { printf("cannot open the vectors\n"); return 2; }
    ln = 0;
    while (fgets(line, sizeof line, f)) {
        int nt = 0;
        size_t len = 0, pl, dl = 0;
        int e, de = 0, text = 0;
        uint8_t key[96], sig[65], h[32];
        const char *chain = NULL, *path = "";
        int kind = 0;
        size_t dlen = 0;

        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 200; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 3) continue;
        if (!strcmp(tok[0], "zecsign") && nt == 4) {
            pl = unhex(tok[2], pay, sizeof pay);
            unhex(tok[1], S.seed, 64);
            e = run("zec", 0, "", pay, pl, &len, NULL);
            dl = unhex(tok[3], want, sizeof want);
            total++;
            if (e || len != dl || memcmp(res, want, dl)) { fails++; printf("FAIL zec line %d: %d\n", ln, e); }
            for (int i = 0; i < 64; i++) S.seed[i] = (uint8_t) (i * 7 + 3);
            continue;
        }
        if (!strcmp(tok[0], "zecerr") && nt == 4) {
            pl = unhex(tok[2], pay, sizeof pay);
            unhex(tok[1], S.seed, 64);
            e = run("zec", 0, "", pay, pl, &len, NULL);
            total++;
            if (e != (atoi(tok[3]) == -2 ? SIGN_ERR_UNSUPPORTED : SIGN_ERR_NOTMINE)) { fails++; printf("FAIL zecerr line %d: %d\n", ln, e); }
            for (int i = 0; i < 64; i++) S.seed[i] = (uint8_t) (i * 7 + 3);
            continue;
        }
        /* the others: dispatcher against the direct call with the same key */
        if (!strcmp(tok[0], "evmtx") || !strcmp(tok[0], "evmmsg") || !strcmp(tok[0], "evmtyped")) {
            chain = "eth"; path = "m/44'/60'/0'/0/0";
            if (key_of(chain, path, key) != 32) continue;
            if (!strcmp(tok[0], "evmtx")) {
                pl = unhex(tok[2], pay, sizeof pay);
                de = evm_sign_tx(pay, pl, key, tmp, sizeof tmp, &dlen, sig);
                memcpy(want, tmp, dlen);
            } else if (!strcmp(tok[0], "evmmsg")) {
                kind = 1; pl = unhex(tok[2], pay, sizeof pay);
                de = evm_personal_sign(pay, pl, key, sig); memcpy(want, sig, 65); dlen = 65;
            } else {
                kind = 2; unhex(tok[2], pay, 32); unhex(tok[3], pay + 32, 32); pl = 64;
                de = evm_typed_sign(pay, pay + 32, key, sig); memcpy(want, sig, 65); dlen = 65;
            }
        } else if (!strcmp(tok[0], "tronraw")) {
            chain = "trx"; path = "m/44'/195'/0'/0/0";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = tron_sign(pay, pl, key, sig, h); memcpy(want, sig, 65); dlen = 65;
        } else if (!strcmp(tok[0], "xrptx")) {
            chain = "xrp"; path = "m/44'/144'/0'/0/0";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = xrp_sign(pay, pl, key, tmp, sizeof tmp, &dlen); memcpy(want, tmp, dlen);
        } else if (!strcmp(tok[0], "cossign")) {
            chain = "atom"; path = "m/44'/118'/0'/0/0";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = cosmos_sign(pay, pl, key, sig, tmp, sizeof tmp, &dlen); memcpy(want, tmp, dlen);
        } else if (!strcmp(tok[0], "nostr")) {
            static char sc[8192];
            chain = "nostr"; path = "m/44'/1237'/0'/0/0";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = nostr_sign((const char *) pay, pl, key, sc, sizeof sc, (char *) tmp, sizeof tmp, &dlen); memcpy(want, tmp, dlen);
        } else if (!strcmp(tok[0], "solsign")) {
            chain = "sol"; path = "m/44'/501'/0'/0'";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = solana_sign(pay, pl, key, sig, tmp, sizeof tmp, &dlen); memcpy(want, tmp, dlen);
        } else if (!strcmp(tok[0], "xlmsign")) {
            char pass[200];
            uint8_t hint[4], xdr[20000];
            size_t pwl, xl = unhex(tok[3], xdr, sizeof xdr);
            chain = "xlm"; path = "m/44'/148'/0'";
            key_of(chain, path, key);
            pwl = unhex(tok[2], tmp, sizeof tmp);
            memcpy(pass, tmp, pwl); pass[pwl] = 0;
            pay[0] = (uint8_t) pwl; memcpy(pay + 1, pass, pwl); memcpy(pay + 1 + pwl, xdr, xl); pl = 1 + pwl + xl;
            de = stellar_sign(xdr, xl, pass, key, sig, hint);
            memcpy(want, hint, 4); want[4] = 0; want[5] = 0; want[6] = 0; want[7] = 64; memcpy(want + 8, sig, 64); dlen = 72;
        } else if (!strcmp(tok[0], "nearsign")) {
            chain = "near"; path = "m/44'/397'/0'";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = near_sign(pay, pl, key, sig, tmp, sizeof tmp, &dlen); memcpy(want, tmp, dlen);
        } else if (!strcmp(tok[0], "dotsign")) {
            int sr = tok[1][0] == '1';
            chain = sr ? "dotsr" : "dot"; path = sr ? "//polkadot//0" : "m/44'/354'/0'/0'/0'";
            key_of(chain, path, key);
            pl = unhex(tok[3], pay, sizeof pay);
            if (sr) polkadot_sign_sr25519(sig, key, pay, pl); else polkadot_sign_ed25519(sig, key, pay, pl);
            memcpy(want, sig, 65); dlen = 65;
        } else if (!strcmp(tok[0], "tonsign")) {
            chain = "ton"; path = "m/44'/607'/0'";
            key_of(chain, path, key);
            pl = unhex(tok[2], pay, sizeof pay);
            de = ton_sign(pay, pl, key, sig, h); memcpy(want, sig, 64); dlen = 64;
        } else if (!strcmp(tok[0], "adasign")) {
            uint8_t vk[2][32], sg[2][64], node[96];
            hd_path p1, p2;
            chain = "ada"; path = "m/1852'/1815'/0'/0/0;m/1852'/1815'/0'/2/0";
            path_parse(&p1, "m/1852'/1815'/0'/0/0"); path_parse(&p2, "m/1852'/1815'/0'/2/0");
            pl = unhex(tok[2], pay, sizeof pay);
            chain_signing_key(node, chain_find("ada"), &S, &p1, NULL);
            de = ada_sign(pay, pl, node, vk[0], sg[0], h);
            chain_signing_key(node, chain_find("ada"), &S, &p2, NULL);
            de |= ada_sign(pay, pl, node, vk[1], sg[1], h);
            dlen = ada_witness_set(want, 2, (const uint8_t (*)[32]) vk, (const uint8_t (*)[64]) sg);
        } else continue;

        total++;
        e = run(chain, kind, path, pay, pl, &len, &text);
        if (de) {
            if (e == SIGN_OK) { fails++; printf("FAIL line %d (%s): the module refused (%d) but the dispatcher signed\n", ln, tok[0], de); }
        } else if (e || len != dlen || memcmp(res, want, dlen)) {
            fails++;
            printf("FAIL line %d (%s): dispatcher %d len %zu, direct len %zu\n", ln, tok[0], e, len, dlen);
        }
    }
    fclose(f);
    {   /* Kaspa through the dispatcher: the key of (account path, change, index) from the seed, and a raw key without a path */
        static uint8_t tx[200], ref[200];
        uint8_t key[32], x[32];
        bip32_node n;
        hd_path p;
        size_t o = 0, rl = 0, l1 = 0;
        int t1 = 0, e1, e2;
        hd_secret R;

        path_parse(&p, "m/44'/111111'/0'/1/3");
        bip32_master(&n, S.seed, 64);
        bip32_derive_path(&n, p.idx, p.n);
        memcpy(key, n.key, 32);
        secp256k1_xonly_pubkey(x, NULL, key);
        memset(tx, 0, sizeof tx);
        tx[2] = 1; tx[3] = 1;                                                  /* version 0, one input, one output, lock time 0 */
        o = 12;
        memset(tx + o, 0x42, 32); o += 32 + 4;                                 /* txid, index 0 */
        o += 8 + 1;                                                            /* sequence 0, sig op count 0 */
        tx[o] = 0x00; tx[o + 1] = 0xe1; tx[o + 2] = 0xf5; tx[o + 3] = 0x05; o += 8;     /* amount 100000000 */
        o += 2;                                                                /* script version 0 */
        tx[o++] = 34; tx[o++] = 0x20; memcpy(tx + o, x, 32); o += 32; tx[o++] = 0xac;
        tx[o++] = 1; tx[o++] = 1; o += 3; tx[o++] = 3; o += 3;                 /* ours: change 1, index 3 */
        tx[o] = 0x80; tx[o + 1] = 0xf0; tx[o + 2] = 0xfa; tx[o + 3] = 0x02; o += 8;     /* output 50000000 */
        o += 2;
        tx[o++] = 34; tx[o++] = 0x20; memset(tx + o, 0x07, 32); o += 32; tx[o++] = 0xac;
        tx[o++] = 0;
        total++;
        e1 = run("kas", SREQ_TX, "m/44'/111111'/0'", tx, o, &l1, &t1);
        memcpy(ref, res, l1 < sizeof ref ? l1 : sizeof ref);
        if (e1 != SIGN_OK || l1 != 6 + 68 || memcmp(res, "KSIG", 4)) { fails++; printf("FAIL Kaspa through the dispatcher: %d, %zu bytes\n", e1, l1); }
        memset(&R, 0, sizeof R);
        memcpy(R.raw, key, 32);
        R.raw_curve = 2;
        R.no_bip = 1;
        {
            hd_secret keep = S;
            S = R;
            total++;
            e2 = run("kas", SREQ_TX, "", tx, o, &rl, &t1);
            if (e2 != SIGN_OK || rl != l1 || memcmp(res, ref, l1)) { fails++; printf("FAIL Kaspa with a raw key: %d\n", e2); }
            S = keep;
        }
    }
    {   /* a raw key signs like the key of its path (EVM message), ignores the path, and refuses a coin of the other curve */
        static uint8_t first[200], msgp[] = "hello raw key";
        size_t l1 = 0, l2 = 0;
        int t1 = 0, e1, e2;
        hd_secret R;
        bip32_node n;
        hd_path p;

        total++;
        e1 = run("eth", SREQ_MSG, "m/44'/60'/0'/0/0", msgp, sizeof msgp - 1, &l1, &t1);
        memcpy(first, res, l1 < sizeof first ? l1 : sizeof first);
        memset(&R, 0, sizeof R);
        path_parse(&p, "m/44'/60'/0'/0/0");
        bip32_master(&n, S.seed, 64);
        bip32_derive_path(&n, p.idx, p.n);
        memcpy(R.raw, n.key, 32);
        R.raw_curve = 2;
        R.no_bip = 1;
        {
            hd_secret keep = S;
            S = R;
            e2 = run("eth", SREQ_MSG, "", msgp, sizeof msgp - 1, &l2, &t1);
            if (e2 == SIGN_OK && (l2 != l1 || memcmp(res, first, l1))) e2 = 99;
            total++;
            if (run("sol", SREQ_TX, "m/44'/501'/0'/0'", msgp, sizeof msgp - 1, &l2, &t1) == SIGN_OK) { fails++; printf("FAIL a secp256k1 raw key signed for Solana\n"); }
            total++;
            if (run("btc84", SREQ_TX, "", msgp, sizeof msgp - 1, &l2, &t1) == SIGN_OK) { fails++; printf("FAIL a raw key signed for a PSBT coin\n"); }
            S = keep;
        }
        if (e1 || e2) { fails++; printf("FAIL raw key signature: seed %d, raw %d\n", e1, e2); }
    }
    printf("DISPATCH %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
