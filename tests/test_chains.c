/* Known-answer tests for the multi chain code: reads tests/chain_vectors.txt (tools/gen_chain_vectors.py, references:
 * bip_utils and hashlib) and checks every line.  Usage: test_chains <path to chain_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/chains.h"
#include "coin/bip32.h"
#include "coin/path.h"
#include "coin/ton.h"
#include "coin/xmr.h"
#include "coin/xpub.h"
#include "ec/ed25519.h"
#include "hash/blake2b.h"
#include "hash/blake3.h"
#include "coin/mweb.h"
#include "ec/secp256k1.h"

static int fails, total;

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

static void check_str(const char *kind, int ln, const char *got, const char *want)
{
    total++;
    if (strcmp(got, want)) { fails++; printf("FAIL %s (line %d)\n  got  %s\n  want %s\n", kind, ln, got, want); }
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/chain_vectors.txt", "r");
    char *line = malloc(16384);
    int ln = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    {   /* MWEB: the secret key is the pair that spends (scan secret, spend secret), the view-only keys are the scan secret and the spend PUBLIC key of the same spend secret; no other chain has view keys */
        hd_secret hs;
        hd_path p;
        char sec[200], view[200], pub[67];
        const char *l1, *l2;
        const chain_def *mw = chain_find("ltcmweb"), *btc = chain_find("btc84");
        uint8_t spend[32], pk[33];

        memset(&hs, 0, sizeof hs);
        for (int i = 0; i < 64; i++) hs.seed[i] = (uint8_t) (i * 7 + 1);
        path_parse(&p, "m/0'/100'/0'/2");
        total++;
        if (!mw || !chain_has_view_keys(mw) || chain_has_view_keys(btc)) { fails++; printf("FAIL chain_has_view_keys\n"); }
        total++;
        if (chain_secret(sec, sizeof sec, &l1, mw, &hs, &p, NULL) != 129 || chain_view_keys(view, sizeof view, &l2, mw, &hs, &p) != 131 || sec[64] != ' ' || view[64] != ' ') { fails++; printf("FAIL MWEB key lengths\n"); }
        else {
            total++;
            if (memcmp(sec, view, 64)) { fails++; printf("FAIL the scan secret differs between the secret key and the view keys\n"); }
            for (int i = 0; i < 32; i++) { unsigned v; sscanf(sec + 65 + 2 * i, "%2x", &v); spend[i] = (uint8_t) v; }
            secp256k1_pubkey_create(pk, spend);
            for (int i = 0; i < 33; i++) sprintf(pub + 2 * i, "%02x", pk[i]);
            total++;
            if (strcmp(pub, view + 65) || !strcmp(sec + 65, view + 65)) { fails++; printf("FAIL the spend public key of the view keys is not the one of the spend secret\n"); }
            total++;
            if (!strcmp(l1, l2) || chain_view_keys(view, sizeof view, &l2, btc, &hs, &p) != CHAIN_ERR_UNSUPPORTED) { fails++; printf("FAIL labels / unsupported view keys\n"); }
        }
    }
    {   /* a raw key gives the address of the same key found by a path, and only for the coins of its curve */
        hd_secret hs, raw;
        hd_path p;
        uint8_t key[32];
        char a1[128], a2[128];
        const chain_def *sol = chain_find("sol"), *ton = chain_find("ton"), *eth = chain_find("eth"), *btc = chain_find("btc84");

        memset(&hs, 0, sizeof hs);
        memset(&raw, 0, sizeof raw);
        for (int i = 0; i < 64; i++) hs.seed[i] = (uint8_t) (i * 3 + 5);
        path_parse(&p, "m/44'/501'/0'/0'");
        slip10_ed25519(key, hs.seed, 64, &p);
        memcpy(raw.raw, key, 32);
        raw.raw_curve = 1;
        raw.no_bip = 1;
        chain_address(a1, sizeof a1, sol, &hs, &p);
        total++;
        if (chain_address(a2, sizeof a2, sol, &raw, &p) < 0) { fails++; printf("FAIL raw ed25519 address\n"); } else check_str("raw ed25519 = path key", 0, a2, a1);
        total++;
        if (!chain_raw_ok(ton, &raw) || !chain_raw_ok(sol, &raw) || chain_raw_ok(eth, &raw) || chain_raw_ok(btc, &raw)) { fails++; printf("FAIL chain_raw_ok for an ed25519 key\n"); }
        raw.raw_curve = 2;
        total++;
        if (chain_raw_ok(sol, &raw) || !chain_raw_ok(eth, &raw) || !chain_raw_ok(btc, &raw) || !chain_raw_ok(chain_find("zec"), &raw) || chain_raw_ok(chain_find("zecu"), &raw) || chain_raw_ok(chain_find("ada"), &raw)) { fails++; printf("FAIL chain_raw_ok for a secp256k1 key\n"); }
        {   /* the secp256k1 raw key = the key of the path */
            bip32_node n;
            path_parse(&p, "m/44'/60'/0'/0/0");
            bip32_master(&n, hs.seed, 64);
            bip32_derive_path(&n, p.idx, p.n);
            memcpy(raw.raw, n.key, 32);
            chain_address(a1, sizeof a1, eth, &hs, &p);
            total++;
            if (chain_address(a2, sizeof a2, eth, &raw, &p) < 0) { fails++; printf("FAIL raw secp256k1 address\n"); } else check_str("raw secp256k1 = path key", 0, a2, a1);
        }
    }
    {   /* Monero integrated address (the encoding written out independently in Python: keccak and Base58 in 8 byte blocks) */
        const uint8_t pid[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
        char o[120];
        xmr_integrated_address(o, sizeof o, (const uint8_t *) "0123456789abcdef0123456789abcdef", (const uint8_t *) "fedcba9876543210fedcba9876543210", pid);
        check_str("xmr_integrated_address", 0, o, "4D9hq1bK3uwAEhaFR4EVAtJ6MXz1ZFX7sAEhaFR4EVAtJ8QfvYuu11zAQN2CimoZXN96YMAxhGAa4AQN2CimoZXN92hniL2PZPrU3A5cPh");
    }
    {   /* the vectors of rusty-kaspa (crypto/addresses) */
        static const char *const KP[2] = {"0000000000000000000000000000000000000000000000000000000000000000", "5fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522"};
        static const char *const KA[2] = {"kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e", "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj"};
        for (int i = 0; i < 2; i++) {
            uint8_t k[32];
            char o[96];
            unhex(KP[i], k, 32);
            kaspa_address(o, sizeof o, "kaspa", k);
            check_str("kaspa_address", i, o, KA[i]);
        }
    }
    while (fgets(line, 16384, f)) {
        char *tok[12];
        int nt = 0;
        ln++;
        for (char *p = strtok(line, " \r\n"); p && nt < 12; p = strtok(NULL, " \r\n")) tok[nt++] = p;
        if (!nt) continue;

        if (!strcmp(tok[0], "chain") && nt == 5) {
            static uint8_t sb[64];
            hd_secret s;
            hd_path p;
            char out[256];
            const chain_def *c = chain_find(tok[1]);
            memset(&s, 0, sizeof s);
            total++;
            if (!c) { fails++; printf("FAIL unknown chain %s (line %d)\n", tok[1], ln); continue; }
            unhex(tok[2], sb, 64);
            memcpy(s.seed, sb, 64);
            if (path_parse(&p, tok[3])) { fails++; printf("FAIL path %s did not parse (line %d)\n", tok[3], ln); continue; }
            int r = chain_address(out, sizeof out, c, &s, &p);
            if (r < 0) { fails++; printf("FAIL %s %s: error %d (line %d)\n", tok[1], tok[3], r, ln); continue; }
            total--;
            check_str(tok[1], ln, out, tok[4]);
        } else if (!strcmp(tok[0], "xpub") && nt == 5) {
            static uint8_t sb2[64];
            char key[XPUB_KEY_MAX], desc[XPUB_DESC_MAX];
            unhex(tok[1], sb2, 64);
            total++;
            if (xpub_export(key, desc, sb2, atoi(tok[2]))) { fails++; printf("FAIL xpub export (line %d)\n", ln); continue; }
            total--;
            if (!desc[0]) strcpy(desc, "-");
            check_str("xpub key", ln, key, tok[3]);
            check_str("xpub descriptor", ln, desc, tok[4]);
        } else if (!strcmp(tok[0], "chaine") && nt == 6) {
            static uint8_t eb[32];
            hd_secret s;
            hd_path p;
            char out[256];
            const chain_def *c = chain_find(tok[1]);
            memset(&s, 0, sizeof s);
            total++;
            if (!c) { fails++; printf("FAIL unknown chain %s (line %d)\n", tok[1], ln); continue; }
            s.entlen = (int) unhex(tok[2], eb, 32);
            memcpy(s.entropy, eb, 32);
            s.passphrase = strcmp(tok[3], "-") ? tok[3] : "";
            if (path_parse(&p, tok[4])) { fails++; printf("FAIL path %s did not parse (line %d)\n", tok[4], ln); continue; }
            int r = chain_address(out, sizeof out, c, &s, &p);
            if (r < 0) { fails++; printf("FAIL %s %s: error %d (line %d)\n", tok[1], tok[4], r, ln); continue; }
            total--;
            check_str(tok[1], ln, out, tok[5]);
        } else if (!strcmp(tok[0], "chains") && nt == 6) {
            static uint8_t eb[32];
            hd_secret s;
            char out[256];
            const chain_def *c = chain_find(tok[1]);
            memset(&s, 0, sizeof s);
            total++;
            if (!c) { fails++; printf("FAIL unknown chain %s (line %d)\n", tok[1], ln); continue; }
            s.entlen = (int) unhex(tok[2], eb, 32);
            memcpy(s.entropy, eb, 32);
            s.passphrase = strcmp(tok[3], "-") ? tok[3] : "";
            int r = chain_address_str(out, sizeof out, c, &s, strcmp(tok[4], "_") ? tok[4] : "");
            if (r < 0) { fails++; printf("FAIL %s %s: error %d (line %d)\n", tok[1], tok[4], r, ln); continue; }
            total--;
            check_str(tok[1], ln, out, tok[5]);
        } else if (!strcmp(tok[0], "tonaddr") && nt == 5) {
            uint8_t pub[32];
            char out[64];
            unhex(tok[3], pub, 32);
            if (ton_address(out, sizeof out, atoi(tok[1]), atoi(tok[2]), pub) < 0) { fails++; total++; printf("FAIL tonaddr (line %d)\n", ln); continue; }
            check_str("tonaddr", ln, out, tok[4]);
        } else if (!strcmp(tok[0], "tonseed") && nt == 7) {
            uint8_t e[64], want[64], seed[64], pub[32];
            char phrase[400], out[64], gh[130], wh[130];
            snprintf(phrase, sizeof phrase, "%s", tok[1]);
            for (char *q = phrase; *q; q++) if (*q == '_') *q = ' ';
            ton_entropy(e, phrase, strcmp(tok[2], "-") ? tok[2] : "");
            unhex(tok[3], want, 64);
            for (int i = 0; i < 64; i++) sprintf(gh + 2 * i, "%02x", e[i]);
            for (int i = 0; i < 64; i++) sprintf(wh + 2 * i, "%02x", want[i]);
            check_str("ton entropy", ln, gh, wh);
            total++;
            if (ton_entropy_is_basic(e) != atoi(tok[4])) { fails++; printf("FAIL ton basic seed flag (line %d)\n", ln); }
            if (strcmp(tok[5], "-")) {                       /* the 100000 round part: only for the valid phrases */
                ton_private_seed(seed, e);
                ed25519_pubkey_from_seed(pub, seed);
                for (int i = 0; i < 32; i++) sprintf(gh + 2 * i, "%02x", pub[i]);
                check_str("ton public key", ln, gh, tok[5]);
                ton_address(out, sizeof out, TON_V4R2, 0, pub);
                check_str("ton address", ln, out, tok[6]);
            }
        } else if (!strcmp(tok[0], "custom") && nt == 8) {
            static uint8_t sb[64];
            hd_secret s;
            hd_path p;
            chain_def cd;
            char out[256];
            memset(&s, 0, sizeof s);
            memset(&cd, 0, sizeof cd);
            cd.curve = (uint8_t) atoi(tok[1]);
            cd.kind = !strcmp(tok[2], "p2pkh") ? K_P2PKH : K_PUBHEX;
            cd.param = (uint16_t) atoi(tok[3]);
            cd.hrp = strcmp(tok[4], "-") ? tok[4] : NULL;
            unhex(tok[5], sb, 64);
            memcpy(s.seed, sb, 64);
            total++;
            if (path_parse(&p, tok[6])) { fails++; printf("FAIL custom path (line %d)\n", ln); continue; }
            if (chain_address(out, sizeof out, &cd, &s, &p) < 0) { fails++; printf("FAIL custom derive (line %d)\n", ln); continue; }
            total--;
            check_str("custom", ln, out, tok[7]);
        } else if (!strcmp(tok[0], "path") && nt == 3) {
            hd_path p;
            char out[160], want[160];
            int r;
            for (char *q = tok[1]; *q; q++) if (*q == '_') *q = ' ';
            r = path_parse(&p, tok[1]);
            if (r) sprintf(out, "err %d", r);
            else path_format(&p, out, sizeof out);
            strcpy(want, tok[2]);
            for (char *q = want; *q; q++) if (*q == '_') *q = ' ';
            check_str("path", ln, out, want);
        } else if (!strcmp(tok[0], "mweb") && nt == 5) {
            uint8_t sc[32], sp[32];
            char a[200];
            unhex(tok[1], sc, 32);
            unhex(tok[2], sp, 32);
            if (mweb_address(a, sizeof a, "ltcmweb", sc, sp, (uint32_t) atoi(tok[3])) < 0) { fails++; total++; printf("FAIL mweb (line %d)\n", ln); continue; }
            check_str("mweb", ln, a, tok[4]);
        } else if (!strcmp(tok[0], "blake3") && nt == 3) {
            uint8_t msg[1100], d[32];
            char gh[65];
            size_t ml = unhex(tok[1], msg, sizeof msg);
            if (blake3_hash(d, msg, ml)) { fails++; total++; printf("FAIL blake3 (line %d)\n", ln); continue; }
            for (int i = 0; i < 32; i++) sprintf(gh + 2 * i, "%02x", d[i]);
            check_str("blake3", ln, gh, tok[2]);
        } else if (!strcmp(tok[0], "blake2b") && nt == 7) {
            static uint8_t key[64], salt[16], pers[16], msg[2048], d[64], want[64];
            size_t ol = (size_t) atoi(tok[1]), kl = unhex(tok[2], key, 64), sl = unhex(tok[3], salt, 16), pl = unhex(tok[4], pers, 16);
            size_t ml = unhex(tok[5], msg, sizeof msg), wl = unhex(tok[6], want, 64);
            blake2b_ctx c;
            char gh[130], wh[130];
            if (blake2b_init(&c, ol, kl ? key : NULL, kl, sl ? salt : NULL, pl ? pers : NULL)) { fails++; total++; printf("FAIL blake2b init (line %d)\n", ln); continue; }
            /* feed in two uneven pieces to exercise the buffering */
            blake2b_update(&c, msg, ml / 3);
            blake2b_update(&c, msg + ml / 3, ml - ml / 3);
            blake2b_final(&c, d);
            for (size_t i = 0; i < ol; i++) sprintf(gh + 2 * i, "%02x", d[i]);
            for (size_t i = 0; i < wl; i++) sprintf(wh + 2 * i, "%02x", want[i]);
            gh[2 * ol] = 0;
            wh[2 * wl] = 0;
            check_str("blake2b", ln, gh, wh);
        }
    }
    printf("CHAINS %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
