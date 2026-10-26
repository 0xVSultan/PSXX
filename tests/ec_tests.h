/* EC known-answer checks, included by test_kat.c (after its helpers are defined). */
#include "ec/secp256k1.h"
#include "ec/ed25519.h"
#include "coin/xmr.h"
#include "coin/bip32.h"
#include "coin/addr.h"
#include "coin/bip39.h"
#include "entropy.h"
#include "coin/wallet.h"
#include "coin/xmr_seed.h"
#include "lz4.h"
#include "lz4_unpack.h"

static int ec_test_line(const char *k, char **tok, int nt, int ln)
{
    uint8_t a[128], b[128], c[128], d[128];
    size_t na, nb, nc;
    (void)nt;

    if (!strcmp(k, "secp_pub")) {
        na = unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b); nc = unhex(tok[3], c, sizeof c);
        (void)na;
        if (secp256k1_pubkey_create(d, a) == 0) expect_hex("secp_pub(33)", ln, d, 33, b, nb);
        else expect_hex("secp_pub(33)", ln, d, 0, b, nb);
        if (secp256k1_pubkey_create_uncompressed(d, a) == 0) expect_hex("secp_pub(65)", ln, d, 65, c, nc);
        else expect_hex("secp_pub(65)", ln, d, 0, c, nc);
        return 1;
    }
    if (!strcmp(k, "secp_tweak")) {
        na = unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b); nc = unhex(tok[3], c, sizeof c);
        (void)na; (void)nb;
        int r = secp256k1_privkey_tweak_add(a, b);
        if (r == 0) expect_hex("secp_tweak", ln, a, 32, c, nc);
        else expect_hex("secp_tweak", ln, a, 0, c, nc);   /* "-" -> expected failure */
        return 1;
    }
    if (!strcmp(k, "ed_pub")) {
        unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b);
        ed25519_pubkey_from_seed(d, a);
        expect_hex(k, ln, d, 32, b, nb);
        return 1;
    }
    if (!strcmp(k, "ed_base")) {
        unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b);
        ed25519_scalarmult_base(d, a);
        expect_hex(k, ln, d, 32, b, nb);
        return 1;
    }
    if (!strcmp(k, "ed_reduce64")) {
        unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b);
        ed25519_sc_reduce64(d, a);
        expect_hex(k, ln, d, 32, b, nb);
        return 1;
    }
    if (!strcmp(k, "ed_reduce32")) {
        unhex(tok[1], a, sizeof a); nb = unhex(tok[2], b, sizeof b);
        ed25519_sc_reduce32(a);
        expect_hex(k, ln, a, 32, b, nb);
        return 1;
    }
    if (!strcmp(k, "ed_scadd") || !strcmp(k, "ed_scmul")) {
        unhex(tok[1], a, sizeof a); unhex(tok[2], b, sizeof b); nc = unhex(tok[3], c, sizeof c);
        if (k[5] == 'a') ed25519_sc_add(d, a, b); else ed25519_sc_mul(d, a, b);
        expect_hex(k, ln, d, 32, c, nc);
        return 1;
    }
    if (!strcmp(k, "xmr_keys")) {
        xmr_keys x;
        char addr[128];
        uint8_t w[32];
        unhex(tok[1], a, sizeof a);
        xmr_keys_from_seed(&x, a);
        nb = unhex(tok[2], w, 32); expect_hex("xmr spend_sec", ln, x.spend_sec, 32, w, nb);
        nb = unhex(tok[3], w, 32); expect_hex("xmr view_sec", ln, x.view_sec, 32, w, nb);
        nb = unhex(tok[4], w, 32); expect_hex("xmr spend_pub", ln, x.spend_pub, 32, w, nb);
        nb = unhex(tok[5], w, 32); expect_hex("xmr view_pub", ln, x.view_pub, 32, w, nb);
        if (xmr_address(addr, sizeof addr, 0x12, x.spend_pub, x.view_pub) < 0) addr[0] = 0;
        expect_str("xmr address", ln, addr, tok[6]);
        return 1;
    }
    if (!strcmp(k, "xmr_sub")) {
        char addr[128];
        uint8_t w[32];
        unhex(tok[1], a, sizeof a); unhex(tok[2], w, 32);
        if (xmr_subaddress(addr, sizeof addr, a, w, (uint32_t) atoi(tok[3]), (uint32_t) atoi(tok[4])) < 0) addr[0] = 0;
        expect_str("xmr subaddress", ln, addr, tok[5]);
        return 1;
    }
    if (!strcmp(k, "bip32")) {
        bip32_node n;
        uint32_t path[16];
        size_t np = 0;
        char xprv[128], xpub[128], pth[128];
        uint8_t fp[4] = {0, 0, 0, 0};
        na = unhex(tok[1], a, sizeof a);
        strncpy(pth, tok[2], sizeof pth - 1); pth[sizeof pth - 1] = 0;
        for (char *p = strtok(pth, "/"); p; p = strtok(NULL, "/")) {
            size_t l = strlen(p);
            if (!strcmp(p, "m")) continue;
            int hard = (p[l - 1] == '\'' || p[l - 1] == 'h');
            path[np++] = (uint32_t)atol(p) | (hard ? BIP32_HARDENED : 0);
        }
        int bad = bip32_master(&n, a, na);
        for (size_t i = 0; i < np && !bad; i++) {
            bip32_fingerprint(&n, fp);
            bad = bip32_derive(&n, path[i]);
        }
        if (bad) { expect_str("bip32 derive", ln, "error", "ok"); return 1; }
        uint32_t idx = np ? path[np - 1] : 0;
        if (bip32_serialize(&n, 0, (uint8_t)np, fp, idx, xprv, sizeof xprv) < 0) xprv[0] = 0;
        if (bip32_serialize(&n, 1, (uint8_t)np, fp, idx, xpub, sizeof xpub) < 0) xpub[0] = 0;
        expect_str("bip32 xprv", ln, xprv, tok[3]);
        expect_str("bip32 xpub", ln, xpub, tok[4]);
        return 1;
    }
    if (!strcmp(k, "addr")) {
        char s[128];
        uint8_t pub[33];
        unhex(tok[1], a, sizeof a);
        secp256k1_pubkey_create(pub, a);
        if (addr_p2pkh(s, sizeof s, 0x00, pub) < 0) s[0] = 0;
        expect_str("addr btc p2pkh", ln, s, tok[2]);
        if (addr_p2pkh(s, sizeof s, 0x1e, pub) < 0) s[0] = 0;
        expect_str("addr doge p2pkh", ln, s, tok[3]);
        if (addr_wif(s, sizeof s, 0x80, a) < 0) s[0] = 0;
        expect_str("addr btc wif", ln, s, tok[4]);
        if (addr_wif(s, sizeof s, 0x9e, a) < 0) s[0] = 0;
        expect_str("addr doge wif", ln, s, tok[5]);
        if (addr_p2wpkh(s, sizeof s, "bc", pub) < 0) s[0] = 0;
        expect_str("addr p2wpkh", ln, s, tok[6]);
        if (addr_eth(s, sizeof s, a) < 0) s[0] = 0;
        expect_str("addr eth", ln, s, tok[7]);
        if (addr_npub(s, sizeof s, a) < 0) s[0] = 0;
        expect_str("addr npub", ln, s, tok[8]);
        if (addr_nsec(s, sizeof s, a) < 0) s[0] = 0;
        expect_str("addr nsec", ln, s, tok[9]);
        return 1;
    }
    if (!strcmp(k, "bip39")) {
        char m[256];
        uint8_t ent[32], seed[64], pw[160];
        size_t npw;
        na = unhex(tok[1], a, sizeof a);
        strncpy(m, tok[2], sizeof m - 1); m[sizeof m - 1] = 0;
        for (char *p = m; *p; p++) if (*p == '_') *p = ' ';
        npw = unhex(tok[3], pw, sizeof pw - 1); pw[npw] = 0;
        nc = unhex(tok[4], c, sizeof c);
        char got[BIP39_MAX_MNEMONIC];
        if (bip39_entropy_to_mnemonic(a, na, got, sizeof got) < 0) got[0] = 0;
        expect_str("bip39 entropy->mnemonic", ln, got, m);
        int n = bip39_mnemonic_to_entropy(m, ent);
        expect_hex("bip39 mnemonic->entropy", ln, ent, n < 0 ? 0 : (size_t)n, a, na);
        bip39_seed(m, (const char *)pw, seed);
        expect_hex("bip39 seed", ln, seed, 64, c, nc);
        return 1;
    }
    if (!strcmp(k, "bip39_bad")) {
        char m[256];
        uint8_t ent[32];
        strncpy(m, tok[1], sizeof m - 1); m[sizeof m - 1] = 0;
        for (char *p = m; *p; p++) if (*p == '_') *p = ' ';
        total++;
        if (bip39_mnemonic_to_entropy(m, ent) >= 0) { fails++; printf("FAIL bip39_bad accepted (line %d): %s\n", ln, m); }
        return 1;
    }
    if (!strcmp(k, "entropy")) {
        entropy_pool pool;
        uint8_t out[32];
        char *list = tok[1];
        entropy_init(&pool, 0);
        for (char *p = strtok(list, ","); p; p = strtok(NULL, ",")) {
            if (p[0] == 'd') entropy_add_dice(&pool, (unsigned)atoi(p + 1));
            else if (p[0] == 'c') entropy_add_coin(&pool, (unsigned)atoi(p + 1));
            else if (p[0] == 's') { unsigned n, v; sscanf(p + 1, "%u_%u", &n, &v); entropy_add_symbol(&pool, v, n); }
        }
        total++;
        if ((long)entropy_bits(&pool) != atol(tok[2])) {
            fails++; printf("FAIL entropy bits (line %d): got %u want %s\n", ln, (unsigned)entropy_bits(&pool), tok[2]);
        }
        int r = entropy_extract(&pool, out);
        if (!strcmp(tok[3], "-")) {
            total++;
            if (r == 0) { fails++; printf("FAIL entropy extract should refuse (line %d)\n", ln); }
        } else {
            nb = unhex(tok[3], b, sizeof b);
            expect_hex("entropy extract", ln, out, r == 0 ? 32 : 0, b, nb);
        }
        return 1;
    }
    if (!strcmp(k, "xmr_seed") || !strcmp(k, "xmr_seed_prefix")) {
        char m[XMR_MAX_MNEMONIC], got[XMR_MAX_MNEMONIC];
        uint8_t key[32];
        int is_prefix = !strcmp(k, "xmr_seed_prefix");
        na = unhex(tok[1], a, sizeof a);
        strncpy(m, tok[2], sizeof m - 1); m[sizeof m - 1] = 0;
        for (char *p = m; *p; p++) if (*p == '_') *p = ' ';
        if (!is_prefix) {
            if (xmr_seed_encode(a, got, sizeof got) < 0) got[0] = 0;
            expect_str("xmr seed encode", ln, got, m);
        }
        int r = xmr_seed_decode(m, key);
        expect_hex("xmr seed decode", ln, key, r == 0 ? 32 : 0, a, na);
        return 1;
    }
    if (!strcmp(k, "xmr_seed_bad")) {
        char m[XMR_MAX_MNEMONIC];
        uint8_t key[32];
        strncpy(m, tok[1], sizeof m - 1); m[sizeof m - 1] = 0;
        for (char *p = m; *p; p++) if (*p == '_') *p = ' ';
        total++;
        if (xmr_seed_decode(m, key) == 0) { fails++; printf("FAIL xmr_seed_bad accepted (line %d)\n", ln); }
        return 1;
    }
    if (!strcmp(k, "lz4") || !strcmp(k, "lz4ip")) {
        static uint8_t o[4096], buf[4096], orig[2048], comp[2048];
        na = unhex(tok[1], orig, sizeof orig); nb = unhex(tok[2], comp, sizeof comp);
        int r = lz4_decompress(comp, nb, o, sizeof o);              /* checked decoder */
        expect_hex("lz4 checked", ln, o, r < 0 ? 0 : (size_t) r, orig, na);
        uint8_t *e = lz4_unpack_unchecked(comp, comp + nb, buf);    /* the stub's loop */
        expect_hex("lz4 unchecked", ln, buf, (size_t) (e - buf), orig, na);
        if (!strcmp(k, "lz4ip")) {                                  /* in place, with the margin the packer computes */
            size_t m = (size_t) atol(tok[3]);
            memset(buf, 0xAA, sizeof buf);
            memcpy(buf + na + m - nb, comp, nb);
            e = lz4_unpack_unchecked(buf + na + m - nb, buf + na + m, buf);
            expect_hex("lz4 in place", ln, buf, (size_t) (e - buf), orig, na);
        }
        return 1;
    }
    if (!strcmp(k, "lz4bad")) {
        uint8_t o[4096];
        nb = unhex(tok[1], b, sizeof b);
        total++;
        if (lz4_decompress(b, nb, o, sizeof o) >= 0) { fails++; printf("FAIL lz4bad accepted (line %d)\n", ln); }
        return 1;
    }
    if (!strcmp(k, "wallet")) {
        wallet_addrs w;
        unhex(tok[1], a, sizeof a);
        int r = wallet_derive(&w, a, NULL, NULL);
        total++;
        if (r) { fails++; printf("FAIL wallet_derive (line %d)\n", ln); return 1; }
        expect_str("wallet btc legacy", ln, w.btc_legacy, tok[2]);
        expect_str("wallet btc segwit", ln, w.btc_segwit, tok[3]);
        expect_str("wallet eth", ln, w.eth, tok[4]);
        expect_str("wallet doge", ln, w.doge, tok[5]);
        expect_str("wallet npub", ln, w.npub, tok[6]);
        return 1;
    }
    return 0;
}

static void ec_test_summary(int *total, int *fails) { (void)total; (void)fails; }
