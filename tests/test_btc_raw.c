/* Bitcoin family PSBTs signed with a raw secp256k1 key (core/sign/btc.c psbt_raw_key; WIF, nsec...): the PSBT of such a wallet has no BIP32 records, the key is found by the script
 * of the output it spends. The same transaction is signed again the way a wallet of the master would have written it (the fingerprint of the key and an empty path in the records):
 * deterministic signatures, so the two results have to be the same bytes, for the four single key scripts. Also the summary (ours, change) and the refusals. Usage: test_btc_raw */
#include <stdio.h>
#include <string.h>
#include "sign/btc.h"
#include "hash/ripemd160.h"
#include "hash/sha256.h"
#include "ec/secp256k1.h"

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

typedef struct { uint8_t b[4096]; size_t n; } buf;

static void put(buf *o, const void *d, size_t n) { memcpy(o->b + o->n, d, n); o->n += n; }
static void put8(buf *o, unsigned v) { uint8_t c = (uint8_t) v; put(o, &c, 1); }
static void put32(buf *o, uint32_t v) { for (int i = 0; i < 4; i++) put8(o, v >> (8 * i)); }
static void put64(buf *o, uint64_t v) { for (int i = 0; i < 8; i++) put8(o, (unsigned) (v >> (8 * i))); }
static void kv(buf *o, const uint8_t *key, size_t kl, const uint8_t *val, size_t vl)
{
    put8(o, (unsigned) kl); put(o, key, kl);
    put8(o, (unsigned) vl); put(o, val, vl);
}

/* the script of a key: type 0 P2PKH, 1 P2WPKH, 2 P2SH-P2WPKH, 3 P2TR */
static size_t spk_of(const uint8_t priv[32], int type, uint8_t s[34])
{
    uint8_t pub[33], h[20], rd[22], q[32], tw[32];

    secp256k1_pubkey_create(pub, priv);
    hash160(pub, 33, h);
    if (type == 0) { s[0] = 0x76; s[1] = 0xa9; s[2] = 0x14; memcpy(s + 3, h, 20); s[23] = 0x88; s[24] = 0xac; return 25; }
    if (type == 1) { s[0] = 0; s[1] = 0x14; memcpy(s + 2, h, 20); return 22; }
    if (type == 2) { rd[0] = 0; rd[1] = 0x14; memcpy(rd + 2, h, 20); hash160(rd, 22, h); s[0] = 0xa9; s[1] = 0x14; memcpy(s + 2, h, 20); s[22] = 0x87; return 23; }
    secp256k1_taproot_tweak_seckey(tw, priv, NULL, 0);
    secp256k1_xonly_pubkey(q, NULL, tw);
    s[0] = 0x51; s[1] = 0x20; memcpy(s + 2, q, 32);
    return 34;
}

/* a PSBT that spends the first output of a one output transaction paying to `owner`'s script and pays 60000 away and 39000 to `change_to`'s script; hd: with the records of the master
 * of the key `owner` (fingerprint, empty path) for the input and the change */
static void make_psbt(buf *o, const uint8_t owner[32], const uint8_t change_to[32], int type, int hd)
{
    uint8_t spk[34], cspk[34], pub[33], h[20], xo[32], prev_id[32], t1[32], redeem[22], fp[4], taprec[5], ext[22] = {0, 0x14};
    size_t sl = spk_of(owner, type, spk), cl = spk_of(change_to, type, cspk);
    buf prev, tx;

    secp256k1_pubkey_create(pub, owner);
    hash160(pub, 33, h);
    memcpy(fp, h, 4);
    secp256k1_xonly_pubkey(xo, NULL, owner);
    memset(&prev, 0, sizeof prev); memset(&tx, 0, sizeof tx);
    put32(&prev, 2); put8(&prev, 1); memset(t1, 0x11, 32); put(&prev, t1, 32); put32(&prev, 0); put8(&prev, 0); put32(&prev, 0xffffffffu);
    put8(&prev, 1); put64(&prev, 100000); put8(&prev, (unsigned) sl); put(&prev, spk, sl); put32(&prev, 0);
    sha256(prev.b, prev.n, t1);
    sha256(t1, 32, prev_id);
    put32(&tx, 2); put8(&tx, 1); put(&tx, prev_id, 32); put32(&tx, 0); put8(&tx, 0); put32(&tx, 0xfffffffdu);
    put8(&tx, 2);
    put64(&tx, 60000); put8(&tx, 22); memset(ext + 2, 0x77, 20); put(&tx, ext, 22);
    put64(&tx, 39000); put8(&tx, (unsigned) cl); put(&tx, cspk, cl);
    put32(&tx, 0);
    memset(o, 0, sizeof *o);
    put(o, "psbt\xff", 5);
    { const uint8_t k0[1] = {0}; kv(o, k0, 1, tx.b, tx.n); }
    put8(o, 0);
    {                                                                   /* the input */
        const uint8_t k0[1] = {0}, k1[1] = {1};

        if (type == 3) {
            uint8_t wu[8 + 1 + 34];
            memset(wu, 0, sizeof wu);
            wu[0] = 0xa0; wu[1] = 0x86; wu[2] = 0x01;                      /* 100000 */
            wu[8] = 34; memcpy(wu + 9, spk, 34);
            kv(o, k1, 1, wu, sizeof wu);
        } else {
            kv(o, k0, 1, prev.b, prev.n);
        }
        if (hd) {
            uint8_t key[34];
            if (type == 3) {
                uint8_t k17[1] = {0x17};
                taprec[0] = 0; memcpy(taprec + 1, fp, 4);
                key[0] = 0x16; memcpy(key + 1, xo, 32);
                kv(o, key, 33, taprec, 5);
                kv(o, k17, 1, xo, 32);
            } else {
                if (type == 2) { uint8_t k4[1] = {4}; redeem[0] = 0; redeem[1] = 0x14; memcpy(redeem + 2, h, 20); kv(o, k4, 1, redeem, 22); }
                key[0] = 6; memcpy(key + 1, pub, 33);
                kv(o, key, 34, fp, 4);
            }
        }
        put8(o, 0);
    }
    put8(o, 0);                                                         /* the payment output */
    if (hd) {                                                           /* the change output */
        uint8_t key[34];
        if (type == 3) {
            uint8_t k5[1] = {5};
            taprec[0] = 0; memcpy(taprec + 1, fp, 4);
            kv(o, k5, 1, xo, 32);
            key[0] = 7; memcpy(key + 1, xo, 32);
            kv(o, key, 33, taprec, 5);
        } else {
            if (type == 2) { uint8_t k0[1] = {0}; redeem[0] = 0; redeem[1] = 0x14; memcpy(redeem + 2, h, 20); kv(o, k0, 1, redeem, 22); }
            key[0] = 2; memcpy(key + 1, pub, 33);
            kv(o, key, 34, fp, 4);
        }
    }
    put8(o, 0);
}

int main(void)
{
    static const char *const NAME[4] = {"P2PKH", "P2WPKH", "P2SH-P2WPKH", "P2TR"};
    uint8_t key[32], other[32];
    const btc_net *net = btc_net_for(chain_find("btc84"));
    bip32_node m;

    sha256((const uint8_t *) "raw key of the test", 19, key);
    sha256((const uint8_t *) "another key", 11, other);
    memset(&m, 0, sizeof m);
    memcpy(m.key, key, 32);
    for (int type = 0; type < 4; type++) {
        static buf raw, hd, foreign;
        static uint8_t out_raw[8192], out_hd[8192], tx_raw[8192], tx_hd[8192];
        size_t l1, l2, t1 = 0, t2 = 0;
        int n1 = 0, n2 = 0, e1, e2;
        psbt p;
        static tx_view v1, v2;

        make_psbt(&raw, key, key, type, 0);
        make_psbt(&hd, key, key, type, 1);
        make_psbt(&foreign, other, other, type, 0);
        /* the PSBT without records, raw mode */
        CHECK(psbt_raw_key(key) == BTC_OK, "raw key set");
        CHECK(psbt_parse(&p, raw.b, raw.n) == BTC_OK, "%s: parse", NAME[type]);
        CHECK(psbt_summary(&p, net, &m, &v1) == BTC_OK && v1.nsign == 1 && !(v1.warn & TXW_NOT_MINE) && v1.out[1].mine && !v1.out[0].mine, "%s: summary: ours %d, change %d, warn %x", NAME[type], v1.nsign, v1.out[1].mine, (unsigned) v1.warn);
        e1 = psbt_sign(&p, net, &m, out_raw, sizeof out_raw, &l1, tx_raw, sizeof tx_raw, &t1, &n1);
        psbt_raw_key(NULL);
        /* the same with the records of the master of the key, no raw mode */
        CHECK(psbt_parse(&p, hd.b, hd.n) == BTC_OK, "parse hd");
        CHECK(psbt_summary(&p, net, &m, &v2) == BTC_OK && v2.nsign == 1 && v2.out[1].mine, "%s: summary with records", NAME[type]);
        e2 = psbt_sign(&p, net, &m, out_hd, sizeof out_hd, &l2, tx_hd, sizeof tx_hd, &t2, &n2);
        CHECK(e1 == BTC_OK && e2 == BTC_OK && n1 == 1 && n2 == 1, "%s: signed %d %d (%d %d signatures)", NAME[type], e1, e2, n1, n2);
        CHECK(l1 == l2 && !memcmp(out_raw, out_hd, l1), "%s: the same signed PSBT", NAME[type]);
        CHECK(t1 == t2 && t1 > 0 && !memcmp(tx_raw, tx_hd, t1), "%s: the same finished transaction (%zu bytes)", NAME[type], t1);
        CHECK(strcmp(v1.fee, v2.fee) == 0 && v1.fee[0] && v1.fee[0] != '?', "%s: fee %s", NAME[type], v1.fee);
        /* an input that pays to another key: not ours */
        CHECK(psbt_raw_key(key) == BTC_OK, "raw key set");
        CHECK(psbt_parse(&p, foreign.b, foreign.n) == BTC_OK, "parse foreign");
        CHECK(psbt_summary(&p, net, &m, &v1) == BTC_OK && v1.nsign == 0 && (v1.warn & TXW_NOT_MINE) && !v1.out[1].mine, "%s: a foreign PSBT is not ours", NAME[type]);
        CHECK(psbt_sign(&p, net, &m, out_raw, sizeof out_raw, &l1, NULL, 0, NULL, &n1) == BTC_ERR_NOKEY, "%s: nothing to sign for a foreign PSBT", NAME[type]);
        psbt_raw_key(NULL);
        /* raw mode off: the records-free PSBT is nobody's */
        CHECK(psbt_parse(&p, raw.b, raw.n) == BTC_OK && psbt_sign(&p, net, &m, out_raw, sizeof out_raw, &l1, NULL, 0, NULL, &n1) == BTC_ERR_NOKEY, "%s: without the raw mode no signature", NAME[type]);
    }
    {   /* the addresses of the raw key on the screens: every form of the Bitcoin family */
        hd_secret hs;
        hd_path none;
        char a[120];
        static const struct { const char *id, *prefix; } A[] = {{"btc84", "bc1q"}, {"btc86", "bc1p"}, {"btc49", "3"}, {"btc44", "1"}, {"ltc84", "ltc1q"}, {"doge", "D"}, {"bch", "bitcoincash:q"}};

        memset(&hs, 0, sizeof hs);
        memset(&none, 0, sizeof none);
        memcpy(hs.raw, key, 32);
        hs.raw_curve = 2;
        hs.no_bip = 1;
        for (unsigned i = 0; i < sizeof A / sizeof A[0]; i++) {
            int r = chain_address(a, sizeof a, chain_find(A[i].id), &hs, &none);

            CHECK(r > 0 && !strncmp(a, A[i].prefix, strlen(A[i].prefix)), "%s address of a raw key: %d %s", A[i].id, r, r > 0 ? a : "");
            CHECK(chain_raw_ok(chain_find(A[i].id), &hs), "%s takes a raw key", A[i].id);
        }
        hs.raw_curve = 1;
        CHECK(!chain_raw_ok(chain_find("btc84"), &hs), "an ed25519 raw key is no Bitcoin key");
    }
    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
