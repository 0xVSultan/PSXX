/* Known-answer tests of the transaction signers (EVM, Tron, XRP, Cosmos, Nostr ...): tests/txsign_vectors.txt
 * (tools/gen_txsign_vectors.py). Usage: test_txsign <path to txsign_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/evm.h"
#include "sign/kaspa.h"
#include "sign/btcmsg.h"
#include "ec/secp256k1.h"
#include "hash/ripemd160.h"
#include "sign/tron.h"
#include "sign/xrp.h"
#include "sign/cosmos.h"
#include "sign/nostr.h"
#include "sign/nip19.h"
#include "sign/nip44.h"
#include "ec/secp_pub.h"
#include "sign/solana.h"
#include "sign/stellar.h"
#include "sign/near.h"
#include "sign/polkadot.h"
#include "coin/substrate.h"
#include "sign/ton.h"
#include "sign/ada.h"
#include "sign/zec.h"
#include "util.h"

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

static void untilde(char *s) { for (; *s; s++) if (*s == '~') *s = ' '; }

/* split a field list on '|' in place; "-" becomes "" */
static int split_bar(char *s, char **f, int max)
{
    int n = 0;
    f[n++] = s;
    for (; *s && n < max; s++) if (*s == '|') { *s = 0; f[n++] = s + 1; }
    for (int i = 0; i < n; i++) { if (!strcmp(f[i], "-")) f[i] = (char *) ""; else untilde(f[i]); }
    return n;
}

static int same(const char *got, const char *want, const char *what, int ln)
{
    if (strcmp(got, want)) { printf("  %s line %d:\n    got  %s\n    want %s\n", what, ln, got, want); return 0; }
    return 1;
}

/* title|fee|total|warn|note1|note2|note3|nout|(to|amount)* against the view */
static int check_view_a(char **fl, int nf, const tx_view *v, int ln)
{
    char w[20];
    int ok = nf >= 8, no;
    if (!ok) return 0;
    no = atoi(fl[7]);
    snprintf(w, sizeof w, "%u", v->warn);
    ok &= nf == 8 + 2 * no && v->nout == no;
    ok &= same(v->title, fl[0], "title", ln); ok &= same(v->fee, fl[1], "fee", ln); ok &= same(v->total, fl[2], "total", ln);
    ok &= same(w, fl[3], "warn", ln);
    for (int i = 0; i < 3; i++) ok &= same(i < v->nnote ? v->note[i] : "", fl[4 + i], "note", ln);
    for (int i = 0; ok && i < no; i++) { ok &= same(v->out[i].to, fl[8 + 2 * i], "to", ln); ok &= same(v->out[i].amount, fl[9 + 2 * i], "amount", ln); }
    return ok;
}

typedef struct { int n; uint32_t c[8], i[8]; uint8_t k[8][32]; } kkeys;

static int kkey(void *ctx, uint32_t c, uint32_t i, uint8_t key[32])
{
    const kkeys *k = ctx;
    for (int j = 0; j < k->n; j++) if (k->c[j] == c && k->i[j] == i) { memcpy(key, k->k[j], 32); return 0; }
    return -1;
}

static void kkeys_parse(kkeys *k, char *s)
{
    k->n = 0;
    if (!strcmp(s, "-")) return;
    for (char *p = strtok(s, ","); p && k->n < 8; p = strtok(NULL, ",")) {
        unsigned c, i;
        char hx[80];
        if (sscanf(p, "%u:%u:%64s", &c, &i, hx) == 3) { k->c[k->n] = c; k->i[k->n] = i; unhex(hx, k->k[k->n], 32); k->n++; }
    }
}

static int zec_raw_ok;                                                         /* requests signed with a raw key of an account address (all their inputs are its own) */

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/txsign_vectors.txt", "r");
    static char line[40000];
    static uint8_t a[20000], b[20000], c[20000], d[200];
    static tx_view v;
    static char text_buf[NIP_PT_MAX + 1];
    static uint8_t work_buf[8192];                    /* the result buffer of the signer lends this much to a summary */
    char *tok[16];
    int ln = 0, fails = 0, total = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    txv_text = text_buf; txv_text_cap = sizeof text_buf;
    txv_work = work_buf; txv_work_cap = sizeof work_buf;
    while (fgets(line, sizeof line, f)) {
        int nt = 0, ok = 1;
        ln++;
        for (char *t = strtok(line, " \r\n"); t && nt < 16; t = strtok(NULL, " \r\n")) tok[nt++] = t;
        if (nt < 2) continue;
        total++;
        if (!strcmp(tok[0], "evmtx") && nt == 5) {
            size_t ul = unhex(tok[2], a, sizeof a), sl = unhex(tok[3], b, sizeof b), ol = 0;
            uint8_t priv[32], sig[65];
            unhex(tok[1], priv, 32);
            unhex(tok[4], d, 65);
            if (evm_sign_tx(a, ul, priv, c, sizeof c, &ol, sig) || ol != sl || memcmp(c, b, sl) || memcmp(sig, d, 65)) ok = 0;
        } else if (!strcmp(tok[0], "evmview") && nt == 3) {
            char *fl[16];
            size_t ul = unhex(tok[1], a, sizeof a);
            char w[20];
            int nf = split_bar(tok[2], fl, 16);
            ok = nf == 9 && !evm_summary(a, ul, &v);
            if (ok) {
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln);
                ok &= same(v.out[0].to, fl[1], "to", ln);
                ok &= same(v.out[0].amount, fl[2], "amount", ln);
                ok &= same(v.fee, fl[3], "fee", ln);
                ok &= same(v.total, fl[4], "total", ln);
                ok &= same(w, fl[5], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[6 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "evmauths") && nt >= 3) {                 /* the authorizations of a type 4 transaction */
            size_t ul = unhex(tok[1], a, sizeof a);
            ok = !evm_summary(a, ul, &v) && v.nout == nt - 1 && (v.warn & TXW_DELEGATION);
            for (int i = 2; ok && i < nt; i++) {
                char *fl[4];
                ok = split_bar(tok[i], fl, 4) == 2;
                if (ok) { ok &= same(v.out[i - 1].to, fl[0], "auth to", ln); ok &= same(v.out[i - 1].amount, fl[1], "auth amount", ln); }
            }
        } else if (!strcmp(tok[0], "bip322") && nt == 7) {
            uint8_t priv[32], mh[32], hb[32], txid[32], tb[32], pub[33], spk[34], w[110], want[110];
            size_t ml = unhex(tok[3], a, sizeof a), wl = unhex(tok[6], want, sizeof want), sl;
            int kind = !strcmp(tok[1], "p2tr") ? K_P2TR : K_P2WPKH, n;
            unhex(tok[2], priv, 32);
            btcmsg322_hash(a, ml, mh);
            unhex(tok[4], hb, 32);
            unhex(tok[5], tb, 32);
            ok = !memcmp(mh, hb, 32);
            if (kind == K_P2WPKH) {
                secp256k1_pubkey_create(pub, priv);
                spk[0] = 0; spk[1] = 20; hash160(pub, 33, spk + 2); sl = 22;
            } else {
                uint8_t tk[32];
                secp256k1_taproot_tweak_seckey(tk, priv, NULL, 0);
                secp256k1_xonly_pubkey(spk + 2, NULL, tk);
                spk[0] = 0x51; spk[1] = 0x20; sl = 34;
            }
            btcmsg322_spend_txid(spk, sl, mh, txid);
            ok &= !memcmp(txid, tb, 32);
            n = btcmsg_sign322(kind, a, ml, priv, w, sizeof w);
            ok &= n == (int) wl && !memcmp(w, want, wl);
            if (!ok) printf("  bip322 line %d (%s): the message hash, the to_spend txid or the signature differs (n %d, want %d)\n", ln, tok[1], n, (int) wl);
        } else if (!strcmp(tok[0], "btcmsg") && nt == 7) {
            const chain_def *cd = chain_find(tok[1]);
            const btc_net *net = cd ? btc_net_for(cd) : NULL;
            uint8_t priv[32], sig[65];
            char *fl[8], w[20];
            size_t ml = unhex(tok[3], a, sizeof a);
            unhex(tok[2], priv, 32);
            unhex(tok[4], d, 65);
            ok = net && !btcmsg_sign(net, cd->kind, a, ml, priv, sig);
            if (ok && memcmp(sig, d, 65)) { ok = 0; printf("  btcmsg line %d: the signature differs\n    got  %02x%02x%02x..\n", ln, sig[0], sig[1], sig[2]); }
            if (ok && split_bar(tok[6], fl, 8) != 6) { ok = 0; printf("  btcmsg line %d: the view has not 6 fields\n", ln); }
            if (ok) {
                btcmsg_summary(net, tok[5], a, ml, &v);
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.out[0].to, fl[1], "to", ln); ok &= same(w, fl[2], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[3 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "kassh") && nt == 4) {
            size_t tl_ = unhex(tok[1], a, sizeof a);
            uint8_t h[32];
            unhex(tok[3], d, 32);
            ok = !kaspa_sighash(a, tl_, atoi(tok[2]), h) && !memcmp(h, d, 32);
        } else if (!strcmp(tok[0], "kas") && nt >= 6) {
            static kkeys keys;
            char *fl[8], w[20];
            size_t tl_ = unhex(tok[1], a, sizeof a), ol = 0;
            int rc;
            kkeys_parse(&keys, tok[2]);
            rc = kaspa_sign(a, tl_, kkey, &keys, c, sizeof c, &ol);
            if (!strcmp(tok[3], "-")) ok = rc != KAS_OK;
            else { size_t bl = unhex(tok[3], b, sizeof b); ok = rc == KAS_OK && ol == bl && !memcmp(c, b, bl); }
            ok &= split_bar(tok[4], fl, 8) == 7 && kaspa_summary(a, tl_, kkey, &keys, &v) == KAS_OK;
            if (ok) {
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.fee, fl[1], "fee", ln); ok &= same(v.total, fl[2], "total", ln); ok &= same(w, fl[3], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[4 + i], "note", ln);
                ok &= v.nout == nt - 5;
                for (int i = 5; ok && i < nt; i++) {
                    char *of[4], mine[4];
                    ok = split_bar(tok[i], of, 4) == 3;
                    if (ok) { snprintf(mine, sizeof mine, "%d", v.out[i - 5].mine); ok &= same(v.out[i - 5].to, of[0], "to", ln); ok &= same(v.out[i - 5].amount, of[1], "amount", ln); ok &= same(mine, of[2], "mine", ln); }
                }
            }
        } else if (!strcmp(tok[0], "tronouts") && nt >= 3) {                  /* the key lines of a permission update, from the second output on */
            size_t rl = unhex(tok[1], a, sizeof a);
            ok = !tron_summary(a, rl, &v) && v.nout == nt - 1 && (v.warn & TXW_DELEGATION);
            for (int i = 2; ok && i < nt; i++) {
                char *fl[4];
                ok = split_bar(tok[i], fl, 4) == 2;
                if (ok) { ok &= same(v.out[i - 1].to, fl[0], "key to", ln); ok &= same(v.out[i - 1].amount, fl[1], "key weight", ln); }
            }
        } else if (!strcmp(tok[0], "evmauth") && nt == 5) {
            uint8_t priv[32], sig[65];
            char *fl[4];
            size_t pl = unhex(tok[2], a, sizeof a);
            unhex(tok[1], priv, 32);
            unhex(tok[3], d, 65);
            ok = !evm_auth_sign(a, pl, priv, sig) && !memcmp(sig, d, 65) && !evm_auth_summary(a, pl, &v) && split_bar(tok[4], fl, 4) == 2 && (v.warn & TXW_DELEGATION);
            if (ok) { ok &= same(v.out[0].to, fl[0], "auth to", ln); ok &= same(v.out[0].amount, fl[1], "auth amount", ln); }
            if (evm_auth_sign(a, pl - 1, priv, sig) == 0) ok = 0;                 /* a cut payload is refused */
        } else if (!strcmp(tok[0], "evmmsg") && nt == 4) {
            size_t ml = unhex(tok[2], a, sizeof a);
            uint8_t priv[32], sig[65];
            unhex(tok[1], priv, 32);
            unhex(tok[3], d, 65);
            if (evm_personal_sign(a, ml, priv, sig) || memcmp(sig, d, 65)) ok = 0;
        } else if (!strcmp(tok[0], "evmtyped") && nt == 5) {
            uint8_t priv[32], sig[65], ds[32], sh[32];
            unhex(tok[1], priv, 32); unhex(tok[2], ds, 32); unhex(tok[3], sh, 32); unhex(tok[4], d, 65);
            if (evm_typed_sign(ds, sh, priv, sig) || memcmp(sig, d, 65)) ok = 0;
        } else if (!strcmp(tok[0], "tronraw") && nt == 5) {
            size_t rl = unhex(tok[2], a, sizeof a);
            uint8_t priv[32], sig[65], id[32], idw[32];
            unhex(tok[1], priv, 32); unhex(tok[3], d, 65); unhex(tok[4], idw, 32);
            if (tron_sign(a, rl, priv, sig, id) || memcmp(sig, d, 65) || memcmp(id, idw, 32)) ok = 0;
        } else if (!strcmp(tok[0], "tronview") && nt == 3) {
            char *fl[16], w[20];
            size_t rl = unhex(tok[1], a, sizeof a);
            ok = split_bar(tok[2], fl, 16) == 9 && !tron_summary(a, rl, &v);
            if (ok) {
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.out[0].to, fl[1], "to", ln);
                ok &= same(v.out[0].amount, fl[2], "amount", ln); ok &= same(v.fee, fl[3], "fee", ln);
                ok &= same(v.total, fl[4], "total", ln); ok &= same(w, fl[5], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[6 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "xrptx") && nt == 4) {
            size_t bl = unhex(tok[2], a, sizeof a), sl = unhex(tok[3], b, sizeof b), ol = 0;
            uint8_t priv[32];
            unhex(tok[1], priv, 32);
            if (xrp_sign(a, bl, priv, c, sizeof c, &ol) || ol != sl || memcmp(c, b, sl)) ok = 0;
        } else if (!strcmp(tok[0], "xrpview") && nt == 3) {
            char *fl[16], w[20];
            size_t bl = unhex(tok[1], a, sizeof a);
            ok = split_bar(tok[2], fl, 16) == 9 && !xrp_summary(a, bl, &v);
            if (ok) {
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.out[0].to, fl[1], "to", ln);
                ok &= same(v.out[0].amount, fl[2], "amount", ln); ok &= same(v.fee, fl[3], "fee", ln);
                ok &= same(v.total, fl[4], "total", ln); ok &= same(w, fl[5], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[6 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "cossign") && nt == 5) {
            size_t dl = unhex(tok[2], a, sizeof a), tl = unhex(tok[4], b, sizeof b), ol = 0;
            uint8_t priv[32], sig[64];
            unhex(tok[1], priv, 32); unhex(tok[3], d, 64);
            if (cosmos_sign(a, dl, priv, sig, c, sizeof c, &ol) || memcmp(sig, d, 64) || ol != tl || memcmp(c, b, tl)) ok = 0;
        } else if (!strcmp(tok[0], "cosview") && nt == 3) {
            char *fl[40], w[20];
            size_t dl = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 40), no;
            ok = nf >= 7 && !cosmos_summary(a, dl, &v);
            if (ok) {
                no = atoi(fl[6]);
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= nf == 7 + 2 * no && v.nout == no;
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.fee, fl[1], "fee", ln); ok &= same(w, fl[2], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[3 + i], "note", ln);
                for (int i = 0; ok && i < no; i++) { ok &= same(v.out[i].to, fl[7 + 2 * i], "to", ln); ok &= same(v.out[i].amount, fl[8 + 2 * i], "amount", ln); }
            }
        } else if (!strcmp(tok[0], "nostr") && nt == 4) {
            static char scratch[10240], outj[8192];
            size_t jl = unhex(tok[2], a, sizeof a), el = unhex(tok[3], b, sizeof b), ol = 0;
            uint8_t priv[32];
            unhex(tok[1], priv, 32);
            if (nostr_sign((const char *) a, jl, priv, scratch, sizeof scratch, outj, sizeof outj, &ol) || ol != el || memcmp(outj, b, el)) ok = 0;
        } else if (!strcmp(tok[0], "nostrview") && nt == 3) {
            char *fl[16];
            size_t jl = unhex(tok[1], a, sizeof a);
            ok = split_bar(tok[2], fl, 16) == 5 && !nostr_summary((const char *) a, jl, &v);
            if (ok) {
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.out[0].to, fl[1], "content", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[2 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "ecdh") && nt == 4) {
            uint8_t priv[32], pub[32], want[32], got[32];
            unhex(tok[1], priv, 32); unhex(tok[2], pub, 32); unhex(tok[3], want, 32);
            ok = !secp256k1_ecdh_x(got, priv, pub) && !memcmp(got, want, 32);
        } else if ((!strcmp(tok[0], "nip44key") && nt == 4) || (!strcmp(tok[0], "nip44keybad") && nt == 3)) {
            uint8_t priv[32], pub[32], want[32], got[32];
            int r;
            unhex(tok[1], priv, 32); unhex(tok[2], pub, 32);
            r = nip44_conv_key(got, priv, pub);
            if (nt == 4) { unhex(tok[3], want, 32); ok = !r && !memcmp(got, want, 32); }
            else ok = r != 0;
        } else if (!strcmp(tok[0], "nip44enc") && nt == 5) {
            static uint8_t work[NIP44_WORK];
            static char msg[2000];
            uint8_t ck[32], nonce[32];
            const uint8_t *p;
            size_t pl;
            unhex(tok[1], ck, 32); unhex(tok[2], nonce, 32);
            pl = unhex(tok[3], a, sizeof a);
            if (pl <= NIP_PT_MAX) {                                               /* the official vectors reach 65535 bytes; this signer takes 1024 */
                int n = nip44_encrypt(msg, sizeof msg, work, ck, nonce, a, pl);
                ok = n == (int) strlen(tok[4]) && !strcmp(msg, tok[4]);
                n = nip44_decrypt(&p, work, ck, tok[4]);
                ok &= n == (int) pl && !memcmp(p, a, pl);
            }
        } else if (!strcmp(tok[0], "nip44bad") && nt == 3) {
            static uint8_t work[NIP44_WORK];
            uint8_t ck[32];
            const uint8_t *p;
            unhex(tok[1], ck, 32);
            ok = nip44_decrypt(&p, work, ck, tok[2]) < 0;
        } else if (!strcmp(tok[0], "nip04enc") && nt == 5) {
            static uint8_t work[NIP04_WORK];
            static char msg[2000], payload[2000];
            uint8_t key[32], iv[16];
            const uint8_t *p;
            size_t pl;
            int n;
            unhex(tok[1], key, 32); unhex(tok[2], iv, 16);
            pl = unhex(tok[3], a, sizeof a);
            n = nip04_encrypt(msg, sizeof msg, work, key, iv, a, pl);
            ok = n == (int) strlen(tok[4]) && !strcmp(msg, tok[4]);
            snprintf(payload, sizeof payload, "%s", tok[4]);
            n = nip04_decrypt(&p, work, key, payload);
            ok &= n == (int) pl && !memcmp(p, a, pl) && !strcmp(payload, tok[4]);
        } else if (!strcmp(tok[0], "nip04bad") && nt == 3) {
            static uint8_t work[NIP04_WORK];
            static char payload[2000];
            uint8_t key[32];
            const uint8_t *p;
            unhex(tok[1], key, 32);
            snprintf(payload, sizeof payload, "%s", tok[2]);
            ok = nip04_decrypt(&p, work, key, payload) < 0;
        } else if (!strcmp(tok[0], "nip19enc") && nt == 4) {
            char s[100];
            uint8_t k[32];
            unhex(tok[2], k, 32);
            ok = nip19_encode32(s, sizeof s, tok[1], k) > 0 && !strcmp(s, tok[3]);
        } else if (!strcmp(tok[0], "nip19dec") && nt == 9) {
            nip19 n;
            uint8_t want[32];
            int t = nip19_decode(&n, tok[1]);
            ok = t == atoi(tok[2]);
            if (ok) {
                const char *rl = !strcmp(tok[6], "-") ? "" : tok[6], *dd = !strcmp(tok[7], "-") ? "" : tok[7];
                if (strcmp(tok[3], "-")) { unhex(tok[3], want, 32); ok &= !memcmp(want, n.id, 32); }
                if (strcmp(tok[4], "-")) { unhex(tok[4], want, 32); ok &= n.have_author && !memcmp(want, n.author, 32); } else ok &= !n.have_author;
                if (strcmp(tok[5], "-")) ok &= n.have_kind && n.kind == (uint32_t) strtoul(tok[5], NULL, 10); else ok &= !n.have_kind;
                ok &= !strcmp(n.relay, rl) && !strcmp(n.d, dd) && n.nrelays == atoi(tok[8]);
            }
        } else if (!strcmp(tok[0], "nip19bad") && nt == 2) {
            nip19 n;
            ok = nip19_decode(&n, !strcmp(tok[1], "-") ? "" : tok[1]) < 0;
        } else if (!strcmp(tok[0], "nostrfail") && nt == 3) {
            static char scratch[10240], outj[8192];
            size_t jl = unhex(tok[2], a, sizeof a), ol = 0;
            uint8_t priv[32];
            unhex(tok[1], priv, 32);
            ok = nostr_sign((const char *) a, jl, priv, scratch, sizeof scratch, outj, sizeof outj, &ol) != 0;
        } else if ((!strcmp(tok[0], "nostrdec") && nt == 4) || (!strcmp(tok[0], "nostrdecfail") && nt == 3)) {
            static char scratch[10240], outj[8192];
            size_t jl = unhex(tok[2], a, sizeof a), ol = 0, pl = nt == 4 ? unhex(tok[3], b, sizeof b) : 0;
            uint8_t priv[32];
            int r;
            unhex(tok[1], priv, 32);
            r = nostr_decrypt((const char *) a, jl, priv, scratch, sizeof scratch, outj, sizeof outj, &ol);
            if (nt == 4) ok = !r && ol == pl && !memcmp(outj, b, pl);
            else ok = r != 0;
        } else if (!strcmp(tok[0], "nostrdecview") && nt == 4) {
            char *fl[16];
            size_t jl = unhex(tok[2], a, sizeof a);
            uint8_t priv[32];
            unhex(tok[1], priv, 32);
            ok = split_bar(tok[3], fl, 16) == 5 && !nostr_decrypt_summary((const char *) a, jl, priv, &v);
            if (ok) {
                ok &= same(v.title, fl[0], "title", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[1 + i], "note", ln);
                ok &= same(txv_text, fl[4], "text", ln) && v.text_len == (int) strlen(fl[4]) && v.nout == 0;
            }
        } else if (!strcmp(tok[0], "nostrtext") && nt == 4) {                      /* a long content: the notes and the whole text on pages of its own */
            char *fl[16];
            size_t jl = unhex(tok[1], a, sizeof a);
            ok = split_bar(tok[2], fl, 16) == 3 && !nostr_summary((const char *) a, jl, &v);
            if (ok) {
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[i], "note", ln);
                split_bar(tok[3], fl, 16);
                ok &= same(v.text_len ? txv_text : "", fl[0], "text", ln) && v.text_len == (int) strlen(fl[0]);
            }
        } else if (!strcmp(tok[0], "solsign") && nt == 5) {
            size_t ml = unhex(tok[2], a, sizeof a), tl = unhex(tok[4], b, sizeof b), ol = 0;
            uint8_t seed[32], sig[64];
            unhex(tok[1], seed, 32); unhex(tok[3], d, 64);
            if (solana_sign(a, ml, seed, sig, c, sizeof c, &ol) || memcmp(sig, d, 64) || ol != tl || memcmp(c, b, tl)) ok = 0;
        } else if (!strcmp(tok[0], "solview") && nt == 3) {
            char *fl[60];
            size_t ml = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 60);
            ok = !solana_summary(a, ml, &v) && check_view_a(fl, nf, &v, ln);
        } else if (!strcmp(tok[0], "xlmsign") && nt == 6) {
            size_t pl = unhex(tok[2], b, sizeof b), tl = unhex(tok[3], a, sizeof a);
            char pass[200];
            uint8_t seed[32], sig[64], hint[4], hw[4];
            memcpy(pass, b, pl); pass[pl] = 0;
            unhex(tok[1], seed, 32); unhex(tok[4], d, 64); unhex(tok[5], hw, 4);
            if (stellar_sign(a, tl, pass, seed, sig, hint) || memcmp(sig, d, 64) || memcmp(hint, hw, 4)) ok = 0;
        } else if (!strcmp(tok[0], "xlmview") && nt == 3) {
            char *fl[60];
            size_t tl = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 60);
            ok = !stellar_summary(a, tl, &v) && check_view_a(fl, nf, &v, ln);
        } else if (!strcmp(tok[0], "nearsign") && nt == 5) {
            size_t tl = unhex(tok[2], a, sizeof a), sl = unhex(tok[4], b, sizeof b), ol = 0;
            uint8_t seed[32], sig[64];
            unhex(tok[1], seed, 32); unhex(tok[3], d, 64);
            if (near_sign(a, tl, seed, sig, c, sizeof c, &ol) || memcmp(sig, d, 64) || ol != sl || memcmp(c, b, sl)) ok = 0;
        } else if (!strcmp(tok[0], "nearbad") && nt == 3) {
            size_t tl = unhex(tok[2], a, sizeof a), ol = 0;
            uint8_t seed[32], sig[64];
            unhex(tok[1], seed, 32);
            if (near_sign(a, tl, seed, sig, c, sizeof c, &ol) != NEAR_ERR_KEY) ok = 0;
        } else if (!strcmp(tok[0], "nearview") && nt == 3) {
            char *fl[60];
            size_t tl = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 60);
            ok = !near_summary(a, tl, &v) && check_view_a(fl, nf, &v, ln);
        } else if (!strcmp(tok[0], "dotsign") && nt == 5) {
            size_t pl = unhex(tok[3], a, sizeof a);
            uint8_t key[32], sig[65];
            unhex(tok[2], key, 32); unhex(tok[4], d, 65);
            if (tok[1][0] == '0') polkadot_sign_ed25519(sig, key, a, pl);
            else { uint8_t sc[32]; sr25519_expand(sc, key); polkadot_sign_sr25519(sig, sc, a, pl); }
            if (memcmp(sig, d, 65)) ok = 0;
        } else if (!strcmp(tok[0], "dotview") && nt == 4) {
            char *fl[16], w[20];
            size_t pl = unhex(tok[2], a, sizeof a);
            ok = split_bar(tok[3], fl, 16) == 8 && !polkadot_summary(a, pl, atoi(tok[1]), &v);
            if (ok) {
                snprintf(w, sizeof w, "%u", v.warn);
                ok &= same(v.title, fl[0], "title", ln); ok &= same(v.out[0].to, fl[1], "to", ln);
                ok &= same(v.out[0].amount, fl[2], "amount", ln); ok &= same(v.total, fl[3], "total", ln); ok &= same(w, fl[4], "warn", ln);
                for (int i = 0; i < 3; i++) ok &= same(i < v.nnote ? v.note[i] : "", fl[5 + i], "note", ln);
            }
        } else if (!strcmp(tok[0], "tonsign") && nt == 5) {
            size_t bl = unhex(tok[2], a, sizeof a);
            uint8_t seed[32], sig[64], hash[32], hw[32];
            unhex(tok[1], seed, 32); unhex(tok[3], hw, 32); unhex(tok[4], d, 64);
            if (ton_sign(a, bl, seed, sig, hash) || memcmp(hash, hw, 32) || memcmp(sig, d, 64)) ok = 0;
        } else if (!strcmp(tok[0], "tonview") && nt == 3) {
            char *fl[60];
            size_t bl = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 60);
            ok = !ton_summary(a, bl, &v) && check_view_a(fl, nf, &v, ln);
        } else if (!strcmp(tok[0], "adasign") && nt == 6) {
            size_t bl = unhex(tok[2], a, sizeof a);
            uint8_t node[96], vk[32], sig[64], hash[32], hw[32], vw[32];
            unhex(tok[1], node, 96); unhex(tok[3], hw, 32); unhex(tok[4], vw, 32); unhex(tok[5], d, 64);
            if (ada_sign(a, bl, node, vk, sig, hash) || memcmp(hash, hw, 32) || memcmp(vk, vw, 32) || memcmp(sig, d, 64)) ok = 0;
        } else if (!strcmp(tok[0], "adaview") && nt == 3) {
            char *fl[60];
            size_t bl = unhex(tok[1], a, sizeof a);
            int nf = split_bar(tok[2], fl, 60);
            ok = !ada_summary(a, bl, &v) && check_view_a(fl, nf, &v, ln);
        } else if (!strcmp(tok[0], "zecsign") && nt == 4) {
            size_t rl = unhex(tok[2], a, sizeof a), sl = unhex(tok[3], b, sizeof b), ol = 0;
            uint8_t seed[64];
            bip32_node m;
            zec_keys zk;
            unhex(tok[1], seed, 64);
            zk.master = &m; zk.orchard_sk = NULL; zk.raw = NULL;
            if (bip32_master(&m, seed, 64) || zec_sign(a, rl, &zk, c, sizeof c, &ol) || ol != sl || memcmp(c, b, sl)) ok = 0;
            for (int ac = 0; ok && ac < 3; ac++)                                  /* a raw key of an account address signs a request whose inputs are all its own: the same bytes */
                for (int ix = 0; ix < 30; ix++) {
                    static const uint32_t H = 0x80000000u;
                    uint32_t pth[5] = {H | 44, H | 133, H | (uint32_t) ac, 0, (uint32_t) ix};
                    bip32_node n = m;
                    zec_keys zr = {NULL, NULL, NULL};
                    uint8_t c2[40000];
                    size_t o2 = 0;

                    if (bip32_derive_path(&n, pth, 5)) { ok = 0; break; }
                    zr.raw = n.key;
                    if (zec_sign(a, rl, &zr, c2, sizeof c2, &o2) == 0) {
                        zec_raw_ok++;
                        if (o2 != sl || memcmp(c2, b, sl)) ok = 0;
                    }
                    secure_zero(&n, sizeof n);
                }
        } else if (!strcmp(tok[0], "zecerr") && nt == 4) {
            size_t rl = unhex(tok[2], a, sizeof a), ol = 0;
            uint8_t seed[64];
            bip32_node m;
            zec_keys zk;
            unhex(tok[1], seed, 64);
            zk.master = &m; zk.orchard_sk = NULL; zk.raw = NULL;
            if (bip32_master(&m, seed, 64) || zec_sign(a, rl, &zk, c, sizeof c, &ol) != atoi(tok[3])) ok = 0;
        } else if (!strcmp(tok[0], "zecview") && nt == 3) {
            char *fl[60];
            size_t rl = unhex(tok[1], a, sizeof a);
            zec_keys zk0 = {NULL, NULL, NULL};
            int nf = split_bar(tok[2], fl, 60);
            ok = !zec_summary(a, rl, &zk0, &v) && check_view_a(fl, nf, &v, ln);
        } else {
            total--;
            continue;
        }
        if (!ok) { fails++; printf("FAIL %s line %d\n", tok[0], ln); }
    }
    fclose(f);
    if (!zec_raw_ok) { fails++; printf("FAIL no Zcash request was signed with a raw key\n"); }
    printf("TXSIGN %s: %d checks, %d failed\n", fails ? "FAILED" : "OK", total, fails);
    return fails != 0;
}
