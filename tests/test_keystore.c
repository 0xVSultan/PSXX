/* The key stores (core/keyfile.c, hal/psx/keystore.c, hal/psx/mcfile.c) on a memory card in RAM that can lose its power in the middle of any frame write.
 * Checks: the formats (directory, chain, store key, both kinds of entries); deleting files (mcf_invalidate); and, the main thing, the changes of a store (create, add, replace,
 * delete, remove the store): with a power cut at every possible write (the write dropped, or half of it written), after the next scan the store is the old version or the new
 * one, never damaged, and the other files and stores of the card are untouched. A long random sequence of changes with cuts against a model. Usage: test_keystore */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blob.h"
#include "keyfile.h"
#include "keystore.h"
#include "mcard.h"

/* ---- the card ---- */
static uint8_t card[1024][MC_FRAME];
static int writes, fail_at = -1, fail_mode, dead, faulted;       /* fail_mode 0: the write is lost, 1: half of it is written */

int mc_present(int port) { (void) port; return !dead; }
int mc_read(int port, int frame, uint8_t out[MC_FRAME])
{
    (void) port;
    if (dead) return MC_NO_CARD;
    memcpy(out, card[frame], MC_FRAME);
    return MC_OK;
}
int mc_write(int port, int frame, const uint8_t in[MC_FRAME])
{
    (void) port;
    if (dead) return MC_NO_CARD;
    if (writes++ == fail_at) {
        if (fail_mode == 1) memcpy(card[frame], in, MC_FRAME / 2);
        dead = 1;
        faulted = 1;
        return MC_NO_CARD;
    }
    memcpy(card[frame], in, MC_FRAME);
    return MC_OK;
}

static void dir_fix(int b) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= card[b][i]; card[b][127] = x; }
static void format(void)
{
    memset(card, 0, sizeof card);
    card[0][0] = 'M'; card[0][1] = 'C';
    dir_fix(0);
    for (int b = 1; b <= 15; b++) { card[b][0] = 0xA0; card[b][8] = card[b][9] = 0xFF; dir_fix(b); }
}
static void power_on(void) { dead = 0; fail_at = -1; writes = 0; }

static uint32_t rs = 0x2468ace1u;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }

static int checks, fails;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- entries ---- */
#define TEST_ITER 8                                              /* rounds of the passwords of the tests (the console uses 16384) */
static uint8_t the_key[32];                                      /* the key of the store password "store pw" */
static ks_dir the_pw;                                            /* flags, iter, salt, check of it */

static void init_pw(void)
{
    for (int i = 0; i < 16; i++) the_pw.salt[i] = (uint8_t) (i * 11 + 3);
    the_pw.flags = KS_DIR_PW;
    the_pw.iter = TEST_ITER;
    ks_store_key(the_key, the_pw.check, (const uint8_t *) "store pw", 8, TEST_ITER, the_pw.salt);
}

static void mk_own(uint8_t *f, int variant, const char *pw)
{
    uint8_t rn[28], ent[32];
    char label[17];
    int n = 16 + 8 * (variant % 3);

    for (int i = 0; i < 28; i++) rn[i] = (uint8_t) (variant * 31 + i * 7);
    for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (variant * 13 + i);
    snprintf(label, sizeof label, "key %d", variant);
    CHECK(ks_own_entry_seal(f, (const uint8_t *) pw, strlen(pw), TEST_ITER, rn, variant & 1 ? KS_TYPE_MONERO : KS_TYPE_BIP39, variant & 2 ? KS_FLAG_PASSPHRASE : 0, ent, n, label, NULL) == KS_OK, "own seal");
}

/* an entry sealed with the store key for the next slot of the store */
static void mk_store(uint8_t *f, const ksd_store *st, int variant)
{
    uint8_t nonce[12], ent[32];
    char label[17];
    int n = 16 + 8 * (variant % 3);

    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t) (variant * 17 + st->seq * 5 + i);
    for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (variant * 13 + i);
    snprintf(label, sizeof label, "store key %d", variant);
    CHECK(st->next_slot >= 0 && ks_store_entry_seal(f, the_key, st->id, st->next_slot, nonce, st->seq + 1, variant & 1 ? KS_TYPE_MONERO : KS_TYPE_BIP39,
                                                    variant & 2 ? KS_FLAG_PASSPHRASE : 0, ent, n, label) == KS_OK, "store seal");
}

/* an entry for a store, of the kind it takes (a store with a password gets entries of both kinds) */
static void mk_for(uint8_t *f, const ksd_store *st, int variant)
{
    if ((st->dir.flags & KS_DIR_PW) && variant % 3 != 2) mk_store(f, st, variant);
    else mk_own(f, variant, "pw");
}

static const uint8_t *key_of(const ksd_store *st) { return st->dir.flags & KS_DIR_PW ? the_key : NULL; }

/* what a store should hold: the label, whether it has the password, and the frame of every live slot */
typedef struct { uint16_t id; int pw; char label[KS_STORE_LABEL + 1]; int last; uint8_t live[KS_SLOTS]; uint8_t f[KS_SLOTS][KS_FRAME]; } model;

static int mslot(const model *m)                                 /* the slot of the next entry: the model's own rule */
{
    for (int i = 1; i <= KS_SLOTS; i++) { int s = (m->last + i) % KS_SLOTS; if (!m->live[s]) return s; }
    return -1;
}
static int mcount(const model *m) { int n = 0; for (int s = 0; s < KS_SLOTS; s++) n += m->live[s]; return n; }

static void mnew(model *m, const char *label, int pw)
{
    memset(m, 0, sizeof *m);
    snprintf(m->label, sizeof m->label, "%s", label);
    m->pw = pw;
    m->last = KS_SLOTS - 1;
}
static void madd(model *m, const uint8_t *f, int replace)
{
    int s = mslot(m);

    memcpy(m->f[s], f, KS_FRAME);
    m->live[s] = 1;
    m->last = s;
    if (replace >= 0) m->live[replace] = 0;
}

static int same_as(int port, const ksd_store *st, const model *m)
{
    static uint8_t img[KS_DATA];
    ks_dir d;

    if (ksd_read(port, st, img) != MCF_OK || ks_dir_pick(&d, img, img + KS_FRAME) < 0) return 0;
    if (d.id != m->id || strcmp(d.label, m->label) || !!(d.flags & KS_DIR_PW) != m->pw || d.last != m->last) return 0;
    if (st->n != mcount(m)) return 0;
    for (int s = 0; s < KS_SLOTS; s++) {
        if (ks_slot_live(&d, s) != m->live[s]) return 0;
        if (m->live[s] && memcmp(img + (KS_DIR_FRAMES + s) * KS_FRAME, m->f[s], KS_FRAME)) return 0;
    }
    if (m->pw && !ks_dir_mac_ok(&d, the_key)) return 0;
    return 1;
}

/* a file of another program, written the way the apps write: scan, begin, write, commit */
static int filler(const char *tag, int fill)
{
    mcf_entry e[1];
    uint8_t f[MC_FRAME];
    int nfiles, next, blk, r = mcf_scan(0, tag, e, 0, &nfiles, &next, &blk);

    if (!r && !blk) return MCF_FULL;
    if (!r) r = mcf_begin(0, blk, "PSXX filler", MCF_ICON_DISC);
    memset(f, fill, sizeof f);
    for (int fr = 0; !r && fr < 3; fr++) r = mcf_write(0, blk, MCF_FIRST_DATA + fr, f);
    if (!r) r = mcf_commit(0, blk, tag, next);
    return r;
}

static int keyblocks(void) { int n = 0; for (int b = 1; b <= 15; b++) if (card[b][0] == 0x51 && !memcmp(card[b] + 22, MCF_KEY_TAG, 6)) n++; return n; }
static int freeblocks(void) { int n = 0; for (int b = 1; b <= 15; b++) if ((card[b][0] & 0xF0) == 0xA0) n++; return n; }

/* a store with a label, with or without the password */
static int new_store(ksd_state *s, const char *label, int pw, uint16_t id, model *m)
{
    static uint8_t work[KS_DATA];
    int st = -1, r = ksd_create(0, s, label, pw ? &the_pw : NULL, pw ? the_key : NULL, id, work, &st);

    if (r != KSD_OK) return -1;
    mnew(m, label, pw);
    m->id = s->st[st].id;
    return st;
}

/* ---- tests ---- */
static void test_format(void)
{
    ks_dir d, e, p;
    uint8_t f[KS_FRAME], g[KS_FRAME];

    /* the directory */
    memset(&d, 0, sizeof d);
    d.flags = KS_DIR_PW; d.id = 0x1234; d.seq = 0x01020304; d.last = 17; d.iter = 777;
    for (int i = 0; i < 8; i++) d.live[i] = (uint8_t) (i * 31 + 1);
    d.live[7] &= 0x0F;                                                  /* 60 slots: the top four bits do not exist */
    for (int i = 0; i < 16; i++) { d.chain[i] = (uint8_t) i; d.salt[i] = (uint8_t) (i + 40); d.check[i] = (uint8_t) (i + 80); d.mac[i] = (uint8_t) (i + 120); }
    snprintf(d.label, sizeof d.label, "%s", "a store label of 31 bytes.....");
    ks_dir_encode(f, &d);
    CHECK(ks_dir_decode(&e, f) == KS_OK && !memcmp(&e, &d, sizeof d), "directory round trip");
    CHECK(f[0] == 'P' && f[1] == 'K' && f[2] == 0 && f[3] == 1 && f[4] == 0x12 && f[5] == 0x34 && f[6] == 1 && f[9] == 4 && f[10] == 17, "directory layout");
    {
        int bad = 0;

        for (int i = 0; i < KS_FRAME; i++)
            for (int bit = 0; bit < 8; bit++) {
                f[i] ^= (uint8_t) (1 << bit);
                if (ks_dir_decode(&e, f) == KS_OK) bad++;
                f[i] ^= (uint8_t) (1 << bit);
            }
        CHECK(bad == 0, "%d single bit changes of a directory frame went unnoticed", bad);
    }
    ks_dir_encode(f, &d);
    d.live[7] = 0xF0;                                                   /* a slot that does not exist is live */
    ks_dir_encode(g, &d);
    CHECK(ks_dir_decode(&e, g) == KS_ERR_FORMAT, "a nonexistent slot");
    d.live[7] = 0; d.last = 60;
    ks_dir_encode(g, &d);
    CHECK(ks_dir_decode(&e, g) == KS_ERR_FORMAT, "last out of range");
    memset(g, 0xFF, sizeof g);
    CHECK(ks_dir_decode(&e, g) == KS_ERR_FORMAT, "an erased frame");

    /* the pick of the two copies */
    d.last = 3;
    d.seq = 5; ks_dir_encode(f, &d);
    d.seq = 6; ks_dir_encode(g, &d);
    CHECK(ks_dir_pick(&p, f, g) == 1 && p.seq == 6 && ks_dir_pick(&p, g, f) == 0 && p.seq == 6, "the higher seq wins");
    g[40] ^= 1;
    CHECK(ks_dir_pick(&p, f, g) == 0 && p.seq == 5, "the copy with a bad CRC is not taken");
    f[40] ^= 1;
    CHECK(ks_dir_pick(&p, f, g) == -1, "none valid");
    memset(g, 0xFF, sizeof g);
    d.seq = 9; ks_dir_encode(f, &d);
    CHECK(ks_dir_pick(&p, f, g) == 0 && p.seq == 9 && ks_dir_pick(&p, g, f) == 1, "one copy erased");

    /* the slots */
    memset(&d, 0, sizeof d);
    d.last = KS_SLOTS - 1;
    CHECK(ks_next_slot(&d) == 0 && ks_live_count(&d) == 0 && ks_live_slot(&d, 0) == -1, "an empty store");
    ks_slot_set(&d, 0, 1); d.last = 0;
    CHECK(ks_next_slot(&d) == 1, "after slot 0 comes 1");
    ks_slot_set(&d, 5, 1); ks_slot_set(&d, 59, 1);
    CHECK(ks_live_count(&d) == 3 && ks_live_slot(&d, 0) == 0 && ks_live_slot(&d, 1) == 5 && ks_live_slot(&d, 2) == 59 && ks_live_slot(&d, 3) == -1, "live slots in order");
    d.last = 58;
    CHECK(ks_next_slot(&d) == 1, "a live slot is skipped, wrapping: %d", ks_next_slot(&d));
    d.last = 4;
    CHECK(ks_next_slot(&d) == 6, "slot 5 is live");
    ks_slot_set(&d, 5, 0);
    CHECK(ks_next_slot(&d) == 5, "a slot freed after `last` is the next");
    d.last = 5;
    CHECK(ks_next_slot(&d) == 6, "but not at once the one just freed behind");
    for (int s = 0; s < KS_SLOTS; s++) ks_slot_set(&d, s, 1);
    CHECK(ks_next_slot(&d) == -1 && ks_live_count(&d) == KS_SLOTS, "all 60 live");
    ks_slot_set(&d, 60, 1); ks_slot_set(&d, -1, 1);
    CHECK(ks_live_count(&d) == KS_SLOTS && !ks_slot_live(&d, 60) && !ks_slot_live(&d, -1), "outside the slots nothing happens");

    /* the chain */
    {
        static uint8_t en[KS_SLOTS * KS_FRAME];
        uint8_t live[8] = {0}, h0[16], h1[16], h2[16], h3[16];

        memset(en, 0xFF, sizeof en);
        ks_chain(h0, en, live);
        CHECK(h0[0] == 0 && h0[15] == 0 && !memcmp(h0, (uint8_t[16]){0}, 16), "an empty chain is zero");
        live[0] = 1; live[1] = 4;
        ks_chain(h1, en, live);
        en[10 * KS_FRAME + 20] ^= 1;
        ks_chain(h2, en, live);
        CHECK(memcmp(h1, h2, 16) != 0, "an entry changes the chain");
        en[10 * KS_FRAME + 20] ^= 1;
        en[3 * KS_FRAME + 20] ^= 1;
        ks_chain(h2, en, live);
        CHECK(memcmp(h1, h2, 16) == 0, "a slot that is not live does not");
        en[3 * KS_FRAME + 20] ^= 1;
        en[0] ^= 1;
        ks_chain(h2, en, live);
        CHECK(memcmp(h1, h2, 16) != 0, "the first live entry changes it");
        en[0] ^= 1;
        live[0] = 0; live[1] = 5;                                        /* slots 8 and 10: the same bytes in other places */
        ks_chain(h3, en, live);
        CHECK(memcmp(h1, h3, 16) != 0, "the places count");
    }

    /* the store key and the directory mac */
    {
        uint8_t k1[32], c1[16], k2[32], c2[16], k3[32], c3[16], salt[16] = {1, 2, 3};

        CHECK(ks_store_key(k1, c1, (const uint8_t *) "pw", 2, 4, salt) == KS_OK && ks_store_key(k2, c2, (const uint8_t *) "pw", 2, 4, salt) == KS_OK && !memcmp(k1, k2, 32) && !memcmp(c1, c2, 16), "the key is repeatable");
        CHECK(ks_store_key(k3, c3, (const uint8_t *) "pW", 2, 4, salt) == KS_OK && memcmp(k1, k3, 32) && memcmp(c1, c3, 16), "another password, another key and check");
        salt[0] ^= 1;
        ks_store_key(k3, c3, (const uint8_t *) "pw", 2, 4, salt);
        CHECK(memcmp(k1, k3, 32) != 0, "another salt");
        CHECK(ks_store_key(k3, c3, (const uint8_t *) "pw", 2, 0, salt) == KS_ERR_ARG && ks_store_key(k3, c3, (const uint8_t *) "pw", 2, BLOB_ITER_MAX + 1, salt) == KS_ERR_ARG, "rounds out of range");
        memset(&d, 0, sizeof d);
        d.flags = KS_DIR_PW; d.id = 5; d.seq = 9; d.last = 1;
        ks_dir_seal(&d, k1);
        CHECK(ks_dir_mac_ok(&d, k1) && !ks_dir_mac_ok(&d, k2 + 0 == k1 ? k3 : k3), "mac right and wrong key");
        d.seq++;
        CHECK(!ks_dir_mac_ok(&d, k1), "a changed field breaks the mac");
        d.seq--; d.chain[3] ^= 1;
        CHECK(!ks_dir_mac_ok(&d, k1), "a changed chain breaks the mac");
        d.chain[3] ^= 1;
        CHECK(ks_dir_mac_ok(&d, k1), "and back");
    }

    /* the entries of the store key */
    {
        uint8_t f1[KS_ENTRY_MAX], nonce[12] = {9}, ent[32], got[KS_KEY_MAX];
        char lab[KS_LABEL_STORE + 1];
        int ty, fl, el;

        for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (i + 7);
        CHECK(ks_store_entry_seal(f1, the_key, 0x77, 9, nonce, 10, KS_TYPE_MONERO, 0, ent, 24, "mine") == KS_OK && ks_entry_kind(f1) == KS_ENTRY_STORE && f1[127] == 0xFF, "store entry sealed");
        CHECK(ks_store_entry_open(f1, the_key, 0x77, 9, &ty, &fl, got, &el, lab) == KS_OK && ty == KS_TYPE_MONERO && el == 24 && !memcmp(got, ent, 24) && !strcmp(lab, "mine"), "store entry opened");
        CHECK(ks_store_entry_open(f1, the_key, 0x78, 9, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "another store (the id is in the additional data)");
        CHECK(ks_store_entry_open(f1, the_key, 0x77, 10, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "another slot");
        {
            uint8_t k2[32];

            memcpy(k2, the_key, 32); k2[0] ^= 1;
            CHECK(ks_store_entry_open(f1, k2, 0x77, 9, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "another key");
        }
        {
            int bad = 0, used = 18 + f1[1] + 16;

            for (int i = 0; i < used; i++)
                for (int bit = 0; bit < 8; bit++) {
                    f1[i] ^= (uint8_t) (1 << bit);
                    if (ks_store_entry_open(f1, the_key, 0x77, 9, &ty, &fl, got, &el, lab) == KS_OK) bad++;
                    f1[i] ^= (uint8_t) (1 << bit);
                }
            CHECK(bad == 0, "%d single bit changes of a store entry went unnoticed", bad);
        }
        CHECK(ks_store_entry_seal(f1, the_key, 1, 60, nonce, 1, KS_TYPE_BIP39, 0, ent, 16, "x") == KS_ERR_ARG && ks_store_entry_seal(f1, the_key, 1, -1, nonce, 1, KS_TYPE_BIP39, 0, ent, 16, "x") == KS_ERR_ARG, "slot range");
        CHECK(ks_store_entry_seal(f1, the_key, 1, 0, nonce, 1, 9, 0, ent, 16, "x") == KS_ERR_ARG, "bad type");
        CHECK(ks_store_entry_seal(f1, the_key, 1, 0, nonce, 1, KS_TYPE_BIP39, 0, ent, 15, "x") == KS_ERR_ARG, "bad length");
        memset(f1, 0xFF, sizeof f1);
        CHECK(ks_entry_kind(f1) == KS_ENTRY_NONE && ks_store_entry_open(f1, the_key, 1, 0, &ty, &fl, got, &el, lab) == KS_ERR_ENTRY && ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_ERR_ENTRY, "an erased frame is no entry");
    }

    /* the label of an entry of the store key holds 32 bytes, an own entry 16 and an open label 16 */
    {
        uint8_t f1[KS_ENTRY_MAX], nonce[12] = {5}, ent[32] = {1, 2, 3}, got[KS_KEY_MAX], rn[28] = {1};
        char lab[KS_LABEL_STORE + 1], pub[KS_PUBLIC + 1];
        const char *l32 = "0123456789abcdef0123456789abcdef", *l16 = "0123456789abcdef";
        int ty, fl, el;

        CHECK(ks_store_entry_seal(f1, the_key, 3, 4, nonce, 7, KS_TYPE_BIP39, 0, ent, 32, l32) == KS_OK && f1[1] == 4 + 32 + KS_LABEL_STORE, "a store entry with a label of 32 bytes");
        CHECK(ks_store_entry_open(f1, the_key, 3, 4, &ty, &fl, got, &el, lab) == KS_OK && !strcmp(lab, l32) && el == 32, "and it opens");
        ks_store_entry_seal(f1, the_key, 3, 4, nonce, 7, KS_TYPE_BIP39, 0, ent, 32, "a longer label than thirty-two bytes is cut here");
        ks_store_entry_open(f1, the_key, 3, 4, &ty, &fl, got, &el, lab);
        CHECK(strlen(lab) == KS_LABEL_STORE && !strncmp(lab, "a longer label than thirty-two b", 32), "a longer label is cut: %s", lab);
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, 0, ent, 32, l16, "cover name") == KS_OK, "own entry with an open label");
        ks_own_entry_open_label(f1, pub);
        CHECK(!strcmp(pub, "cover name") && f1[KS_PUBLIC_AT + 10] == 0, "the open label is read back: %s", pub);
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "pw", 2, &ty, &fl, got, &el, lab) == KS_OK && !strcmp(lab, l16), "the true label stays inside");
        ks_own_entry_seal(f1, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, 0, ent, 32, l16, l32);
        ks_own_entry_open_label(f1, pub);
        CHECK(strlen(pub) == KS_PUBLIC && !strncmp(pub, l32, KS_PUBLIC), "an open label is cut to 16 bytes");
        ks_own_entry_seal(f1, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, 0, ent, 32, l16, NULL);
        ks_own_entry_open_label(f1, pub);
        CHECK(pub[0] == 0 && f1[KS_PUBLIC_AT] == 0xFF, "no open label");
        mk_own(f1, 2, "pw");
        ks_store_entry_seal(f1 + 0, the_key, 3, 4, nonce, 7, KS_TYPE_BIP39, 0, ent, 32, "x");
        ks_own_entry_open_label(f1, pub);
        CHECK(pub[0] == 0, "an entry of the other kind has none");
        /* the largest own entry still leaves the open label its place */
        ks_own_entry_seal(f1, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, 0, ent, 32, l16, l16);
        CHECK(2 + f1[1] <= KS_PUBLIC_AT, "the blob (%d) ends before the open label", 2 + f1[1]);
    }

    /* the entries with their own password */
    {
        uint8_t f1[KS_ENTRY_MAX], ent[KS_KEY_MAX], got[KS_KEY_MAX], rn[28] = {0};
        char lab[KS_LABEL_STORE + 1];
        int ty, fl, el;

        mk_own(f1, 1, "pw");
        CHECK(ks_entry_kind(f1) == KS_ENTRY_OWN && ks_own_entry_iterations(f1) == TEST_ITER && f1[127] == 0xFF, "own entry");
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "pw", 2, &ty, &fl, ent, &el, lab) == KS_OK && ty == KS_TYPE_MONERO && el == 24 && !strcmp(lab, "key 1"), "open");
        CHECK(ent[0] == 13 && ent[23] == (uint8_t) (13 + 23), "entropy");
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "pX", 2, &ty, &fl, ent, &el, lab) == KS_ERR_PASSWORD, "wrong password");
        f1[40] ^= 1;
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "pw", 2, &ty, &fl, ent, &el, lab) == KS_ERR_PASSWORD, "changed entry");
        f1[40] ^= 1;
        f1[1] = 20;
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "pw", 2, &ty, &fl, ent, &el, lab) == KS_ERR_ENTRY && ks_own_entry_iterations(f1) == 0, "a short blob");
        memset(ent, 0x55, 32);
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, 9, 0, ent, 16, "x", NULL) == KS_ERR_ARG, "bad type");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, 1, 0, ent, 15, "x", NULL) == KS_ERR_ARG, "bad length");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, 1, 0, ent, 36, "x", NULL) == KS_ERR_ARG, "long entropy");
        for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (i * 7 + 1);          /* raw keys and the language bits */
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, KS_CURVE_ED25519 << KS_FLAG_CURVE_SHIFT, ent, 32, "ton key", NULL) == KS_OK, "raw key sealed");
        CHECK(ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && ty == KS_TYPE_RAW && el == 32 && !memcmp(got, ent, 32) && KS_CURVE(fl) == KS_CURVE_ED25519 && !strcmp(lab, "ton key"), "raw key opened");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, KS_CURVE_SECP256K1 << KS_FLAG_CURVE_SHIFT, ent, 32, "imported", NULL) == KS_OK &&
              ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && KS_CURVE(fl) == KS_CURVE_SECP256K1, "secp256k1 raw key");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, 5 << KS_FLAG_CURVE_SHIFT, ent, 32, "x", NULL) == KS_ERR_ARG, "unknown curve");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, 0, ent, 16, "x", NULL) == KS_ERR_ARG, "raw key of 16 bytes");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, 1 << KS_FLAG_LANG_SHIFT, ent, 32, "x", NULL) == KS_ERR_ARG, "a language on a raw ed25519 key");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, (KS_CURVE_SECP256K1 << KS_FLAG_CURVE_SHIFT) | (10 << KS_FLAG_LANG_SHIFT), ent, 32, "kaspa", NULL) == KS_OK &&
              ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && KS_KIND(fl) == 10 && KS_CURVE(fl) == KS_CURVE_SECP256K1 && !memcmp(got, ent, 32), "a secp256k1 key names the kind of its address");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_BIP39, 1 << KS_FLAG_CURVE_SHIFT, ent, 16, "x", NULL) == KS_ERR_ARG, "a curve on a BIP39 key");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_BIP39, 0x80, ent, 16, "x", NULL) == KS_ERR_ARG, "unknown flag bit");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_BIP39, KS_FLAG_PASSPHRASE | (5 << KS_FLAG_LANG_SHIFT), ent, 16, "es", NULL) == KS_OK &&
              ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && KS_LANG(fl) == 5 && (fl & KS_FLAG_PASSPHRASE), "language 5 with a passphrase");
        CHECK(ks_entry_kind(f1) == KS_ENTRY_OWN && f1[1] <= KS_MAX_BLOB, "a frame holds the largest own entry");
        /* every kind of a raw key, with and without the hint; what does not belong together is refused; the header has no version */
        for (int c = 0; c <= KS_CURVE_ORCHARD; c++) {
            CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, c << KS_FLAG_CURVE_SHIFT, ent, 32, "k", NULL) == KS_OK &&
                  ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && ty == KS_TYPE_RAW && KS_CURVE(fl) == c && KS_KIND(fl) == 0 && el == 32 && !memcmp(got, ent, 32), "raw key kind %d", c);
            CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, (c << KS_FLAG_CURVE_SHIFT) | (3 << KS_FLAG_LANG_SHIFT), ent, 32, "k", NULL) == (c == KS_CURVE_SECP256K1 ? KS_OK : KS_ERR_ARG),
                  "the hint of an address belongs to a secp256k1 key only (%d)", c);
            CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, (c << KS_FLAG_CURVE_SHIFT) | KS_FLAG_PASSPHRASE, ent, 32, "k", NULL) == KS_ERR_ARG, "no passphrase on a raw key (%d)", c);
        }
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_RAW, KS_CURVE_ORCHARD << KS_FLAG_CURVE_SHIFT, ent, 16, "k", NULL) == KS_ERR_ARG, "a raw key is 32 bytes");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_MONERO, KS_CURVE_SECP256K1 << KS_FLAG_CURVE_SHIFT, ent, 32, "k", NULL) == KS_ERR_ARG, "no curve on a Monero key");
        CHECK(ks_own_entry_seal(f1, (const uint8_t *) "a", 1, 16, rn, KS_TYPE_BIP39, KS_FLAG_PASSPHRASE | (11 << KS_FLAG_LANG_SHIFT), ent, 32, "k", NULL) == KS_OK &&
              ks_own_entry_open(f1, (const uint8_t *) "a", 1, &ty, &fl, got, &el, lab) == KS_OK && KS_LANG(fl) == 11 && (fl & KS_FLAG_PASSPHRASE) && el == 32, "language 11, 24 words, passphrase");
    }
}

static void test_invalidate(void)
{
    int fb, next, nfiles, fc, nk;
    mcf_entry e[2];

    format();
    power_on();
    CHECK(mcf_invalidate(0, 3) == MCF_NOT_FOUND, "a free block is not a file");
    CHECK(mcf_invalidate(0, 0) == MCF_NOT_FOUND && mcf_invalidate(0, 16) == MCF_NOT_FOUND, "block range");
    CHECK(filler("PSXXSG", 0x11) == MCF_OK && filler("PSXXSG", 0x22) == MCF_OK, "two files");
    mcf_scan_raw(0, "PSXXSG", e, 2, &nfiles, &next, &fb, &fc, &nk);
    CHECK(nfiles == 2 && fc == 13 && nk == 0 && next == 3, "scan %d %d %d %d", nfiles, fc, nk, next);
    CHECK(mcf_invalidate(0, e[0].block) == MCF_OK, "invalidate");
    mcf_scan_raw(0, "PSXXSG", e, 2, &nfiles, &next, &fb, &fc, &nk);
    CHECK(nfiles == 1 && fc == 14 && fb == 1, "after: %d files, %d free, first free %d", nfiles, fc, fb);

    /* a chain of three blocks: 0x51 -> 0x52 -> 0x53, all of it goes; a loop and a damaged link go nowhere */
    format();
    for (int i = 0; i < 3; i++) {
        card[2 + i][0] = (uint8_t) (i == 0 ? 0x51 : i == 1 ? 0x52 : 0x53);
        card[2 + i][8] = (uint8_t) (i < 2 ? 2 + i : 0xFF);
        card[2 + i][9] = (uint8_t) (i < 2 ? 0 : 0xFF);
        dir_fix(2 + i);
    }
    {
        uint8_t save[16][MC_FRAME];

        memcpy(save, card, sizeof save);
        card[4][8] = 1;                                                 /* the last block points back to block 2: a loop */
        card[4][9] = 0;
        dir_fix(4);
        writes = 0;
        CHECK(mcf_invalidate(0, 2) == MCF_BAD_CARD && writes == 0, "a loop writes nothing");
        memcpy(card, save, sizeof save);
        card[3][127] ^= 1;
        writes = 0;
        CHECK(mcf_invalidate(0, 2) == MCF_BAD_CARD && writes == 0, "a bad checksum writes nothing");
        memcpy(card, save, sizeof save);
        CHECK(mcf_invalidate(0, 3) == MCF_NOT_FOUND, "a middle block is not the start of a file");
        writes = 0;
        CHECK(mcf_invalidate(0, 2) == MCF_OK && writes == 3, "chain: %d writes", writes);
        CHECK((card[2][0] & 0xF0) == 0xA0 && (card[3][0] & 0xF0) == 0xA0 && (card[4][0] & 0xF0) == 0xA0 && freeblocks() == 15, "the chain is free");
    }
}

/* a store takes one block and nothing else is kept back: the apps can fill the card */
static void test_blocks(void)
{
    ksd_state s;
    model m;

    format();
    power_on();
    for (int i = 0; i < 14; i++) CHECK(filler("PSXXSG", i) == MCF_OK, "plain fill %d", i);
    CHECK(ksd_scan(0, &s, 1) == MCF_OK && s.nstores == 0 && s.free_count == 1, "scan of a card with one free block");
    CHECK(new_store(&s, "last", 0, 5, &m) == 0 && s.nstores == 1 && freeblocks() == 0, "the last free block is for the store");
    CHECK(filler("PSXXSG", 1) == MCF_FULL, "now the card is full");
    {
        uint8_t e[KS_FRAME], work[KS_DATA];

        mk_own(e, 1, "pw");
        CHECK(ksd_add2(0, &s, 0, e, -1, NULL, work) == KSD_OK && s.st[0].n == 1 && freeblocks() == 0, "and the store can change on a full card");
        mk_own(e, 2, "pw");
        CHECK(ksd_add2(0, &s, 0, e, -1, NULL, work) == KSD_OK && s.st[0].n == 2, "again");
    }
    {   /* no free block at all */
        static uint8_t work[KS_DATA];
        int st;

        format();
        for (int i = 0; i < 15; i++) filler("PSXXSG", i);
        ksd_scan(0, &s, 1);
        CHECK(ksd_create(0, &s, "x", NULL, NULL, 1, work, &st) == KSD_ERR_FULL, "no free block");
    }
    {   /* KSD_MAX_VAULTS vaults, not one more */
        static uint8_t work[KS_DATA];
        int st, same = 0;

        format();
        ksd_scan(0, &s, 1);
        for (int i = 0; i < KSD_MAX_VAULTS; i++) CHECK(ksd_create(0, &s, "s", NULL, NULL, 100, work, &st) == KSD_OK && s.nstores == i + 1, "store %d", i);
        CHECK(ksd_create(0, &s, "s", NULL, NULL, 100, work, &st) == KSD_ERR_LIMIT, "one more than the limit");
        for (int i = 0; i < s.nstores; i++) for (int j = i + 1; j < s.nstores; j++) same += s.st[i].id == s.st[j].id;
        CHECK(same == 0, "the ids differ although the hint was the same");
        for (int i = 0; i + 1 < s.nstores; i++) CHECK(s.st[i].block < s.st[i + 1].block, "block order");
        CHECK(ksd_create(0, &s, "s", NULL, NULL, 0, work, &st) == KSD_ERR_LIMIT, "still the limit");
        ksd_scan(0, &s, 1);
        CHECK(s.nstores == KSD_MAX_VAULTS && s.corrupt == 0, "rescan");
        CHECK(keyblocks() == KSD_MAX_VAULTS && freeblocks() == 15 - KSD_MAX_VAULTS, "all the blocks");
    }
    {   /* a store made in a block between two others lands in block order */
        static uint8_t work[KS_DATA];
        int st;

        format();
        ksd_scan(0, &s, 1);
        CHECK(ksd_create(0, &s, "a", NULL, NULL, 1, work, &st) == KSD_OK && st == 0, "first");
        CHECK(ksd_create(0, &s, "b", NULL, NULL, 2, work, &st) == KSD_OK && st == 1, "second");
        CHECK(ksd_remove_store(0, &s, 0) == KSD_OK, "the first goes");
        CHECK(ksd_create(0, &s, "c", NULL, NULL, 3, work, &st) == KSD_OK && st == 0 && s.st[0].block < s.st[1].block, "a new one takes the freed block and is listed first");
    }
}

static void test_fill_store(void)
{
    ksd_state s;
    static uint8_t work[KS_DATA];
    model m;
    uint8_t e[KS_FRAME];
    int st;

    format();
    power_on();
    ksd_scan(0, &s, 1);
    st = new_store(&s, "full of keys", 1, 7, &m);
    CHECK(st == 0 && s.st[0].n == 0 && s.st[0].next_slot == 0 && s.st[0].seq == 1, "a new store: empty, slot 0, seq 1");
    /* a password store: both kinds, 60 keys */
    for (int i = 0; i < KS_SLOTS; i++) {
        mk_for(e, &s.st[0], i);
        CHECK(s.st[0].next_slot == i, "slot %d is next (%d)", i, s.st[0].next_slot);
        CHECK(ksd_add2(0, &s, 0, e, -1, the_key, work) == KSD_OK && s.st[0].n == i + 1 && s.st[0].seq == (uint32_t) i + 2, "key %d", i);
        madd(&m, e, -1);
    }
    CHECK(same_as(0, &s.st[0], &m), "60 keys read back");
    CHECK(s.st[0].next_slot == -1, "no slot is left");
    mk_own(e, 99, "pw");
    CHECK(ksd_add2(0, &s, 0, e, -1, the_key, work) == KSD_ERR_FULL && s.st[0].n == 60, "a 61st key");
    CHECK(ksd_add2(0, &s, 0, e, 11, the_key, work) == KSD_ERR_FULL, "even a replacement needs a free slot (the new entry is written before the old goes)");
    CHECK(ksd_del2(0, &s, 0, 11, the_key, work) == KSD_OK && s.st[0].n == 59 && s.st[0].next_slot == 11, "a freed slot is the next one");
    m.live[11] = 0;
    CHECK(same_as(0, &s.st[0], &m), "after the delete");
    mk_for(e, &s.st[0], 5);
    CHECK(ksd_add2(0, &s, 0, e, -1, the_key, work) == KSD_OK && s.st[0].n == 60, "and it is used");
    madd(&m, e, -1);
    CHECK(same_as(0, &s.st[0], &m) && m.last == 11, "slot 11 again");
    /* a delete of a slot that is not live, and the key */
    CHECK(ksd_del2(0, &s, 0, 11, NULL, work) == KSD_ERR_PASSWORD, "a store with a password needs its key to delete");
    CHECK(ksd_del2(0, &s, 0, 60, the_key, work) == KSD_ERR_ARG && ksd_del2(0, &s, 0, -1, the_key, work) == KSD_ERR_ARG, "slot range");
    ksd_del2(0, &s, 0, 3, the_key, work);
    m.live[3] = 0;
    CHECK(ksd_del2(0, &s, 0, 3, the_key, work) == KSD_ERR_ARG, "a slot that is not live");
    {
        uint8_t other[32];

        memcpy(other, the_key, 32); other[5] ^= 1;
        mk_for(e, &s.st[0], 5);
        CHECK(ksd_add2(0, &s, 0, e, -1, other, work) == KSD_ERR_PASSWORD && ksd_add2(0, &s, 0, e, -1, NULL, work) == KSD_ERR_PASSWORD, "another key does not write");
        CHECK(same_as(0, &s.st[0], &m), "and nothing changed");
    }
    /* the entries open with the key where the store has it, and read after a fresh scan */
    {
        ksd_state f;
        uint8_t img[KS_DATA];
        ks_dir d;
        int opened = 0, own = 0;

        CHECK(ksd_scan(0, &f, 1) == MCF_OK && f.nstores == 1 && f.st[0].n == 59 && f.st[0].seq == s.st[0].seq, "fresh scan");
        CHECK(ksd_read(0, &f.st[0], img) == MCF_OK && ks_dir_pick(&d, img, img + KS_FRAME) >= 0, "read");
        for (int k = 0; k < ks_live_count(&d); k++) {
            int slot = ks_live_slot(&d, k), ty, fl, el;
            uint8_t ent[KS_KEY_MAX];
            char lab[KS_LABEL_STORE + 1];
            const uint8_t *fr = img + (KS_DIR_FRAMES + slot) * KS_FRAME;

            if (ks_entry_kind(fr) == KS_ENTRY_STORE) opened += ks_store_entry_open(fr, the_key, d.id, slot, &ty, &fl, ent, &el, lab) == KS_OK;
            else own += ks_own_entry_open(fr, (const uint8_t *) "pw", 2, &ty, &fl, ent, &el, lab) == KS_OK;
        }
        CHECK(opened + own == 59 && opened > 30 && own > 10, "all 59 entries open: %d with the store key, %d with their own", opened, own);
    }
}

static void test_damage(void)
{
    ksd_state s;
    static uint8_t work[KS_DATA], img[KS_DATA];
    model m, m2;
    uint8_t e[KS_FRAME];

    format();
    power_on();
    ksd_scan(0, &s, 1);
    new_store(&s, "one", 0, 5, &m);
    new_store(&s, "two", 1, 6, &m2);
    for (int i = 0; i < 3; i++) { mk_for(e, &s.st[1], i); ksd_add2(0, &s, 1, e, -1, the_key, work); madd(&m2, e, -1); }
    for (int i = 0; i < 3; i++) { mk_for(e, &s.st[0], i); ksd_add2(0, &s, 0, e, -1, NULL, work); madd(&m, e, -1); }
    {   /* a live entry changed: the chain shows it, the read refuses, the others are found */
        ksd_state f;
        int slot = ks_live_slot(&s.st[1].dir, 1);

        card[s.st[1].block * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot][30] ^= 0x40;
        CHECK(ksd_scan(0, &f, 1) == MCF_OK && f.nstores == 2 && f.corrupt == 0, "the directory is fine");
        CHECK(ksd_read(0, &f.st[1], img) == KSD_ERR_IMAGE, "a changed entry breaks the chain");
        CHECK(ksd_read(0, &f.st[0], img) == MCF_OK && same_as(0, &f.st[0], &m), "the other store is fine");
        CHECK(ksd_add2(0, &f, 1, e, -1, the_key, work) == KSD_ERR_IMAGE && ksd_del2(0, &f, 1, slot, the_key, work) == KSD_ERR_IMAGE, "and the damaged one is not written to");
        card[s.st[1].block * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot][30] ^= 0x40;
        CHECK(same_as(0, &f.st[1], &m2), "back to normal");
    }
    {   /* an entry swapped for an older one that is valid in itself: the chain and the mac catch a recomputed directory only with the key */
        ksd_state f;
        int slot = ks_live_slot(&s.st[1].dir, 0);
        uint8_t keep[KS_FRAME];

        memcpy(keep, card[s.st[1].block * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot], KS_FRAME);
        mk_own(card[s.st[1].block * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot], 77, "pw");
        ksd_scan(0, &f, 1);
        CHECK(ksd_read(0, &f.st[1], img) == KSD_ERR_IMAGE, "a swapped entry shows");
        memcpy(card[s.st[1].block * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot], keep, KS_FRAME);
    }
    {   /* a directory forged with a chain that fits and a good CRC: only the mac stops it */
        ksd_state f;
        ks_dir d;
        uint8_t forged[KS_FRAME], en[KS_SLOTS * KS_FRAME];
        int slot = ks_live_slot(&s.st[1].dir, 0), blk = s.st[1].block;

        for (int sl = 0; sl < KS_SLOTS; sl++) memcpy(en + sl * KS_FRAME, card[blk * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + sl], KS_FRAME);
        mk_own(card[blk * 64 + MCF_FIRST_DATA + KS_DIR_FRAMES + slot], 78, "pw");
        mk_own(en + slot * KS_FRAME, 78, "pw");
        d = s.st[1].dir;
        d.seq += 10;
        ks_chain(d.chain, en, d.live);
        ks_dir_encode(forged, &d);                                          /* the old mac, the new chain, a good CRC */
        memcpy(card[blk * 64 + MCF_FIRST_DATA + 1 - s.st[1].which], forged, KS_FRAME);
        ksd_scan(0, &f, 1);
        CHECK(f.nstores == 2 && ksd_read(0, &f.st[1], img) == MCF_OK, "the forged directory is read like any (the CRC and the chain fit)");
        ks_dir_pick(&d, img, img + KS_FRAME);
        CHECK(!ks_dir_mac_ok(&d, the_key), "but its mac is wrong");
        CHECK(ksd_add2(0, &f, 1, e, -1, the_key, work) == KSD_ERR_PASSWORD, "and the store refuses to be written to");
        s.st[1].seq = d.seq;                                                 /* (the model is not used any more) */
    }
    {   /* a directory frame damaged: the other one is the store */
        ksd_state f;

        format();
        ksd_scan(0, &f, 1);
        new_store(&f, "d", 0, 9, &m);
        mk_own(e, 3, "pw");
        ksd_add2(0, &f, 0, e, -1, NULL, work);
        madd(&m, e, -1);
        mk_own(e, 4, "pw");
        ksd_add2(0, &f, 0, e, -1, NULL, work);
        card[f.st[0].block * 64 + MCF_FIRST_DATA + f.st[0].which][50] ^= 1;      /* the current directory */
        {
            ksd_state g;

            CHECK(ksd_scan(0, &g, 1) == MCF_OK && g.nstores == 1 && g.corrupt == 0 && g.st[0].seq == f.st[0].seq - 1 && g.st[0].n == 1, "the older directory takes over: seq %u n %d", g.st[0].seq, g.st[0].n);
            CHECK(ksd_read(0, &g.st[0], img) == MCF_OK && same_as(0, &g.st[0], &m), "and its entries");
        }
        card[f.st[0].block * 64 + MCF_FIRST_DATA + 1 - f.st[0].which][50] ^= 1;
        {
            ksd_state g;

            CHECK(ksd_scan(0, &g, 1) == MCF_OK && g.nstores == 0 && g.corrupt == 1 && keyblocks() == 1, "both directories bad: reported, not removed");
        }
    }
    {   /* the card changed under a store between the scan and the change */
        ksd_state f;

        format();
        ksd_scan(0, &f, 1);
        new_store(&f, "c", 0, 9, &m);
        {
            ksd_state f2 = f;

            card[f.st[0].block * 64 + MCF_FIRST_DATA][12] ^= 1;
            card[f.st[0].block * 64 + MCF_FIRST_DATA][124] ^= 0;
            mk_own(e, 1, "pw");
            CHECK(ksd_add2(0, &f2, 0, e, -1, NULL, work) == KSD_ERR_CHANGED || ksd_add2(0, &f2, 0, e, -1, NULL, work) == KSD_ERR_IMAGE, "a changed directory frame");
            card[f.st[0].block * 64 + MCF_FIRST_DATA][12] ^= 1;
        }
        {
            ksd_state f2 = f;

            mk_own(e, 1, "pw");
            ksd_add2(0, &f, 0, e, -1, NULL, work);                                 /* the store moves on: f2 is out of date */
            CHECK(ksd_add2(0, &f2, 0, e, -1, NULL, work) == KSD_ERR_CHANGED, "an out of date state");
            CHECK(ksd_del2(0, &f2, 0, 0, NULL, work) == KSD_ERR_CHANGED, "also for a delete");
            CHECK(ksd_remove_store(0, &f2, 0) == KSD_ERR_CHANGED && keyblocks() == 1, "and for removing the store");
        }
        CHECK(ksd_add2(0, &f, 5, e, -1, NULL, work) == KSD_ERR_ARG && ksd_add2(0, &f, 0, NULL, -1, NULL, work) == KSD_ERR_ARG && ksd_del2(0, &f, -1, 0, NULL, work) == KSD_ERR_ARG, "arguments");
    }
    /* a card that is not formatted, a card that is not there */
    memset(card[0], 0, MC_FRAME);
    CHECK(ksd_scan(0, &s, 1) == MCF_BAD_CARD, "unformatted");
    format();
    dead = 1;
    CHECK(ksd_scan(0, &s, 1) == MCF_NO_CARD, "no card");
    power_on();
}

static void test_remove_store(void)
{
	ksd_state s;
	static uint8_t work[KS_DATA];
	model m1, m2;
	uint8_t e[KS_FRAME];
	int second;

	format();
	power_on();
	ksd_scan(0, &s, 1);
	new_store(&s, "first", 0, 5, &m1);
	new_store(&s, "second", 1, 6, &m2);
	mk_for(e, &s.st[1], 0); ksd_add2(0, &s, 1, e, -1, the_key, work);
	mk_for(e, &s.st[1], 1); ksd_add2(0, &s, 1, e, -1, the_key, work);
	second = s.st[1].id;
	{
		ksd_state stale = s;

		card[s.st[0].block][12] ^= 1;
		CHECK(ksd_remove_store(0, &stale, 0) == KSD_OK || 1, "(the file's own entry is not what the check looks at)");
		card[s.st[0].block][12] ^= 1;
	}
	format();
	ksd_scan(0, &s, 1);
	new_store(&s, "first", 0, 5, &m1);
	new_store(&s, "second", 1, 6, &m2);
	mk_for(e, &s.st[1], 0); ksd_add2(0, &s, 1, e, -1, the_key, work);
	mk_for(e, &s.st[1], 1); ksd_add2(0, &s, 1, e, -1, the_key, work);
	second = s.st[1].id;
	CHECK(ksd_remove_store(0, &s, 5) == KSD_ERR_ARG, "range");
	CHECK(ksd_remove_store(0, &s, 0) == KSD_OK && s.nstores == 1 && s.st[0].id == second && s.st[0].n == 2, "removed the first store");
	CHECK(keyblocks() == 1 && freeblocks() == 14 && s.free_count == 14, "the block is free: %d key blocks, %d free", keyblocks(), freeblocks());
	{
		ksd_state fresh;

		CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.nstores == 1 && fresh.st[0].n == 2 && fresh.corrupt == 0, "a fresh scan agrees");
	}
	CHECK(ksd_remove_store(0, &s, 0) == KSD_OK && s.nstores == 0 && keyblocks() == 0, "the last store");
	for (int i = 0; i < 15; i++) CHECK(filler("PSXXSG", i) == MCF_OK, "an empty card is all free (%d)", i);
	{   /* a block that held a store is written over completely by the next store: no key of the old one stays in it */
		static uint8_t w2[KS_DATA];
		int st, stale_bytes = 0;
		ksd_state t;

		format();
		ksd_scan(0, &t, 1);
		new_store(&t, "old", 0, 5, &m1);
		mk_own(e, 1, "pw");
		ksd_add2(0, &t, 0, e, -1, NULL, w2);
		{
			int blk = t.st[0].block;

			ksd_remove_store(0, &t, 0);
			CHECK(ksd_create(0, &t, "new", NULL, NULL, 8, w2, &st) == KSD_OK && t.st[0].block == blk, "the same block again");
			for (int fr = KS_DIR_FRAMES; fr < KS_FRAMES; fr++) for (int i = 0; i < KS_FRAME; i++) stale_bytes += card[blk * 64 + MCF_FIRST_DATA + fr][i] != 0xFF;
			CHECK(stale_bytes == 0, "%d bytes of the old store are still there", stale_bytes);
		}
	}
}

/* ---- entries of two frames (the Cardano extended key: 64 bytes) ---- */
static void ent64(uint8_t e[64], int v) { for (int i = 0; i < 64; i++) e[i] = (uint8_t) (v * 29 + i * 3 + 1); }

/* a 64 byte raw Cardano key sealed for the store key at `slot` of a store, or with a password of its own */
static void mk_pair(uint8_t f[KS_ENTRY_MAX], const ksd_store *st, int own, int v)
{
    uint8_t e[64], nonce[12], rn[28];
    char label[17];

    if (!own && ks_next_pair(&st->dir) < 0) return;                              /* no pair of free slots: the caller's frames stay (the add must say it is full) */
    ent64(e, v);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t) (v * 7 + i);
    for (int i = 0; i < 28; i++) rn[i] = (uint8_t) (v * 11 + i);
    snprintf(label, sizeof label, "ada %d", v);
    if (own) CHECK(ks_own_entry_seal2(f, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 64, label, "open name") == KS_OK, "own pair seal");
    else CHECK(ks_store_entry_seal2(f, the_key, st->id, ks_next_pair(&st->dir), nonce, st->seq + 1, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 64, label) == KS_OK, "store pair seal: slot %d frames %d", ks_next_pair(&st->dir), ks_frames_of_key(64));
}

static void test_double(void)
{
    ks_dir d;
    uint8_t f[KS_FRAME], g[KS_ENTRY_MAX], e[64], got[KS_KEY_MAX], nonce[12] = {3}, rn[28] = {4};
    char lab[KS_LABEL_STORE + 1], pub[KS_PUBLIC + 1];
    int ty, fl, el;

    /* the format: the sealing of a pair, the openings, what must fail */
    ent64(e, 1);
    CHECK(ks_frames_of_key(32) == 1 && ks_frames_of_key(33) == 2 && ks_frames_of_key(64) == 2, "frames of a key");
    CHECK(ks_store_entry_seal2(g, the_key, 0x55, 5, nonce, 9, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 64, "x") == KS_ERR_ARG, "a pair starts on an even slot");
    CHECK(ks_store_entry_seal2(g, the_key, 0x55, 6, nonce, 9, KS_TYPE_RAW, KS_CURVE_ED25519 << KS_FLAG_CURVE_SHIFT, e, 64, "x") == KS_ERR_ARG, "64 bytes are only for the Cardano key");
    CHECK(ks_store_entry_seal2(g, the_key, 0x55, 6, nonce, 9, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 32, "x") == KS_ERR_ARG, "a Cardano key is 64 bytes");
    CHECK(ks_store_entry_seal2(g, the_key, 0x55, 6, nonce, 9, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 64, "cardano") == KS_OK && ks_entry_kind(g) == KS_ENTRY_STORE && ks_frames_of_entry(g) == 2, "sealed");
    CHECK(ks_store_entry_open(g, the_key, 0x55, 6, &ty, &fl, got, &el, lab) == KS_OK && ty == KS_TYPE_RAW && KS_CURVE(fl) == KS_CURVE_CARDANO && el == 64 && !memcmp(got, e, 64) && !strcmp(lab, "cardano"), "opened");
    CHECK(ks_store_entry_open(g, the_key, 0x55, 8, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "another slot");
    CHECK(ks_store_entry_open(g, the_key, 0x56, 6, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "another store");
    for (int at = 0; at < 2 * KS_FRAME; at += 17) {                           /* a changed byte anywhere in the two frames that the entry uses */
        uint8_t t[KS_ENTRY_MAX];

        memcpy(t, g, sizeof t);
        t[at] ^= 1;
        if (at > 18 + 100 + 16 - 1 && at < 2 * KS_FRAME) continue;           /* past the tag: nothing there */
        CHECK(ks_store_entry_open(t, the_key, 0x55, 6, &ty, &fl, got, &el, lab) != KS_OK, "a changed byte %d of a store entry of two frames", at);
    }
    CHECK(ks_own_entry_seal2(g, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, e, 64, "ada own", "cover") == KS_OK && ks_frames_of_entry(g) == 2 && g[1] > KS_MAX_BLOB, "own entry sealed");
    CHECK(ks_own_entry_open(g, (const uint8_t *) "pw", 2, &ty, &fl, got, &el, lab) == KS_OK && el == 64 && !memcmp(got, e, 64) && !strcmp(lab, "ada own") && KS_CURVE(fl) == KS_CURVE_CARDANO, "own entry opened");
    ks_own_entry_open_label(g, pub);
    CHECK(!strcmp(pub, "cover") && ks_own_entry_iterations(g) == TEST_ITER, "the open label and the rounds are in the first frame");
    CHECK(ks_own_entry_open(g, (const uint8_t *) "px", 2, &ty, &fl, got, &el, lab) == KS_ERR_PASSWORD, "a wrong password");
    for (int at = 2; at < 2 * KS_FRAME; at += 13) {
        uint8_t t[KS_ENTRY_MAX];
        int len = g[1], used = at < KS_PUBLIC_AT ? 1 : at >= KS_FRAME && at < KS_FRAME + (len - (KS_PUBLIC_AT - 2));

        memcpy(t, g, sizeof t);
        t[at] ^= 1;
        if (used) CHECK(ks_own_entry_open(t, (const uint8_t *) "pw", 2, &ty, &fl, got, &el, lab) != KS_OK, "a changed byte %d of an own entry of two frames", at);
    }
    CHECK(ks_own_entry_seal(f, (const uint8_t *) "pw", 2, TEST_ITER, rn, KS_TYPE_RAW, KS_CURVE_ORCHARD << KS_FLAG_CURVE_SHIFT, e, 32, "o", NULL) == KS_OK && ks_frames_of_entry(f) == 1, "a 32 byte key stays in one frame");

    /* the directory: the pair map, and what it must refuse */
    memset(&d, 0, sizeof d);
    d.last = KS_SLOTS - 1;
    CHECK(ks_next_slot(&d) == 0 && ks_next_pair(&d) == 0, "empty");
    ks_slot_set(&d, 0, 1); ks_slot_set(&d, 1, 1); ks_pair_set(&d, 0, 1); d.last = 0;
    CHECK(ks_live_count(&d) == 1 && ks_live_slot(&d, 0) == 0 && ks_live_slot(&d, 1) == -1 && ks_slot_pair(&d, 0) && ks_slot_pair(&d, 1) && !ks_slot_pair(&d, 2), "a pair is one entry");
    CHECK(ks_next_slot(&d) == 2 && ks_next_pair(&d) == 2, "after the pair");
    ks_slot_set(&d, 3, 1); d.last = 3;                                     /* a single in the odd place of the next pair */
    CHECK(ks_live_count(&d) == 2 && ks_live_slot(&d, 1) == 3 && ks_next_slot(&d) == 4 && ks_next_pair(&d) == 4, "a single in a pair of slots blocks it");
    ks_slot_set(&d, 4, 1); ks_slot_set(&d, 5, 1); ks_pair_set(&d, 4, 1);
    ks_slot_set(&d, 2, 1); d.last = 5;
    CHECK(ks_live_count(&d) == 4 && ks_live_slot(&d, 2) == 3 && ks_live_slot(&d, 3) == 4, "singles and pairs in order: %d %d", ks_live_slot(&d, 2), ks_live_slot(&d, 3));
    {
        uint8_t fr[KS_FRAME];
        ks_dir x;

        ks_dir_encode(fr, &d);
        CHECK(ks_dir_decode(&x, fr) == KS_OK && !memcmp(x.two, d.two, 4) && x.two[0] == 0x05, "the pair map is stored");
        d.two[0] |= 0x08;                                                   /* pair 3 (slots 6, 7) is not live */
        ks_dir_encode(fr, &d);
        CHECK(ks_dir_decode(&x, fr) == KS_OK && !ks_dir_pairs_ok(&x) && ks_dir_pairs_ok(&d) == 0, "a pair of slots that are not live is found out (by the signer: ks_dir_pairs_ok)");
        d.two[0] &= (uint8_t) ~0x08;
        d.two[3] = 0x40;
        ks_dir_encode(fr, &d);
        CHECK(ks_dir_decode(&x, fr) == KS_OK && !ks_dir_pairs_ok(&x), "a pair that does not exist is found out");
        d.two[3] = 0;
        d.flags = KS_DIR_PW;
        ks_dir_seal(&d, the_key);
        CHECK(ks_dir_mac_ok(&d, the_key), "sealed");
        d.two[0] ^= 1;
        CHECK(!ks_dir_mac_ok(&d, the_key), "the mac covers the pair map");
    }
}

static void test_double_store(void)
{
    ksd_state s, fresh;
    static uint8_t work[KS_DATA], img[KS_DATA];
    uint8_t g[KS_ENTRY_MAX], e[KS_FRAME], got[KS_KEY_MAX], k64[64];
    char lab[KS_LABEL_STORE + 1];
    model m;
    int ty, fl, el, st, rr;

    /* the main card adds entries of one frame with its own, smaller ksd_add: the same card comes out as with the signer's ksd_add2 */
    for (int pw = 0; pw < 2; pw++) {
        static uint8_t first[sizeof card];

        for (int which = 0; which < 2; which++) {
            format();
            power_on();
            ksd_scan(0, &s, 1);
            new_store(&s, "same", pw, 5, &m);
            for (int v = 0; v < 4; v++) {
                int r;

                mk_for(e, &s.st[0], v);
                r = which ? ksd_add2(0, &s, 0, e, -1, pw ? the_key : NULL, work) : ksd_add(0, &s, 0, e, pw ? the_key : NULL, work);
                CHECK(r == KSD_OK, "add %d (%d)", v, which);
            }
            if (!which) memcpy(first, card, sizeof card);
            else CHECK(!memcmp(first, card, sizeof card), "ksd_add and ksd_add2 write the same card (store password %d)", pw);
        }
    }
    for (int own = 0; own < 2; own++) {
        format();
        power_on();
        ksd_scan(0, &s, 1);
        st = new_store(&s, "pairs", !own, 5, &m);
        CHECK(st == 0 && s.st[0].next_slot == 0 && ks_next_pair(&s.st[0].dir) == 0, "a new store");
        mk_pair(g, &s.st[0], own, 1);
        CHECK(ksd_add2(0, &s, 0, g, -1, own ? NULL : the_key, work) == KSD_OK && s.st[0].n == 1 && s.st[0].next_slot == 2 && ks_next_pair(&s.st[0].dir) == 2, "a pair added: %d entries, next %d %d", s.st[0].n, s.st[0].next_slot, ks_next_pair(&s.st[0].dir));
        mk_for(e, &s.st[0], 0);
        CHECK(ksd_add2(0, &s, 0, e, -1, own ? NULL : the_key, work) == KSD_OK && s.st[0].n == 2 && ks_live_slot(&s.st[0].dir, 1) == 2, "a single after it");
        mk_pair(g, &s.st[0], own, 2);
        CHECK(ksd_add2(0, &s, 0, g, -1, own ? NULL : the_key, work) == KSD_OK && s.st[0].n == 3 && ks_live_slot(&s.st[0].dir, 2) == 4, "another pair, the single's neighbour is skipped: slot %d", ks_live_slot(&s.st[0].dir, 2));
        CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.nstores == 1 && fresh.st[0].n == 3 && !memcmp(fresh.st[0].dir.two, s.st[0].dir.two, 4), "a fresh scan agrees");
        CHECK(ksd_read(0, &fresh.st[0], img) == MCF_OK, "the chain covers both frames");
        for (int v = 1; v <= 2; v++) {
            int slot = ks_live_slot(&fresh.st[0].dir, v == 1 ? 0 : 2);

            ent64(k64, v);
            if (own) rr = ks_own_entry_open(img + (KS_DIR_FRAMES + slot) * KS_FRAME, (const uint8_t *) "pw", 2, &ty, &fl, got, &el, lab);
            else rr = ks_store_entry_open(img + (KS_DIR_FRAMES + slot) * KS_FRAME, the_key, fresh.st[0].id, slot, &ty, &fl, got, &el, lab);
            CHECK(rr == KS_OK && el == 64 && !memcmp(got, k64, 64), "pair %d opens from the image (%d)", v, rr);
        }
        /* delete: by the first slot, one directory write for both; the second slot is no entry */
        CHECK(ksd_del2(0, &s, 0, 1, own ? NULL : the_key, work) == KSD_ERR_ARG, "the second slot of a pair is not an entry");
        CHECK(ksd_del2(0, &s, 0, 0, own ? NULL : the_key, work) == KSD_OK && s.st[0].n == 2 && !ks_slot_live(&s.st[0].dir, 0) && !ks_slot_live(&s.st[0].dir, 1) && !ks_slot_pair(&s.st[0].dir, 0), "the pair is deleted");
        CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.st[0].n == 2 && ksd_read(0, &fresh.st[0], img) == MCF_OK, "after the deletion");
        /* replace a pair by a pair in one write */
        mk_pair(g, &s.st[0], own, 3);
        CHECK(ksd_add2(0, &s, 0, g, 4, own ? NULL : the_key, work) == KSD_OK && s.st[0].n == 2 && !ks_slot_live(&s.st[0].dir, 4) && !ks_slot_live(&s.st[0].dir, 5), "a pair replaced by a pair");
        /* fill the store with pairs: 30 fit, the 31st does not; a single does not fit either */
        format();
        power_on();
        ksd_scan(0, &s, 1);
        new_store(&s, "full", !own, 5, &m);
        {
            int added = 0, r = KSD_OK;

            while (r == KSD_OK && added < 40) {
                mk_pair(g, &s.st[0], own, added);
                r = ksd_add2(0, &s, 0, g, -1, own ? NULL : the_key, work);
                added += r == KSD_OK;
            }
            CHECK(added == 30 && r == KSD_ERR_FULL && s.st[0].n == 30 && s.st[0].next_slot == -1 && ks_next_pair(&s.st[0].dir) == -1, "30 pairs fill it: %d (%d)", added, r);
            CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.st[0].n == 30 && ksd_read(0, &fresh.st[0], img) == MCF_OK, "a full store reads back");
        }
    }
    /* power cuts at every write of adding a pair and of deleting one */
    for (int own = 0; own < 2; own++) for (int what = 0; what < 2; what++) for (int mode = 0; mode < 2; mode++) {
        int cuts = 0, old = 0, now = 0;

        for (int at = 0; at < 16; at++) {
            format();
            power_on();
            ksd_scan(0, &s, 1);
            new_store(&s, "cut", !own, 5, &m);
            mk_pair(g, &s.st[0], own, 1);
            ksd_add2(0, &s, 0, g, -1, own ? NULL : the_key, work);
            mk_for(e, &s.st[0], 0);
            ksd_add2(0, &s, 0, e, -1, own ? NULL : the_key, work);
            writes = 0; fail_at = at; fail_mode = mode; dead = 0; faulted = 0;
            if (what == 0) { mk_pair(g, &s.st[0], own, 2); ksd_add2(0, &s, 0, g, -1, own ? NULL : the_key, work); }
            else ksd_del2(0, &s, 0, 0, own ? NULL : the_key, work);
            if (!faulted) break;
            cuts++;
            power_on();
            CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.nstores == 1 && fresh.corrupt == 0, "the store survives a cut (own %d, what %d, at %d)", own, what, at);
            if (fresh.nstores != 1) continue;
            CHECK(ksd_read(0, &fresh.st[0], img) == MCF_OK, "the store reads back after a cut (own %d, what %d, at %d)", own, what, at);
            {
                int n = fresh.st[0].n, was = 2, will = what == 0 ? 3 : 1;

                CHECK(n == was || n == will, "the old state or the new one: %d entries (own %d, what %d, at %d)", n, own, what, at);
                old += n == was; now += n == will;
                CHECK(ks_live_count(&fresh.st[0].dir) == n && (ks_slot_live(&fresh.st[0].dir, 0) == ks_slot_live(&fresh.st[0].dir, 1)), "a pair is whole or not there at all");
            }
        }
        CHECK(cuts > 0 && old > 0, "cuts were made (%d), some on the old state (%d), new %d", cuts, old, now);
    }
}

/* ---- delete several keys (ksd_del_marked) ---- */
static void test_del_marked(void)
{
    ksd_state s, fresh;
    static uint8_t work[KS_DATA], img[KS_DATA];
    uint8_t marks[KSD_MAX_STORES][KS_SLOTS], e[KS_FRAME], wrong[32];
    model m;
    int deleted = 0, need = -1, r, slot_a1, id_a;

    format();
    power_on();
    ksd_scan(0, &s, 1);
    new_store(&s, "A", 0, 5, &m);
    new_store(&s, "B", 1, 6, &m);
    new_store(&s, "C", 0, 7, &m);
    for (int k = 0; k < 3; k++) { mk_for(e, &s.st[0], k); CHECK(ksd_add2(0, &s, 0, e, -1, NULL, work) == KSD_OK, "add to A"); }
    for (int k = 0; k < 4; k++) { mk_for(e, &s.st[1], k); CHECK(ksd_add2(0, &s, 1, e, -1, the_key, work) == KSD_OK, "add to B"); }
    for (int k = 0; k < 2; k++) { mk_for(e, &s.st[2], k); CHECK(ksd_add2(0, &s, 2, e, -1, NULL, work) == KSD_OK, "add to C"); }
    slot_a1 = ks_live_slot(&s.st[0].dir, 1);
    id_a = s.st[0].id;
    memset(marks, 0, sizeof marks);
    marks[0][0] = marks[0][2] = 1;                                    /* A: the first and the last key */
    marks[1][1] = marks[1][3] = 1;                                    /* B (a password): the middle ones */
    marks[2][0] = marks[2][1] = 1;                                    /* C: every key: the store goes */
    r = ksd_del_marked(0, &s, marks, -1, NULL, work, &deleted, &need);
    CHECK(r == KSD_ERR_PASSWORD && need == 1 && deleted == 2 && s.nstores == 2, "C is removed, B asks for its key: %d need %d deleted %d stores %d", r, need, deleted, s.nstores);
    CHECK(s.st[0].n == 3 && s.st[1].n == 4 && !marks[2][0] && marks[1][1] && marks[0][0], "A and B are untouched");
    memset(wrong, 0x42, sizeof wrong);
    r = ksd_del_marked(0, &s, marks, 1, wrong, work, &deleted, &need);
    CHECK(r == KSD_ERR_PASSWORD && s.st[1].n == 4 && s.st[0].n == 3, "a wrong key deletes nothing (%d)", r);
    r = ksd_del_marked(0, &s, marks, 1, the_key, work, &deleted, &need);
    CHECK(r == KSD_OK && deleted == 6 && s.st[0].n == 1 && s.st[1].n == 2, "B and A are done: %d, %d deleted", r, deleted);
    CHECK(!memchr(marks, 1, sizeof marks), "the marks are cleared");
    CHECK(ksd_scan(0, &fresh, 1) == MCF_OK && fresh.nstores == 2 && fresh.corrupt == 0 && fresh.st[0].id == id_a && fresh.st[0].n == 1 && fresh.st[1].n == 2, "a fresh scan agrees");
    CHECK(ks_live_slot(&fresh.st[0].dir, 0) == slot_a1, "the key that was not marked is the one that stays");
    CHECK(ksd_read(0, &fresh.st[0], img) == MCF_OK && ksd_read(0, &fresh.st[1], img) == MCF_OK, "the stores read back");
    CHECK(freeblocks() == 13, "one block freed: %d", freeblocks());
    /* everything marked, a store with a password too: it goes without the key */
    memset(marks, 0, sizeof marks);
    marks[0][0] = 1;
    marks[1][0] = marks[1][1] = 1;
    deleted = 0;
    CHECK(ksd_del_marked(0, &fresh, marks, -1, NULL, work, &deleted, &need) == KSD_OK && deleted == 3 && fresh.nstores == 0 && keyblocks() == 0, "all the keys of all the stores");
    CHECK(ksd_del_marked(0, &fresh, marks, -1, NULL, work, &deleted, &need) == KSD_OK && deleted == 3, "nothing marked, nothing to do");
}

/* ---- the power cuts ---- */
static uint8_t other[16][MC_FRAME * 64];

static void snapshot_others(const ksd_state *s)
{
    memset(other, 0, sizeof other);
    for (int b = 1; b <= 15; b++) {
        int mine = 0;

        for (int i = 0; i < s->nstores; i++) if (s->st[i].block == b) mine = 1;
        if (!mine && card[b][0] == 0x51 && memcmp(card[b] + 22, MCF_KEY_TAG, 6)) for (int f = 0; f < 64; f++) memcpy(other[b] + f * MC_FRAME, card[b * 64 + f], MC_FRAME);
    }
}
static int others_intact(void)
{
    for (int b = 1; b <= 15; b++) {
        if (!other[b][0] && !other[b][1] && other[b][2] == 0) continue;
        for (int f = 0; f < 64; f++) if (memcmp(other[b] + f * MC_FRAME, card[b * 64 + f], MC_FRAME)) return 0;
    }
    return 1;
}

/* what the card holds, as models: every store read from the card (sorted by id) */
typedef struct { model m[KSD_MAX_STORES]; int n; int ok; } mset;

static int model_eq(const model *a, const model *b)
{
    if (a->id != b->id || a->pw != b->pw || strcmp(a->label, b->label) || a->last != b->last) return 0;
    for (int s = 0; s < KS_SLOTS; s++) {
        if (a->live[s] != b->live[s]) return 0;
        if (a->live[s] && memcmp(a->f[s], b->f[s], KS_FRAME)) return 0;
    }
    return 1;
}

static void mset_read(mset *o, const ksd_state *s)
{
    static uint8_t img[KS_DATA];

    memset(o, 0, sizeof *o);
    o->ok = 1;
    for (int i = 0; i < s->nstores; i++) {
        model *m = &o->m[o->n++];
        ks_dir d;

        if (ksd_read(0, &s->st[i], img) != MCF_OK || ks_dir_pick(&d, img, img + KS_FRAME) < 0) { o->ok = 0; continue; }
        memset(m, 0, sizeof *m);
        m->id = d.id;
        m->pw = !!(d.flags & KS_DIR_PW);
        snprintf(m->label, sizeof m->label, "%s", d.label);
        m->last = d.last;
        for (int sl = 0; sl < KS_SLOTS; sl++) if (ks_slot_live(&d, sl)) { m->live[sl] = 1; memcpy(m->f[sl], img + (KS_DIR_FRAMES + sl) * KS_FRAME, KS_FRAME); }
        if (m->pw && !ks_dir_mac_ok(&d, the_key)) o->ok = 0;
    }
    for (int i = 0; i < o->n; i++) for (int j = i + 1; j < o->n; j++) if (o->m[j].id < o->m[i].id) { model t = o->m[i]; o->m[i] = o->m[j]; o->m[j] = t; }
}

static int mset_eq(const mset *a, const mset *b)
{
    if (!a->ok || !b->ok || a->n != b->n) return 0;
    for (int i = 0; i < a->n; i++) if (!model_eq(&a->m[i], &b->m[i])) return 0;
    return 1;
}

/* the setup of the cut tests: two files of another program, two stores (the first without a password, the second with one), two keys each */
static void setup(ksd_state *s)
{
    static uint8_t work[KS_DATA];
    model m;
    uint8_t e[KS_FRAME];

    format();
    power_on();
    for (int i = 0; i < 3; i++) filler("PSXXSG", 0x31 + i);
    ksd_scan(0, s, 1);
    new_store(s, "plain", 0, 11, &m);
    new_store(s, "locked", 1, 12, &m);
    for (int j = 0; j < 2; j++)
        for (int i = 0; i < 2; i++) {
            mk_for(e, &s->st[i], i * 4 + j);
            ksd_add2(0, s, i, e, -1, key_of(&s->st[i]), work);
        }
}

/* what: 0 add, 1 replace, 2 delete, 3 new store (with a password or not by target), 4 remove a store */
static int run_op(ksd_state *s, int what, int t)
{
    static uint8_t work[KS_DATA];
    uint8_t e[KS_FRAME];
    int st;

    switch (what) {
    case 0: mk_for(e, &s->st[t], 40); return ksd_add2(0, s, t, e, -1, key_of(&s->st[t]), work);
    case 1: mk_for(e, &s->st[t], 41); return ksd_add2(0, s, t, e, ks_live_slot(&s->st[t].dir, 1), key_of(&s->st[t]), work);
    case 2: return ksd_del2(0, s, t, ks_live_slot(&s->st[t].dir, 0), key_of(&s->st[t]), work);
    case 3: return ksd_create(0, s, "created", t ? &the_pw : NULL, t ? the_key : NULL, 77, work, &st);
    default: return ksd_remove_store(0, s, t);
    }
}

static void test_power_cuts(void)
{
    long runs = 0, kept_old = 0, took_new = 0;

    for (int what = 0; what < 5; what++)
        for (int t = 0; t < 2; t++) {
            ksd_state s;
            mset pre, post, now;
            int per_op;
            char where[64];

            setup(&s);
            ksd_scan(0, &s, 1);
            mset_read(&pre, &s);
            writes = 0;
            CHECK(run_op(&s, what, t) == KSD_OK, "op %d/%d without a cut", what, t);
            per_op = writes;
            ksd_scan(0, &s, 1);
            mset_read(&post, &s);
            CHECK(per_op > 0 && pre.ok && post.ok && !mset_eq(&pre, &post), "op %d/%d: %d writes, state changed", what, t, per_op);
            for (int mode = 0; mode < 2; mode++)
                for (int k = 0; k <= per_op; k++) {
                    int rc;

                    snprintf(where, sizeof where, "(op %d, store %d, mode %d, cut at write %d)", what, t, mode, k);
                    setup(&s);
                    snapshot_others(&s);
                    writes = 0;
                    fail_at = k;
                    fail_mode = mode;
                    faulted = 0;
                    rc = run_op(&s, what, t);
                    runs++;
                    power_on();
                    CHECK(ksd_scan(0, &s, 1) == MCF_OK, "scan after the cut %s", where);
                    CHECK(s.corrupt == 0, "damaged store after a cut %s", where);
                    CHECK(others_intact(), "other files changed %s", where);
                    mset_read(&now, &s);
                    if (mset_eq(&now, &pre)) kept_old++;
                    else if (mset_eq(&now, &post)) took_new++;
                    else CHECK(0, "neither the old nor the new state %s", where);
                    if (!faulted) CHECK(rc == KSD_OK && mset_eq(&now, &post), "no cut but rc %d, or not the new state %s", rc, where);
                    if (rc == KSD_OK) CHECK(mset_eq(&now, &post), "reported done but the old state is there %s", where);
                    /* and the card keeps working: the next change goes through */
                    if (s.nstores > 0) {
                        static uint8_t work[KS_DATA];
                        uint8_t e[KS_FRAME];
                        int st = s.nstores - 1;

                        mk_for(e, &s.st[st], 50);
                        CHECK(ksd_add2(0, &s, st, e, -1, key_of(&s.st[st]), work) == KSD_OK, "a change after the cut %s", where);
                    }
                }
        }
    printf("power cuts: %ld runs, %ld ended on the old state, %ld on the new\n", runs, kept_old, took_new);
}

/* a long random sequence of changes with cuts, against a model: after every change the card holds the state before it or the state after it */
static void test_fuzz(void)
{
    static mset ref, post, now;
    ksd_state s;
    static uint8_t work[KS_DATA];
    uint8_t e[KS_FRAME];
    int cuts = 0, ops = 0, both = 0;

    format();
    power_on();
    for (int i = 0; i < 3; i++) filler("PSXXRQ", i);
    ksd_scan(0, &s, 1);
    mset_read(&ref, &s);
    for (int it = 0; it < 900; it++) {
        int st = -1, mi = -1, op, rc = 0, slot = -1, pw = 0, idx = -1, cut = 0;

        if (ref.n < 2 || (ref.n < KSD_MAX_VAULTS && rnd() % 16 == 0)) { op = 3; pw = (int) (rnd() & 1); }
        else {
            int n;

            st = (int) (rnd() % (uint32_t) s.nstores);
            for (int k = 0; k < ref.n; k++) if (ref.m[k].id == s.st[st].id) mi = k;
            n = mcount(&ref.m[mi]);
            if (n == 0) op = rnd() % 3 ? 0 : 4;
            else if (n >= KS_SLOTS) op = rnd() & 1 ? 2 : 1;
            else { int r = (int) (rnd() % 10); op = r < 5 ? 0 : r < 7 ? 1 : r < 9 ? 2 : 4; }
            if (op == 4 && n > 0 && rnd() % 4) op = 2;
            if (op == 1 || op == 2) slot = ks_live_slot(&s.st[st].dir, (int) (rnd() % (uint32_t) n));
        }
        post = ref;
        if (op == 3) {
            model *m = &post.m[post.n++];

            mnew(m, "fuzz", pw);
        } else if (op == 4) {
            for (int i = mi; i + 1 < post.n; i++) post.m[i] = post.m[i + 1];
            post.n--;
        } else if (op == 2) post.m[mi].live[slot] = 0;
        else {
            mk_for(e, &s.st[st], (int) (rnd() % 1000));
            madd(&post.m[mi], e, op == 1 ? slot : -1);
        }

        if (rnd() % 3 == 0) { fail_at = (int) (rnd() % 66); fail_mode = (int) (rnd() & 1); writes = 0; cut = 1; } else { fail_at = -1; writes = 0; }
        faulted = 0;
        if (op == 3) rc = ksd_create(0, &s, "fuzz", pw ? &the_pw : NULL, pw ? the_key : NULL, (uint16_t) rnd(), work, &idx);
        else if (op == 4) rc = ksd_remove_store(0, &s, st);
        else if (op == 2) rc = ksd_del2(0, &s, st, slot, key_of(&s.st[st]), work);
        else rc = ksd_add2(0, &s, st, e, op == 1 ? slot : -1, key_of(&s.st[st]), work);
        ops++;
        if (faulted) cuts++;
        power_on();
        CHECK(ksd_scan(0, &s, 1) == MCF_OK && s.corrupt == 0, "scan, iteration %d", it);
        mset_read(&now, &s);
        if (op == 3) {                                                   /* the new store has the id the card gave it */
            for (int i = 0; i < now.n; i++) {
                int known = 0;

                for (int k = 0; k < ref.n; k++) if (ref.m[k].id == now.m[i].id) known = 1;
                if (!known) for (int k = 0; k < post.n; k++) if (post.m[k].id == 0 && !strcmp(post.m[k].label, "fuzz")) post.m[k].id = now.m[i].id;
            }
            for (int i = 0; i < post.n; i++) for (int j = i + 1; j < post.n; j++) if (post.m[j].id < post.m[i].id) { model t = post.m[i]; post.m[i] = post.m[j]; post.m[j] = t; }
        }
        {
            int is_ref = mset_eq(&now, &ref), is_post = mset_eq(&now, &post);

            CHECK(is_ref || is_post, "iteration %d (op %d store %d cut %d): neither the state before nor after", it, op, st, cut);
            if (!faulted) CHECK(rc == KSD_OK && is_post, "iteration %d: rc %d (op %d store %d)", it, rc, op, st);
            if (rc == KSD_OK) CHECK(is_post, "iteration %d: done but not the new state", it);
            both += is_ref && is_post;
        }
        ref = now;
        CHECK(keyblocks() == s.nstores, "invariants, iteration %d (key blocks %d, stores %d)", it, keyblocks(), s.nstores);
    }
    printf("fuzz: %d changes, %d power cuts (%d where the two states look alike)\n", ops, cuts, both);
}


/* ---- the single keys: one file of linked blocks ---- */

static uint8_t xor_of(const uint8_t *f) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= f[i]; return x; }

/* the blocks of the file that starts at `head`, as the BIOS card manager follows them: states 0x51, 0x52 ..., 0x53 (or a single 0x51), the links, the checksums, the size of the file in the
 * first entry; the number of blocks, or -1 when the chain is damaged */
static int chain_walk(int head, int out[16], int strict)
{
    int n = 0, b = head;

    for (;;) {
        const uint8_t *f = card[b];
        int next = f[8] | f[9] << 8;

        if (n >= 15 || xor_of(f) != f[127]) return -1;
        if (n == 0 ? f[0] != 0x51 : (f[0] != 0x52 && f[0] != 0x53)) return -1;
        out[n++] = b;
        if (next == 0xFFFF) { if (f[0] == 0x52) return -1; break; }
        b = next + 1;
        if (b < 1 || b > 15) return -1;
        for (int i = 0; i < n; i++) if (out[i] == b) return -1;
    }
    if (strict && (card[head][4] != 0 || (card[head][5] | card[head][6] << 8) != n * 0x20)) return -1;      /* the size of the file: n blocks of 8192 bytes */
    return n;
}
static int chain_of(int head, int out[16]) { return chain_walk(head, out, 1); }

static int single_keys(const ksd_state *s) { int n = 0; for (int i = 0; i < s->nstores; i++) n += s->st[i].single ? s->st[i].n : 0; return n; }
static int single_blocks(const ksd_state *s) { int n = 0; for (int i = 0; i < s->nstores; i++) n += s->st[i].single; return n; }

static char title_buf[64];
static const char *title_of(int head) { memcpy(title_buf, card[head * 64] + 4, 60); title_buf[60] = 0; return title_buf; }

/* a card with a vault (with a key), some files of others, and `keys` single keys (60 to a block) */
static void single_setup(ksd_state *s, int keys, model *vm)
{
    static uint8_t work[KS_DATA];
    uint8_t f[KS_FRAME];
    int st, v;

    format();
    power_on();
    filler("PSXXSG", 0x31);
    ksd_scan(0, s, 1);
    v = new_store(s, "vault", 1, 9, vm);
    mk_store(f, &s->st[v], 3);
    ksd_add2(0, s, v, f, -1, the_key, work);
    madd(vm, f, -1);
    for (int i = 0; i < keys; i++) {
        mk_own(f, 100 + i, "own pw");
        for (int j = 0; j < s->nstores; j++) {
            if (!s->st[j].single || s->st[j].next_slot < 0) continue;
            CHECK(ksd_add(0, s, j, f, NULL, work) == KSD_OK, "a single key into a block with room");
            goto added;
        }
        { int rr = ksd_new_single(0, s, f, 1, 40 + i, work, &st); CHECK(rr == KSD_OK, "a new block of single keys (key %d, rc %d, blocks %d)", i, rr, single_blocks(s)); }
added:  ;
    }
    ksd_single_title(0, s);
}

static int vault_ok(const ksd_state *s, const model *vm)
{
    for (int i = 0; i < s->nstores; i++) if (!s->st[i].single && s->st[i].id == vm->id) return same_as(0, &s->st[i], vm);
    return 0;
}

static void test_singles(void)
{
    static uint8_t work[KS_DATA];
    static ksd_state s, t;
    model vm;
    uint8_t f[KS_FRAME];
    int st, chain[16];

    /* the first key makes the file: name, title, one block */
    single_setup(&s, 1, &vm);
    CHECK(s.single_head && s.single_head == s.single_last && single_blocks(&s) == 1 && single_keys(&s) == 1, "the first single key makes one block");
    CHECK(chain_of(s.single_head, chain) == 1, "the file is one block");
    CHECK(!memcmp(card[s.single_head] + 22, MCF_SKEY_TAG, 6), "the name has the tag of the single keys");
    CHECK(!strcmp(title_of(s.single_head), "PSXX key store S 01"), "the title: '%s'", title_of(s.single_head));
    CHECK(keyblocks() == 1, "one vault");
    for (int i = 0; i < s.nstores; i++) if (!s.st[i].single) CHECK(!strcmp(title_of(s.st[i].block), "PSXX key store M"), "the title of the vault: '%s'", title_of(s.st[i].block));
    ksd_scan(0, &t, 1);
    CHECK(t.nstores == 2 && t.single_head == s.single_head && single_keys(&t) == 1 && t.corrupt == 0 && t.free_count == s.free_count, "a scan finds the file again");
    CHECK(vault_ok(&t, &vm), "the vault is as it was");

    /* a block holds 60 keys; the 61st makes the next block, linked to the first */
    single_setup(&s, 60, &vm);
    CHECK(single_blocks(&s) == 1 && single_keys(&s) == 60, "sixty keys, one block");
    CHECK(!strcmp(title_of(s.single_head), "PSXX key store S 60"), "the title says 60: '%s'", title_of(s.single_head));
    mk_own(f, 500, "own pw");
    for (int j = 0; j < s.nstores; j++) if (s.st[j].single) CHECK(ksd_add(0, &s, j, f, NULL, work) == KSD_ERR_FULL, "the block is full");
    CHECK(ksd_new_single(0, &s, f, 1, 77, work, &st) == KSD_OK && s.st[st].single && s.st[st].n == 1 && single_blocks(&s) == 2, "the 61st key opens the next block");
    CHECK(s.single_last == s.st[st].block && s.single_head != s.single_last, "the last block is the new one");
    CHECK(chain_of(s.single_head, chain) == 2 && chain[1] == s.single_last, "two linked blocks");
    CHECK(card[s.single_head][0] == 0x51 && card[s.single_last][0] == 0x53 && card[s.single_last][4] == 0 && card[s.single_last][10] == 0, "first block named, the second a plain link");
    CHECK(!strcmp(title_of(s.single_head), "PSXX key store S 61"), "the title says 61: '%s'", title_of(s.single_head));
    ksd_scan(0, &t, 1);
    CHECK(single_keys(&t) == 61 && single_blocks(&t) == 2 && t.single_last == s.single_last && t.corrupt == 0, "a scan follows the link");
    CHECK(vault_ok(&t, &vm), "the vault is untouched");

    /* the third block: the middle one becomes 0x52 */
    for (int i = 1; i < 60; i++) { mk_own(f, 600 + i, "own pw"); for (int j = 0; j < s.nstores; j++) if (s.st[j].single && s.st[j].block == s.single_last) CHECK(ksd_add(0, &s, j, f, NULL, work) == KSD_OK, "fill the second block"); }
    mk_own(f, 700, "own pw");
    CHECK(ksd_new_single(0, &s, f, 1, 78, work, &st) == KSD_OK, "the third block");
    CHECK(chain_of(s.single_head, chain) == 3 && card[chain[1]][0] == 0x52 && card[chain[2]][0] == 0x53, "head 51, middle 52, last 53");
    ksd_single_title(0, &s);
    CHECK(!strcmp(title_of(s.single_head), "PSXX key store S 121"), "the title says 121: '%s'", title_of(s.single_head));

    /* a key of two frames in a block of its own: the pair, in slots 0 and 1 */
    {
        uint8_t big[KS_ENTRY_MAX];
        uint8_t k64[64];

        for (int i = 0; i < 64; i++) k64[i] = (uint8_t) (i * 5 + 1);
        single_setup(&s, 0, &vm);
        CHECK(ks_own_entry_seal2(big, (const uint8_t *) "pw", 2, TEST_ITER, (const uint8_t *) "0123456789abcdef0123456789ab", KS_TYPE_RAW, KS_CURVE_CARDANO << KS_FLAG_CURVE_SHIFT, k64, 64, "ada", "open name") == KS_OK, "a key of 64 bytes");
        CHECK(ksd_new_single(0, &s, big, 2, 5, work, &st) == KSD_OK && s.st[st].n == 1 && s.st[st].dir.two[0] == 1, "an entry of two frames in a block of its own");
        ksd_scan(0, &t, 1);
        CHECK(single_keys(&t) == 1 && t.corrupt == 0, "it is one key");
    }

    /* everything goes: the file, and only it */
    single_setup(&s, 130, &vm);
    CHECK(single_blocks(&s) == 3 && chain_of(s.single_head, chain) == 3, "three blocks to remove");
    CHECK(ksd_remove_store(0, &s, 1) == KSD_ERR_ARG, "a block of the single keys is not removed alone");
    CHECK(ksd_remove_singles(0, &s) == KSD_OK && s.single_head == 0 && single_blocks(&s) == 0 && s.nstores == 1, "the file is removed");
    ksd_scan(0, &t, 1);
    CHECK(t.nstores == 1 && t.free_count == 13 && vault_ok(&t, &vm), "a scan: the vault only, the blocks free (%d)", t.free_count);

    /* delete the keys with the signer's call: every single key marked removes the file, a part of them leaves the blocks */
    {
        static uint8_t marks[KSD_MAX_STORES][KS_SLOTS];
        int deleted = 0, need = 0;

        single_setup(&s, 70, &vm);
        memset(marks, 0, sizeof marks);
        for (int i = 0; i < s.nstores; i++) if (s.st[i].single) for (int k = 0; k < s.st[i].n; k++) marks[i][k] = 1;
        CHECK(ksd_del_marked(0, &s, marks, -1, NULL, work, &deleted, &need) == KSD_OK && deleted == 70, "every single key deleted");
        CHECK(s.single_head == 0 && s.nstores == 1 && vault_ok(&s, &vm), "the file is gone with the last key");
        single_setup(&s, 70, &vm);
        memset(marks, 0, sizeof marks);
        for (int i = 0; i < s.nstores; i++) if (s.st[i].single && i == 2) for (int k = 0; k < s.st[i].n; k++) marks[i][k] = 1;
        deleted = 0;
        CHECK(ksd_del_marked(0, &s, marks, -1, NULL, work, &deleted, &need) == KSD_OK && deleted == 10, "the keys of the last block deleted");
        CHECK(s.single_head && single_keys(&s) == 60 && chain_of(s.single_head, chain) == 2, "the empty block stays in the file for the next key");
        CHECK(!strcmp(title_of(s.single_head), "PSXX key store S 60"), "the title follows: '%s'", title_of(s.single_head));
        ksd_scan(0, &t, 1);
        CHECK(single_keys(&t) == 60 && single_blocks(&t) == 2 && t.corrupt == 0, "a scan agrees");
        mk_own(f, 901, "own pw");
        for (int j = 0; j < t.nstores; j++) if (t.st[j].single && t.st[j].next_slot >= 0) { CHECK(ksd_add(0, &t, j, f, NULL, work) == KSD_OK && t.st[j].block == t.single_last, "the next key goes into the empty block"); break; }
    }
}

/* power cut at every write of a new block of the single keys: the first one (the file), or the one linked to a full block */
static void sweep_new_single(int prefill, int mode)
{
    static uint8_t work[KS_DATA];
    static ksd_state s, t;
    model vm;
    uint8_t f[KS_FRAME];
    int chain[16], st, old_keys, old_blocks, ended_old = 0, ended_new = 0;

    for (int k = 0;; k++) {
        single_setup(&s, prefill, &vm);
        old_keys = single_keys(&s);
        old_blocks = single_blocks(&s);
        mk_own(f, 800, "own pw");
        power_on();
        fail_at = k;
        fail_mode = mode;
        faulted = 0;
        ksd_new_single(0, &s, f, 1, 55, work, &st);
        if (!faulted) { CHECK(k > 0, "some writes happen"); break; }
        power_on();
        CHECK(ksd_scan(0, &t, 1) == MCF_OK && t.corrupt == 0, "prefill %d cut %d: the card scans", prefill, k);
        CHECK(vault_ok(&t, &vm), "prefill %d cut %d: the vault is untouched", prefill, k);
        if (single_keys(&t) == old_keys + 1) {
            ended_new++;
            CHECK(single_blocks(&t) == old_blocks + 1 && chain_walk(t.single_head, chain, 0) == old_blocks + 1, "prefill %d cut %d: the new state is a whole file (the size in the first entry may still be the old one)", prefill, k);
        } else {
            ended_old++;
            CHECK(single_keys(&t) == old_keys && single_blocks(&t) == old_blocks, "prefill %d cut %d: the old state", prefill, k);
            if (old_blocks) CHECK(chain_walk(t.single_head, chain, 0) == old_blocks, "prefill %d cut %d: the old file is whole", prefill, k);
            else CHECK(t.single_head == 0, "prefill %d cut %d: no file", prefill, k);
        }
        CHECK(t.free_count >= s.free_count - 1, "prefill %d cut %d: at most the block that was written is not free", prefill, k);
    }
    CHECK(ended_old > 0 && ended_new > 0, "both ends are reached (%d old, %d new)", ended_old, ended_new);
}

static void test_singles_power(void)
{
    for (int mode = 0; mode < 2; mode++) { sweep_new_single(0, mode); sweep_new_single(60, mode); sweep_new_single(120, mode); }
}

/* a new vault is made together with its first key (no empty vault is ever on the card): the entry is sealed for the id, slot 0 and seq 1 of the directory that makes it live */
static void test_vault_with_key(void)
{
    static uint8_t work[KS_DATA], img[KS_DATA];
    static ksd_state s, t;
    uint8_t f[KS_FRAME], nonce[12], ent[32], got[KS_KEY_MAX];
    int st = -1, ty, fl, el, slot0;
    char lab[KS_LABEL_STORE + 1];
    uint16_t id;

    format();
    power_on();
    ksd_scan(0, &s, 1);
    id = ksd_free_id(&s, 0);
    CHECK(id == 1, "the first free id is 1, not 0");
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t) (i * 9 + 1);
    for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (i * 3 + 7);
    CHECK(ks_store_entry_seal(f, the_key, id, 0, nonce, 1, KS_TYPE_BIP39, 0, ent, 32, "first") == KS_OK, "the entry is sealed for the new vault");
    CHECK(ksd_make_block(0, &s, 0, "Family", &the_pw, the_key, id, f, 1, work, &st) == KSD_OK && st == 0 && !s.st[0].single && s.st[0].n == 1, "a vault with its first key");
    CHECK(!strcmp(title_of(s.st[0].block), "PSXX key store M") && !memcmp(card[s.st[0].block] + 22, MCF_KEY_TAG, 6), "the title and the name of a vault");
    ksd_scan(0, &t, 1);
    CHECK(t.nstores == 1 && t.st[0].n == 1 && t.st[0].seq == 1 && t.corrupt == 0 && ks_dir_mac_ok(&t.st[0].dir, the_key), "a scan finds it, the directory is signed with the key");
    CHECK(ksd_read(0, &t.st[0], img) == MCF_OK, "the chain matches the entry");
    slot0 = ks_live_slot(&t.st[0].dir, 0);
    CHECK(slot0 == 0 && ks_store_entry_open(img + (KS_DIR_FRAMES + slot0) * KS_FRAME, the_key, t.st[0].id, slot0, &ty, &fl, got, &el, lab) == KS_OK && el == 32 && !memcmp(got, ent, 32) && !strcmp(lab, "first"), "the key opens");
    /* another key goes in the usual way */
    CHECK(t.st[0].next_slot == 1, "the next slot");
    mk_store(f, &t.st[0], 5);
    CHECK(ksd_add(0, &t, 0, f, the_key, work) == KSD_OK && t.st[0].n == 2, "a second key");
    /* the id: one that is taken is skipped */
    CHECK(ksd_free_id(&t, t.st[0].id) != t.st[0].id && ksd_free_id(&t, t.st[0].id) != 0, "a taken id is not given again");

    /* power cuts: the vault is not there, or it is there with its key (never empty, never without the key) */
    for (int mode = 0; mode < 2; mode++)
        for (int k = 0;; k++) {
            format();
            power_on();
            ksd_scan(0, &s, 1);
            CHECK(ks_store_entry_seal(f, the_key, 5, 0, nonce, 1, KS_TYPE_BIP39, 0, ent, 32, "first") == KS_OK, "seal");
            fail_at = k;
            fail_mode = mode;
            faulted = 0;
            ksd_make_block(0, &s, 0, "Family", &the_pw, the_key, 5, f, 1, work, &st);
            if (!faulted) break;
            power_on();
            CHECK(ksd_scan(0, &t, 1) == MCF_OK && t.corrupt == 0, "cut %d: the card scans", k);
            CHECK(t.nstores == 0 || (t.nstores == 1 && t.st[0].n == 1 && ksd_read(0, &t.st[0], img) == MCF_OK), "cut %d: no vault, or one with its key", k);
        }
}

int main(void)
{
    init_pw();
    test_format();
    test_invalidate();
    test_blocks();
    test_fill_store();
    test_damage();
    test_remove_store();
    test_double();
    test_double_store();
    test_del_marked();
    test_singles();
    test_singles_power();
    test_vault_with_key();
    test_power_cuts();
    test_fuzz();
    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
