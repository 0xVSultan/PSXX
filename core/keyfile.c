#include "keyfile.h"
#include <string.h>
#include "aes.h"
#include "blob.h"
#include "hash/crc32.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "util.h"

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v & 0xFFFF); }
static unsigned get16(const uint8_t *p) { return (unsigned) (p[0] << 8 | p[1]); }
static uint32_t get32(const uint8_t *p) { return (uint32_t) get16(p) << 16 | get16(p + 2); }

/* ---- the directory ---- */

#define DIR_MAC_AT 104

void ks_dir_encode(uint8_t f[KS_FRAME], const ks_dir *d)
{
    memset(f, 0, KS_FRAME);
    f[0] = 'P'; f[1] = 'K'; f[3] = (uint8_t) d->flags;
    put16(f + 4, d->id);
    put32(f + 6, d->seq);
    f[10] = (uint8_t) d->last;
    memcpy(f + 12, d->live, 8);
    memcpy(f + 20, d->chain, 16);
    memcpy(f + 36, d->label, KS_STORE_LABEL);
    put32(f + 68, d->iter);
    memcpy(f + 72, d->salt, 16);
    memcpy(f + 88, d->check, 16);
    memcpy(f + DIR_MAC_AT, d->mac, 16);
    memcpy(f + 120, d->two, 4);
    put32(f + 124, crc32(f, 124));
}

int ks_dir_decode(ks_dir *d, const uint8_t f[KS_FRAME])
{
    memset(d, 0, sizeof *d);
    if (f[0] != 'P' || f[1] != 'K' || f[2] || (f[3] & ~KS_DIR_PW) || f[10] >= KS_SLOTS || f[11]) return KS_ERR_FORMAT;
    if (crc32(f, 124) != get32(f + 124)) return KS_ERR_CRC;
    d->flags = f[3];
    d->id = (uint16_t) get16(f + 4);
    d->seq = get32(f + 6);
    d->last = f[10];
    memcpy(d->live, f + 12, 8);
    memcpy(d->chain, f + 20, 16);
    memcpy(d->label, f + 36, KS_STORE_LABEL);
    d->label[KS_STORE_LABEL] = 0;
    d->iter = get32(f + 68);
    memcpy(d->salt, f + 72, 16);
    memcpy(d->check, f + 88, 16);
    memcpy(d->mac, f + DIR_MAC_AT, 16);
    memcpy(d->two, f + 120, 4);
    for (int s = KS_SLOTS; s < 64; s++) if (d->live[s >> 3] & (1 << (s & 7))) return KS_ERR_FORMAT;       /* a slot that does not exist */
    return KS_OK;
}

int ks_dir_pick(ks_dir *d, const uint8_t a[KS_FRAME], const uint8_t b[KS_FRAME])
{
    ks_dir x, y;
    int ra = ks_dir_decode(&x, a), rb = ks_dir_decode(&y, b);

    if (ra && rb) return -1;
    if (!ra && (rb || x.seq > y.seq)) { *d = x; return 0; }
    *d = y;
    return 1;
}

int ks_slot_live(const ks_dir *d, int slot) { return slot >= 0 && slot < KS_SLOTS && (d->live[slot >> 3] >> (slot & 7)) & 1; }

void ks_slot_set(ks_dir *d, int slot, int live)
{
    if (slot < 0 || slot >= KS_SLOTS) return;
    if (live) d->live[slot >> 3] |= (uint8_t) (1 << (slot & 7));
    else d->live[slot >> 3] &= (uint8_t) ~(1 << (slot & 7));
}

int ks_slot_pair(const ks_dir *d, int slot) { return slot >= 0 && slot < KS_SLOTS && (d->two[slot >> 4] >> ((slot >> 1) & 7)) & 1; }

/* the second slot of a pair is not an entry of its own */
int ks_live_count(const ks_dir *d)
{
    int n = 0;
    for (int s = 0; s < KS_SLOTS; s++) n += ks_slot_live(d, s) && !((s & 1) && ks_slot_pair(d, s));
    return n;
}

int ks_next_slot(const ks_dir *d)
{
    for (int i = 1; i <= KS_SLOTS; i++) {
        int s = (d->last + i) % KS_SLOTS;
        if (!ks_slot_live(d, s)) return s;
    }
    return -1;
}

void ks_chain(uint8_t h[16], const uint8_t *entries, const uint8_t live[8])
{
    uint8_t cur[32] = {0};

    for (int s = 0; s < KS_SLOTS; s++) {
        sha256_ctx c;
        uint8_t b = (uint8_t) s;

        if (!((live[s >> 3] >> (s & 7)) & 1)) continue;
        sha256_init(&c);
        sha256_update(&c, cur, 16);
        sha256_update(&c, &b, 1);
        sha256_update(&c, entries + s * KS_FRAME, KS_FRAME);
        sha256_final(&c, cur);
    }
    memcpy(h, cur, 16);
}

/* ---- the store password ---- */

int ks_store_key(uint8_t key[32], uint8_t check[16], const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t salt[16])
{
    static const char INFO[] = "psx-store-v1", CHK[] = "psx-store-check";
    uint8_t ikm[64], mac[32];

    if (!iter || iter > BLOB_ITER_MAX) return KS_ERR_ARG;
    pbkdf2_hmac_sha512(pw, pwlen, salt, 16, iter, ikm, 64);
    hkdf_sha256(salt, 16, ikm, 64, (const uint8_t *) INFO, sizeof INFO - 1, key, 32);
    hmac_sha256(key, 32, (const uint8_t *) CHK, sizeof CHK - 1, mac);
    memcpy(check, mac, 16);
    secure_zero(ikm, sizeof ikm);
    secure_zero(mac, sizeof mac);
    return KS_OK;
}

static void dir_mac(uint8_t mac[16], const ks_dir *d, const uint8_t key[32])
{
    uint8_t f[KS_FRAME], m[32];
    ks_dir t = *d;

    memset(t.mac, 0, 16);
    ks_dir_encode(f, &t);
    hmac_sha256(key, 32, f, 124, m);                    /* all of it but the CRC: the live slots, the pairs ... */
    memcpy(mac, m, 16);
}

void ks_dir_seal(ks_dir *d, const uint8_t key[32]) { dir_mac(d->mac, d, key); }

int ks_dir_mac_ok(const ks_dir *d, const uint8_t key[32])
{
    uint8_t mac[16], x = 0;

    dir_mac(mac, d, key);
    for (int i = 0; i < 16; i++) x |= (uint8_t) (mac[i] ^ d->mac[i]);
    return x == 0;
}

/* ---- entries ---- */

/* what an entry may hold: BIP39 16..32 bytes of entropy (a language), Monero a seed, a raw key of a kind (a secp256k1 key may name the kind of address it was made for): 32 bytes, the
 * Cardano extended key 64 (an entry of two frames) */
int ks_entry_ok(int type, int flags, int n)
{
    if (flags & ~(KS_FLAG_PASSPHRASE | KS_FLAG_LANG_MASK | KS_FLAG_CURVE_MASK)) return 0;
    if (type == KS_TYPE_RAW) return n == (KS_CURVE(flags) == KS_CURVE_CARDANO ? 64 : 32) && (KS_KIND(flags) == 0 || KS_CURVE(flags) == KS_CURVE_SECP256K1) && KS_CURVE(flags) <= KS_CURVE_CARDANO && !(flags & KS_FLAG_PASSPHRASE);
    if (n < 16 || n > 32 || (n & 3)) return 0;
    if (type == KS_TYPE_BIP39) return KS_CURVE(flags) == 0;
    if (type == KS_TYPE_MONERO) return KS_LANG(flags) == 0 && KS_CURVE(flags) == 0;
    return 0;
}


int ks_plain(uint8_t pt[PT_MAX], int type, int flags, const uint8_t *entropy, int elen, const char *label, int lcap)
{
    if (!ks_entry_ok(type, flags, elen) || !entropy || !label) return 0;
    pt[0] = (uint8_t) (type << 4 | (type == KS_TYPE_RAW ? KS_CURVE(flags) : KS_LANG(flags)));
    pt[1] = (uint8_t) ((flags & KS_FLAG_PASSPHRASE) | (type == KS_TYPE_RAW ? KS_LANG(flags) << 1 : 0));
    pt[2] = (uint8_t) elen;
    pt[3] = 0;
    memcpy(pt + 4, entropy, (size_t) elen);
    memset(pt + 4 + elen, 0, (size_t) lcap);
    for (int i = 0; i < lcap && label[i]; i++) pt[4 + elen + i] = (uint8_t) label[i];
    return 4 + elen + lcap;
}

int ks_store_entry_seal(uint8_t f[KS_FRAME], const uint8_t key[32], uint16_t id, int slot, const uint8_t nonce[12], uint32_t aseq, int type, int flags, const uint8_t *entropy, int elen,
                        const char *label)
{
    uint8_t pt[PT_MAX], a[9];
    aes_ctx c;
    int n = ks_plain(pt, type, flags, entropy, elen, label, KS_LABEL_STORE);

    if (!n || n > CT_ONE || slot < 0 || slot >= KS_SLOTS) return KS_ERR_ARG;                 /* (a key over 32 bytes takes two frames: keyfile_open.c, the signer) */
    memset(f, 0xFF, KS_FRAME);
    f[0] = KS_ENTRY_STORE;
    f[1] = (uint8_t) n;
    put32(f + 2, aseq);
    memcpy(f + 6, nonce, 12);
    memcpy(a, f, 6);                                   /* kind, length, aseq */
    put16(a + 6, id);
    a[8] = (uint8_t) slot;
    aes_init(&c, key, 256);
    aes_gcm_encrypt(&c, nonce, a, sizeof a, pt, (size_t) n, f + 18, f + 18 + n);
    aes_wipe(&c);
    secure_zero(pt, sizeof pt);
    return KS_OK;
}

int ks_own_entry_seal(uint8_t f[KS_FRAME], const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t rnd[28], int type, int flags, const uint8_t *entropy, int elen, const char *label,
                      const char *open_label)
{
    uint8_t pt[PT_MAX];
    int n = ks_plain(pt, type, flags, entropy, elen, label, KS_LABEL), r;

    if (!n) return KS_ERR_ARG;
    memset(f, 0xFF, KS_FRAME);
    r = blob_seal(pw, pwlen, NULL, 0, iter, rnd, pt, (size_t) n, f + 2, KS_MAX_BLOB);
    secure_zero(pt, sizeof pt);
    if (r < 0 || r > KS_MAX_BLOB) return KS_ERR_ARG;
    f[0] = KS_ENTRY_OWN;
    f[1] = (uint8_t) r;
    if (open_label) {
        memset(f + KS_PUBLIC_AT, 0, KS_PUBLIC);
        for (int i = 0; i < KS_PUBLIC && open_label[i]; i++) f[KS_PUBLIC_AT + i] = (uint8_t) open_label[i];
    }
    return KS_OK;
}
