/* The openings of the key store entries and the listing of its keys (the signer overlay only: the main card seals and writes, it never opens). The format is core/keyfile.h. */
#include "keyfile.h"
#include <string.h>
#include "aes.h"
#include "hash/crc32.h"
#include "blob.h"
#include "util.h"

int ks_live_slot(const ks_dir *d, int n)
{
    for (int s = 0; s < KS_SLOTS; s++) if (ks_slot_live(d, s) && !((s & 1) && ks_slot_pair(d, s)) && n-- == 0) return s;
    return -1;
}

int ks_entry_kind(const uint8_t f[KS_FRAME]) { return f[0] == KS_ENTRY_STORE || f[0] == KS_ENTRY_OWN ? f[0] : KS_ENTRY_NONE; }

static int unplain(const uint8_t *pt, int n, int *type, int *flags, uint8_t entropy[KS_KEY_MAX], int *elen, char *label, int lcap)
{
    int e, t, fl;

    if (n < 4 + 16 + lcap) return KS_ERR_ENTRY;
    e = pt[2];
    t = pt[0] >> 4;
    if ((pt[1] & 0xE0) || pt[3]) return KS_ERR_ENTRY;
    fl = (pt[1] & KS_FLAG_PASSPHRASE) | (t == KS_TYPE_RAW ? (pt[0] & 15) << KS_FLAG_CURVE_SHIFT | (pt[1] >> 1 & 15) << KS_FLAG_LANG_SHIFT : (pt[0] & 15) << KS_FLAG_LANG_SHIFT);
    if (!ks_entry_ok(t, fl, e) || n != 4 + e + lcap) return KS_ERR_ENTRY;
    *type = t;
    *flags = fl;
    *elen = e;
    memcpy(entropy, pt + 4, (size_t) e);
    memcpy(label, pt + 4 + e, (size_t) lcap);
    label[lcap] = 0;
    return KS_OK;
}


int ks_store_entry_open(const uint8_t *f, const uint8_t key[32], uint16_t id, int slot, int *type, int *flags, uint8_t entropy[KS_KEY_MAX], int *elen, char label[KS_LABEL_STORE + 1])
{
    uint8_t pt[PT_MAX], a[9];
    aes_ctx c;
    int n = f[1], r;

    if (f[0] != KS_ENTRY_STORE || n < 4 + 16 + KS_LABEL_STORE || n > PT_MAX || slot < 0 || slot >= KS_SLOTS) return KS_ERR_ENTRY;
    ks_aad(a, f, id, slot, n > CT_ONE ? 2 : 1);
    aes_init(&c, key, 256);
    r = aes_gcm_decrypt(&c, f + 6, a, sizeof a, f + 18, (size_t) n, f + 18 + n, pt);
    aes_wipe(&c);
    if (r) { secure_zero(pt, sizeof pt); return KS_ERR_PASSWORD; }
    r = unplain(pt, n, type, flags, entropy, elen, label, KS_LABEL_STORE);
    secure_zero(pt, sizeof pt);
    return r;
}

int ks_own_entry_open(const uint8_t *f, const uint8_t *pw, size_t pwlen, int *type, int *flags, uint8_t entropy[KS_KEY_MAX], int *elen, char label[KS_LABEL + 1])
{
    uint8_t pt[PT_MAX], blob[KS_MAX_BLOB2];
    int r, n = f[1];

    if (f[0] != KS_ENTRY_OWN || n < BLOB_OVERHEAD || n > KS_MAX_BLOB2) return KS_ERR_ENTRY;
    memcpy(blob, f + 2, (size_t) (n < BLOB_HEAD ? n : BLOB_HEAD));
    if (n > BLOB_HEAD) memcpy(blob + BLOB_HEAD, f + KS_FRAME, (size_t) (n - BLOB_HEAD));
    r = blob_open(pw, pwlen, NULL, 0, blob, (size_t) n, pt, sizeof pt);
    if (r == -2) return KS_ERR_PASSWORD;
    if (r < 0) return KS_ERR_ENTRY;
    r = unplain(pt, r, type, flags, entropy, elen, label, KS_LABEL);
    secure_zero(pt, sizeof pt);
    return r;
}

void ks_own_entry_open_label(const uint8_t f[KS_FRAME], char out[KS_PUBLIC + 1])
{
    out[0] = 0;
    if (f[0] != KS_ENTRY_OWN || f[KS_PUBLIC_AT] == 0xFF) return;
    memcpy(out, f + KS_PUBLIC_AT, KS_PUBLIC);
    out[KS_PUBLIC] = 0;
}

uint32_t ks_own_entry_iterations(const uint8_t f[KS_FRAME])
{
    return f[0] == KS_ENTRY_OWN && f[1] >= BLOB_OVERHEAD ? blob_iterations(f + 2, f[1] < BLOB_HEAD ? f[1] : BLOB_HEAD) : 0;
}

/* ---- entries of two frames: the pair map, the sealing (the signer overlay only) ---- */

void ks_pair_set(ks_dir *d, int head, int on)
{
    if (head < 0 || head >= KS_SLOTS - 1) return;
    if (on) d->two[head >> 4] |= (uint8_t) (1 << ((head >> 1) & 7));
    else d->two[head >> 4] &= (uint8_t) ~(1 << ((head >> 1) & 7));
}

int ks_frames_of_key(int elen) { return elen > 32 ? 2 : 1; }

/* the frames of an entry, from its length byte: a store key entry with a plain text over CT_ONE bytes, an own entry with a blob over KS_MAX_BLOB bytes take two */
int ks_frames_of_entry(const uint8_t f[KS_FRAME]) { return f[1] > (f[0] == KS_ENTRY_STORE ? CT_ONE : KS_MAX_BLOB) ? 2 : 1; }

/* the first pair of free slots after `last`, wrapping: the even one */
int ks_next_pair(const ks_dir *d)
{
    for (int i = 1; i <= KS_PAIRS; i++) {
        int p = ((d->last >> 1) + i) % KS_PAIRS;

        if (!ks_slot_live(d, 2 * p) && !ks_slot_live(d, 2 * p + 1)) return 2 * p;
    }
    return -1;
}

/* a pair has both its slots live, and there are 30 of them */
int ks_dir_pairs_ok(const ks_dir *d)
{
    for (int k = 0; k < 32; k++) {
        if (!((d->two[k >> 3] >> (k & 7)) & 1)) continue;
        if (k >= KS_PAIRS || !ks_slot_live(d, 2 * k) || !ks_slot_live(d, 2 * k + 1)) return 0;
    }
    return 1;
}

void ks_aad(uint8_t a[9], const uint8_t *f, uint16_t id, int slot, int nf)
{
    memcpy(a, f, 6);                                   /* kind, length, aseq */
    a[6] = (uint8_t) (id >> 8);
    a[7] = (uint8_t) id;
    a[8] = (uint8_t) (slot | (nf - 1) << 6);           /* the slot, and whether the entry has a second frame */
}

int ks_store_entry_seal2(uint8_t *f, const uint8_t key[32], uint16_t id, int slot, const uint8_t nonce[12], uint32_t aseq, int type, int flags, const uint8_t *entropy, int elen,
                         const char *label)
{
    uint8_t pt[PT_MAX], a[9];
    aes_ctx c;
    int nf = ks_frames_of_key(elen), n = ks_plain(pt, type, flags, entropy, elen, label, KS_LABEL_STORE);

    if (!n || slot < 0 || slot >= KS_SLOTS || (nf == 2 && (slot & 1)) || (n > CT_ONE) != (nf == 2)) return KS_ERR_ARG;
    memset(f, 0xFF, (size_t) nf * KS_FRAME);
    f[0] = KS_ENTRY_STORE;
    f[1] = (uint8_t) n;
    f[2] = (uint8_t) (aseq >> 24); f[3] = (uint8_t) (aseq >> 16); f[4] = (uint8_t) (aseq >> 8); f[5] = (uint8_t) aseq;
    memcpy(f + 6, nonce, 12);
    ks_aad(a, f, id, slot, nf);
    aes_init(&c, key, 256);
    aes_gcm_encrypt(&c, nonce, a, sizeof a, pt, (size_t) n, f + 18, f + 18 + n);
    aes_wipe(&c);
    secure_zero(pt, sizeof pt);
    return KS_OK;
}

int ks_own_entry_seal2(uint8_t *f, const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t rnd[28], int type, int flags, const uint8_t *entropy, int elen, const char *label,
                       const char *open_label)
{
    uint8_t pt[PT_MAX], blob[KS_MAX_BLOB2];
    int nf = ks_frames_of_key(elen), n = ks_plain(pt, type, flags, entropy, elen, label, KS_LABEL), r;

    if (!n) return KS_ERR_ARG;
    r = blob_seal(pw, pwlen, NULL, 0, iter, rnd, pt, (size_t) n, blob, KS_MAX_BLOB2);
    secure_zero(pt, sizeof pt);
    if (r < 0 || r > KS_MAX_BLOB2 || (r > KS_MAX_BLOB) != (nf == 2)) return KS_ERR_ARG;
    memset(f, 0xFF, (size_t) nf * KS_FRAME);
    memcpy(f + 2, blob, (size_t) (r < BLOB_HEAD ? r : BLOB_HEAD));
    if (r > BLOB_HEAD) memcpy(f + KS_FRAME, blob + BLOB_HEAD, (size_t) (r - BLOB_HEAD));
    f[0] = KS_ENTRY_OWN;
    f[1] = (uint8_t) r;
    if (open_label) {
        memset(f + KS_PUBLIC_AT, 0, KS_PUBLIC);
        for (int i = 0; i < KS_PUBLIC && open_label[i]; i++) f[KS_PUBLIC_AT + i] = (uint8_t) open_label[i];
    }
    secure_zero(blob, sizeof blob);
    return KS_OK;
}
