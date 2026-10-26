#pragma once
/* The key store: a block of a memory card that holds up to KS_MAX_KEYS encrypted keys. This file is only the format: the frames of the block,
 * built and checked here; reading and writing the card is hal/psx/keystore.c.
 *
 * A store is one block, 62 data frames of 128 bytes (KS_DATA = 7936 bytes). Nothing in it is rewritten in place except one of two directory frames, so no spare block is needed:
 *   frame 0, 1       two copies of the directory (below); the one with the higher seq that checks out is the current one
 *   frame 2 .. 61    60 slots of one entry each; a slot is live when the directory says so, any other slot is free and is written over by the next entry
 * An append writes the entry into a free slot (no live slot is touched), then writes the new directory over the OLDER copy: a power cut before that last write leaves the
 * current directory as it was, a cut during it leaves a frame whose CRC fails (and so the current one wins). The slots after the one written last are tried first, so the
 * frames wear evenly.
 *
 * Directory frame (integers big endian; there is no version, one format):
 *   0 "PK" | 2 0 | 3 flags u8 | 4 id u16 | 6 seq u32 | 10 last u8 (the slot written last) | 11 0 | 12 live[8] (bit s of slot s) | 20 chain[16] | 36 label[32] (UTF-8, 0 padded)
 *   | 68 iter u32 | 72 salt[16] | 88 check[16] | 104 mac[16] | 120 two[4] | 124 CRC-32 of the bytes before it
 * flags bit 0: the store has a password (KS_DIR_PW): iter, salt and check describe it, mac is an HMAC-SHA256 of the bytes 0..123 (its own 16 bytes read as 0) under the store key (without a
 * password they are 0).
 * two: bit k set when the slots 2k and 2k + 1 hold ONE entry of two frames (a key longer than 32 bytes: the Cardano extended key); both their live bits are set. The pair is written, listed and
 * deleted as one entry; the key store counts entries, not frames.
 * chain: the first 16 bytes of H(n), H(0) = 0, H(i) = SHA-256(H(i-1) || slot || the entry frame) over the live slots in order: it ties the directory to the exact entries, so one
 * cannot be swapped for an older one (with a password the mac keeps the chain from being recomputed by someone who does not know the password). The CRC finds damage.
 *
 * Entry frame, two kinds:
 *   1  sealed with the store key:  1 | ctlen u8 | aseq u32 (the seq of the directory that made it live) | nonce[12] | ciphertext | tag[16]; AES-256-GCM, the first 6 bytes, the id and
 *      the slot are the additional data, so an entry opens only in its own place and time; the rest of the frame is 0xFF
 *   2  sealed with its own password:  2 | len u8 | a blob (core/blob.h: its own salt and rounds) | 0xFF ... | open label[16] at 112 (UTF-8, 0 padded; 0xFF: none); the rest 0xFF
 *      The open label is a cover name that the list shows without a password: it need not be the true label (that one is inside the blob) and it says nothing about the content.
 *      It is not covered by the blob's tag; the directory chain (and, with a store password, its mac) covers the whole frame.
 * A store can mix them. The store key is PBKDF2-HMAC-SHA512(password, salt, iter) -> HKDF-SHA256 "psx-store-v1": the password is stretched once for all entries of the store.
 *
 * Plain text of an entry (inside either), no version: four header bytes | key[n] | label (UTF-8, padded with 0): 32 bytes in an entry of the store key, 16 in an own entry.
 *   byte 0   type in the high nibble (1 BIP39, 2 Monero, 3 raw key); in the low nibble the language of the BIP39 words (0 English; the seed comes from the words, so the same entropy in
 *            another language is another wallet: a reader that does not have that list must refuse the entry, not read it as English), or the kind of the raw key (KS_CURVE_*)
 *   byte 1   bit 0 a BIP39 passphrase is used; bits 1..4 of a secp256k1 raw key: the kind of address the vanity search made it for (1 + the row of the table, 0 = none); the rest 0
 *   byte 2   n, the length of the key
 *   byte 3   0 (kept for what comes later)
 * The callers see these as one `flags` word (KS_FLAG_*): passphrase, language or hint, curve. Type RAW: one key with no derivation (TON, or an imported key). */
#include <stddef.h>
#include <stdint.h>

#define KS_FRAME 128
#define KS_FRAMES 62                        /* data frames of the block */
#define KS_DATA (KS_FRAMES * KS_FRAME)      /* 7936 */
#define KS_DIR_FRAMES 2
#define KS_SLOTS 60
#define KS_MAX_KEYS KS_SLOTS                /* per store */
#define KS_MAX_BLOB 110                     /* an own entry: 58 bytes of blob overhead + at most 4 + 32 + 16 (a frame holds 126) */
#define KS_MAX_BLOB2 238                    /* an entry of two frames: the blob goes on in the second (110 bytes in the first, then 128) */
#define KS_KEY_MAX 64                       /* the longest key of an entry (two frames) */
#define KS_ENTRY_MAX (2 * KS_FRAME)         /* the buffer of an entry */
#define KS_PAIRS (KS_SLOTS / 2)
#define KS_LABEL 16                         /* the label inside an own entry (it shows after the password) */
#define KS_LABEL_STORE 32                   /* the label inside an entry of the store key (it shows once the store is open) */
#define KS_PUBLIC 16                        /* the open label of an own entry: in the frame, at KS_PUBLIC_AT, seen without any password */
#define KS_PUBLIC_AT 112
#define KS_STORE_LABEL 32
#define KS_TYPE_BIP39 1
#define KS_TYPE_MONERO 2
#define KS_TYPE_RAW 3
#define KS_FLAG_PASSPHRASE 1
#define KS_FLAG_LANG_SHIFT 1
#define KS_FLAG_LANG_MASK (15 << KS_FLAG_LANG_SHIFT)
#define KS_FLAG_CURVE_SHIFT 5
#define KS_FLAG_CURVE_MASK (15 << KS_FLAG_CURVE_SHIFT)
#define KS_LANG(flags) (((flags) & KS_FLAG_LANG_MASK) >> KS_FLAG_LANG_SHIFT)
/* A raw secp256k1 key has no language: the same bits say what the vanity search made it for (1 + the row of the table of the kinds of signer_vanity.h; 0 = nothing), so that the
 * screen after the loading shows that address and not the Ethereum one. */
#define KS_KIND(flags) KS_LANG(flags)
#define KS_CURVE(flags) (((flags) & KS_FLAG_CURVE_MASK) >> KS_FLAG_CURVE_SHIFT)
/* The kind of a raw key: 0 ed25519 seed (TON, Solana...), 1 secp256k1 (Bitcoin, Ethereum, Nostr, Zcash transparent...), 2 sr25519 mini secret, 3 Orchard spending key, 4 Cardano. */
enum { KS_CURVE_ED25519 = 0, KS_CURVE_SECP256K1 = 1, KS_CURVE_SR25519 = 2, KS_CURVE_ORCHARD = 3, KS_CURVE_CARDANO = 4 };     /* Cardano: the extended key kL | kR, 64 bytes: an entry of two frames */
#define KS_DIR_PW 1                         /* directory flag: the store has a password */
enum { KS_ENTRY_NONE = 0, KS_ENTRY_STORE = 1, KS_ENTRY_OWN = 2 };
#define KS_ITER_STORE 16384                 /* rounds of the store password (a key of its own: BLOB_ITER_KEY) */

enum { KS_OK = 0, KS_ERR_FORMAT = -1, KS_ERR_CRC = -2, KS_ERR_FULL = -3, KS_ERR_ARG = -4, KS_ERR_PASSWORD = -5, KS_ERR_ENTRY = -6, KS_ERR_CHAIN = -7 };

typedef struct {
    uint16_t id;
    uint32_t seq;
    int      flags;
    int      last;                          /* the slot written last, 0..59 */
    uint8_t  live[8];
    uint8_t  two[4];                        /* pairs of slots that hold one entry of two frames */
    uint8_t  chain[16];
    char     label[KS_STORE_LABEL + 1];
    uint32_t iter;
    uint8_t  salt[16], check[16], mac[16];
} ks_dir;

/* The directory frame: encode, decode (KS_ERR_FORMAT, KS_ERR_CRC). */
void ks_dir_encode(uint8_t f[KS_FRAME], const ks_dir *d);
int ks_dir_decode(ks_dir *d, const uint8_t f[KS_FRAME]);
/* The current directory of two frames: the valid one with the higher seq. Returns its index (0 or 1), or -1 when neither is valid. */
int ks_dir_pick(ks_dir *d, const uint8_t a[KS_FRAME], const uint8_t b[KS_FRAME]);

int ks_slot_live(const ks_dir *d, int slot);
void ks_slot_set(ks_dir *d, int slot, int live);
/* Whether the slot is one of the two of an entry of two frames (and, with ks_pair_set, making a pair of the slots head and head + 1, head even). */
int ks_slot_pair(const ks_dir *d, int slot);
void ks_pair_set(ks_dir *d, int head, int on);
/* The entries (a pair counts once). */
int ks_live_count(const ks_dir *d);
/* The first slot of the n-th live entry (n from 0), or -1. */
int ks_live_slot(const ks_dir *d, int n);
/* The slot an append of one frame goes to: the first free one after `last`, wrapping; -1 when there is none. */
int ks_next_slot(const ks_dir *d);
/* The signer only (keyfile_open.c): the first pair of free slots after `last` (the even one) for an entry of two frames; how many frames an entry of a key of `elen` bytes takes, and
 * how many the entry has (from its length byte); a directory whose pair map is consistent (the main card does not check it, the signer does). */
int ks_next_pair(const ks_dir *d);
int ks_frames_of_key(int elen);
int ks_frames_of_entry(const uint8_t f[KS_FRAME]);
int ks_dir_pairs_ok(const ks_dir *d);
/* The chain over the live slots of `entries` (KS_SLOTS frames). */
void ks_chain(uint8_t h[16], const uint8_t *entries, const uint8_t live[8]);

/* The store key of a password: key (32) and the check value (16) that tells a wrong password at once. The long part: iter rounds of PBKDF2. */
int ks_store_key(uint8_t key[32], uint8_t check[16], const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t salt[16]);
/* The mac of a directory (flags with KS_DIR_PW) under the store key: ks_dir_seal sets d->mac, ks_dir_mac_ok compares it (1 when it is right). */
void ks_dir_seal(ks_dir *d, const uint8_t key[32]);
int ks_dir_mac_ok(const ks_dir *d, const uint8_t key[32]);

/* The kind of an entry frame (KS_ENTRY_*). */
int ks_entry_kind(const uint8_t f[KS_FRAME]);
/* Kind 1: `slot`, `aseq` (the seq the directory will have) and `id` go into the additional data; nonce is 12 bytes the caller makes unique per entry. Returns KS_OK or KS_ERR_ARG. */
int ks_store_entry_seal(uint8_t f[KS_FRAME], const uint8_t key[32], uint16_t id, int slot, const uint8_t nonce[12], uint32_t aseq, int type, int flags, const uint8_t *entropy, int elen,
                        const char *label);          /* label up to KS_LABEL_STORE bytes */
/* Opens it: KS_ERR_PASSWORD for a wrong key or a changed entry, KS_ERR_ENTRY for a frame that is not such an entry. `f` is the entry's frames one after the other (KS_ENTRY_MAX bytes
 * for an entry of two; `slot` is its first); the key buffers of the open functions are KS_KEY_MAX bytes. */
int ks_store_entry_open(const uint8_t *f, const uint8_t key[32], uint16_t id, int slot, int *type, int *flags, uint8_t entropy[KS_KEY_MAX], int *elen, char label[KS_LABEL_STORE + 1]);
/* Kind 2: the plain text sealed with its own password (blob_seal, `rnd` 28 bytes of fresh random data). */
int ks_own_entry_seal(uint8_t f[KS_FRAME], const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t rnd[28], int type, int flags, const uint8_t *entropy, int elen, const char *label,
                      const char *open_label);   /* label up to KS_LABEL bytes; open_label up to KS_PUBLIC bytes or NULL */
int ks_own_entry_open(const uint8_t *f, const uint8_t *pw, size_t pwlen, int *type, int *flags, uint8_t entropy[KS_KEY_MAX], int *elen, char label[KS_LABEL + 1]);
/* The open label of an own entry ('' when it has none or the frame is of the other kind). */
void ks_own_entry_open_label(const uint8_t f[KS_FRAME], char out[KS_PUBLIC + 1]);
/* The rounds an own entry asks for (0 if it is not one): to tell the user how long opening it takes. */
uint32_t ks_own_entry_iterations(const uint8_t f[KS_FRAME]);

/* Shared by keyfile.c (the seals, in the main card) and keyfile_open.c (the openings, only in the signer): what an entry may hold, and its additional data. */
#define PT_MAX (4 + KS_KEY_MAX + KS_LABEL_STORE)
#define CT_ONE (KS_FRAME - 18 - 16)                         /* the longest plain text of a store key entry in one frame: 94 bytes */
#define BLOB_HEAD (KS_PUBLIC_AT - 2)                        /* the blob in the first frame of an own entry: 110 bytes, then it goes on in the second */
int ks_entry_ok(int type, int flags, int n);
int ks_plain(uint8_t pt[PT_MAX], int type, int flags, const uint8_t *entropy, int elen, const char *label, int lcap);
void ks_aad(uint8_t a[9], const uint8_t *f, uint16_t id, int slot, int nf);
/* The seals for any number of frames (1 or 2: buffers of KS_ENTRY_MAX bytes), the signer only: the main card seals the entries of one frame (ks_store_entry_seal, ks_own_entry_seal
 * above), the entry of two frames (a key over 32 bytes) is sealed by the signer overlay. `slot` of a two frame entry is its even first slot. */
int ks_store_entry_seal2(uint8_t *f, const uint8_t key[32], uint16_t id, int slot, const uint8_t nonce[12], uint32_t aseq, int type, int flags, const uint8_t *entropy, int elen,
                         const char *label);
int ks_own_entry_seal2(uint8_t *f, const uint8_t *pw, size_t pwlen, uint32_t iter, const uint8_t rnd[28], int type, int flags, const uint8_t *entropy, int elen, const char *label,
                       const char *open_label);
void ks_pair_set(ks_dir *d, int head, int on);
