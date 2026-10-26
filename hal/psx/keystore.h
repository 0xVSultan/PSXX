#pragma once
#include <stddef.h>
#include <stdint.h>
#include "mcfile.h"
#include "keyfile.h"

/* The key stores of a memory card: finding them, reading them, and changing them. A store is one block (core/keyfile.h): two directory frames and
 * 60 slots of one entry each. A change never rewrites a live frame: the new entry goes into a free slot, then the new directory over the older of the two directory frames, both
 * read back and compared. A power failure or a card pulled out at any point leaves the old directory (a torn frame fails its CRC and is not taken), so the store is the old
 * version or the new one, never half of one, and no spare block is needed. */

#define KSD_MAX_VAULTS 4                     /* vaults on a card (the chooser of the main card has a row for each) */
#define KSD_MAX_STORES 8                     /* blocks of key stores on a card (vaults and the blocks of the single keys); a new one beyond this is refused */

enum {
    KSD_OK = 0,
    KSD_ERR_FULL = -10,                      /* no free block for a new store, or no free slot in the store */
    KSD_ERR_LIMIT = -12,                     /* more than KSD_MAX_STORES stores */
    KSD_ERR_VERIFY = -13,                    /* a frame did not read back as written */
    KSD_ERR_CHANGED = -14,                   /* the directory is not what the scan saw: the card was changed, nothing was written */
    KSD_ERR_ARG = -15,
    KSD_ERR_IMAGE = -16,                     /* the block is damaged (no directory that checks out, or the chain does not match its entries) */
    KSD_ERR_PASSWORD = -17                   /* the store key is missing or does not belong to the store */
};

typedef struct {
    int      block;                          /* 1..15 */
    int      single;                         /* a block of the single keys (no password: every key has its own), else a vault */
    uint16_t id;
    uint32_t seq;
    int      n;                              /* keys (an entry of two frames counts once) */
    int      which;                          /* the directory frame (0 or 1) that is current */
    int      next_slot;                      /* where the next entry of one frame goes (-1: all 60 slots are live) */
    uint32_t dir_crc;                        /* CRC-32 of both directory frames at the scan: a changed card shows here before anything is written */
    ks_dir   dir;                            /* the current directory */
} ksd_store;

typedef struct {
    ksd_store st[KSD_MAX_STORES];
    int       nstores;                       /* in block order */
    int       corrupt;                       /* blocks that carry the store name and have no directory that checks out (not touched; the user decides) */
    int       free_count;
    int       single_head, single_last;      /* the first and the last block of the file of the single keys (0: there is none); their blocks are in st[] as the others are */
} ksd_state;

/* Finds the stores on the card in `port`: the vaults (a file of one block each) and the blocks of the single keys (one file: its blocks follow the links of its directory entries). clean != 0: a directory entry of the card with a torn checksum is repaired. Returns MCF_OK or an MCF_* error. */
int ksd_scan(int port, ksd_state *s, int clean);
/* The 62 frames of a store (KS_DATA bytes), checked: the directory is the one the scan saw and its chain matches the live entries. */
int ksd_read(int port, const ksd_store *st, uint8_t img[KS_DATA]);
/* A new store with no key in it (seq 1; keystore_del.c: the screens make a vault together with its first key, ksd_make_block): `pw` carries flags KS_DIR_PW, iter, salt and check of a store password with its `key` (both NULL for a store without one), `id_hint`
 * becomes its id unless it is taken. `work` is KS_DATA bytes of scratch. *store is its index in s. */
int ksd_create(int port, ksd_state *s, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id_hint, uint8_t work[KS_DATA], int *store);
/* A free id for a block of this card (the hint, or the next one that is not taken; never 0). */
uint16_t ksd_free_id(const ksd_state *s, uint16_t hint);
/* A new block of key store with this first entry (nf frames, sealed for `id` and slot 0, the directory is seq 1 and makes it live; entry NULL: an empty one): single 0 a vault (label, pw and
 * key as for ksd_create), single 1 a block of the single keys; the id is the caller's (ksd_free_id). The block is written whole, the last write makes it seen (or linked). */
int ksd_make_block(int port, ksd_state *s, int single, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id, const uint8_t *entry, int nf, uint8_t work[KS_DATA], int *store);
/* A new block for the single keys with this entry (nf frames, 1 or 2: sealed for its own password, which does not depend on the place) in its slot 0: the first block of the file, or the next one,
 * linked to the last. The block is written whole before it can be seen (the file, or the link, is the last write). *store is its index in s. KSD_ERR_FULL: no free block. */
int ksd_new_single(int port, ksd_state *s, const uint8_t *entry, int nf, uint16_t id_hint, uint8_t work[KS_DATA], int *store);
/* The title that the BIOS card manager shows for the file of the single keys: "PSXX key store S" and the number of keys; written again after a key is added or deleted. */
int ksd_single_title(int port, const ksd_state *s);
/* Deletes the whole file of the single keys (every block of it). */
int ksd_remove_singles(int port, ksd_state *s);
/* Adds the entry frame (it was sealed for st->next_slot and the seq st->seq + 1). A store with a password needs its key. `work` is KS_DATA bytes of scratch. s is brought up to date. */
int ksd_add(int port, ksd_state *s, int store, const uint8_t entry[KS_FRAME], const uint8_t key[32], uint8_t work[KS_DATA]);
/* Deletes a whole store (a store whose last key is removed does not stay as an empty block): its directory entry is freed, one frame write. KSD_ERR_CHANGED when the
 * entry is not what the scan saw. s is brought up to date. */
int ksd_remove_store(int port, ksd_state *s, int store);
/* Deletes the marked keys (keystore_del.c, in the signer overlay): marks[store][n] != 0 for the n-th live key of a store, from the last store to the first. A store with every key marked is removed whole, from any other
 * the keys go one directory write each (the older directory frame is overwritten last, as for ksd_del). A store with a password that loses only some of its keys needs its key:
 * `key` belongs to the store `key_store`; for another store it returns KSD_ERR_PASSWORD with *need_store set, nothing of that store is touched, and the call can be repeated with the key
 * (the stores before it are done and their marks cleared). *deleted counts the keys that went. Returns KSD_OK or the error of the first write that failed. */
int ksd_del_marked(int port, ksd_state *s, uint8_t (*marks)[KS_SLOTS], int key_store, const uint8_t key[32], uint8_t work[KS_DATA], int *deleted, int *need_store);

/* For the signer overlay (keystore_del.c); the main card only adds entries of one frame. */
/* The two directory frames of a block (the current directory, its index and the CRC of both), one frame written and read back, a store brought up to date. */
int ksd_read_dir(int port, int block, ks_dir *d, int *which, uint32_t *crc);
int ksd_put_frame(int port, int block, int frame, const uint8_t *data);
void ksd_fill_store(ksd_store *o, int block, const ks_dir *d, int which, uint32_t crc);
/* a new block of the file of the single keys (written before this call, not yet seen): its directory entry, the link from the last block, the size in the first (the order keeps the card
 * readable if the power fails between the writes); s is not changed */
int ksd_link_block(int port, const ksd_state *s, int block);
/* a store of the card known to s (in block order); single: a block of the single keys. Returns its index. */
int ksd_add_store(ksd_state *s, int block, const ks_dir *d, int which, uint32_t crc, int single);
/* Adds the entry (one frame, or two one after the other: ks_frames_of_entry says; sealed for st->next_slot, or for ks_next_pair of the directory, and the seq st->seq + 1) and, if
 * replace_slot >= 0, makes that slot (the first one of an entry of two) free in the same directory write. A store with a password needs its key. */
int ksd_add2(int port, ksd_state *s, int store, const uint8_t *entry, int replace_slot, const uint8_t key[32], uint8_t work[KS_DATA]);
/* Makes a slot free, or the two slots of an entry of two frames, given its first (one directory write; the frames themselves stay where they are, encrypted). */
int ksd_del2(int port, ksd_state *s, int store, int slot, const uint8_t key[32], uint8_t work[KS_DATA]);
