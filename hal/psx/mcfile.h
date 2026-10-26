#pragma once
#include <stdint.h>
#include "mcard.h"

/* Save files on a formatted memory card (one block = 8 KB each), on top of mcard.[ch].
 *
 * A file is made in four steps so that it only shows up in the directory once all of it is there:
 *   mcf_scan()   find a free block and the next number for a name tag;
 *   mcf_begin()  write the file header (title, icon) into that block;
 *   mcf_write()  write the data frames (frame 2 .. 63 of the block, 128 bytes each);
 *   mcf_commit() write the directory entry.
 * Names are 20 characters: "BESCES-00000" + a 6 character tag + two digits ("PSXXCD01"). */

#define MCF_KEY_TAG "PSXXKM"                       /* the vaults: key stores with a password, one block each */
#define MCF_SKEY_TAG "PSXXKS"                      /* the single keys: one file of one or more blocks, linked as the blocks of a long save are (keystore.c) */

enum { MCF_OK = 0, MCF_NO_CARD = -1, MCF_BAD_CARD = -2, MCF_FULL = -3, MCF_IO = -4, MCF_NOT_FOUND = -5 };
enum { MCF_ICON_DISC = 0, MCF_ICON_LOCK = 1 };

#define MCF_FIRST_DATA 2                           /* first data frame inside the block */
#define MCF_NAME 21

typedef struct {
	int  block;                                    /* 1..15 */
	char name[MCF_NAME];
} mcf_entry;

/* Look at the directory of the card in `port` (1 = slot 2). Files whose name carries `tag` (6 characters) are listed in
 * `out` (at most `max`, in block order) and counted in *nfiles; *next is the next free two digit number for that tag
 * (1..99), *free_block the first free block or 0. Returns MCF_OK or an error (NO_CARD, BAD_CARD for an unformatted
 * card, IO). */
int mcf_scan(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block);
/* The same with the number of free blocks and of key store files. (A key store is changed inside its own block, so no block is kept in reserve for it.) */
int mcf_scan_raw(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block, int *free_count, int *nkeys);
/* Deletes a file: the entries of its blocks are marked free, the first one first (one frame write makes the file disappear from the directory; the rest is tidying).
 * MCF_NOT_FOUND if `block` is not the first block of a file. */
int mcf_invalidate(int port, int block);
int mcf_begin(int port, int block, const char *title, int icon);
/* frame: 2..63; `data` is MC_FRAME bytes. */
int mcf_write(int port, int block, int frame, const uint8_t *data);
int mcf_read(int port, int block, int frame, uint8_t *data);
int mcf_commit(int port, int block, const char *tag, int number);
/* "BESCES-00000" + tag + 2 digits */
void mcf_name(char out[MCF_NAME], const char *tag, int number);
