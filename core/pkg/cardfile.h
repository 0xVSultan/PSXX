#pragma once
#include <stdint.h>

/* Files of several blocks on a PlayStation memory card, read-only, on top of a frame reader (tools/mkcard.py is the reference writer and describes the format).
 * A file is found by its 20 character name; its blocks are followed through the directory (state 0x51 first, 0x52 middle, 0x53 last, the next block as a 16 bit
 * number), and its data is read at any byte offset: the data of the first block starts after the header and icon frames, the other blocks are data throughout.
 * The directory is checked (header frame, the xor of the entries that are used, the chain: no loop, no block twice, at most 15 blocks, the size of the first entry).
 * The reader is a callback, so the same code runs on the polled card driver of the app and on a memory card image in the tests. */

#define CF_FRAME 128
#define CF_MAX_BLOCKS 15

enum {
    CF_OK = 0,
    CF_ERR_READ = -1,                 /* the frame reader failed (no card, bad checksum) */
    CF_ERR_FORMAT = -2,               /* not a formatted card */
    CF_ERR_NOTFOUND = -3,
    CF_ERR_CHAIN = -4,                /* a directory entry or the chain of blocks is damaged */
    CF_ERR_HEADER = -5,               /* the header frame of the file is not a save file header */
    CF_ERR_RANGE = -6                 /* a read beyond the end of the file */
};

/* read frame `frame` (0..1023) of the card into out[128]; 0 on success */
typedef int (*cf_frame_fn)(void *ctx, int frame, uint8_t out[CF_FRAME]);

typedef struct {
    cf_frame_fn rd;
    void       *ctx;
    uint8_t     nblocks;
    uint8_t     blocks[CF_MAX_BLOCKS];   /* in the order of the chain, block numbers 1..15 */
    uint8_t     start;                   /* the first data frame of the first block (2 with one icon frame) */
    uint32_t    size;                    /* bytes of data in the file */
    int         cached;                  /* the frame in buf, or -1 */
    uint8_t     buf[CF_FRAME];
} cf_file;

int cf_open(cf_file *f, cf_frame_fn rd, void *ctx, const char *name);
int cf_read(cf_file *f, uint32_t off, uint8_t *buf, uint32_t len);
const char *cf_strerror(int rc);
