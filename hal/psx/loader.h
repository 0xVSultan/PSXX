#pragma once
#include <stdint.h>
#include "pkg/cardfile.h"
#include "pkg/dirscan.h"
#include "pkg/pkg.h"
#include "memmap.h"

/* The loader of the overlays: reads a package from a file on the memory card in a slot, checks it against the pin of the release record,
 * unpacks the overlay to its fixed address (ovl.ld), and calls it. The slot is a parameter (0 = slot 1, 1 = slot 2): nothing in here knows which one holds the package.
 *
 * Trust: nothing from the card is used before it is checked: the header and the table of the package against the pin (pkg_open), the overlay's group against the hash in
 * that table (pkg_read_group), and the base id of the package against the one of this image (pkg_check_base); only then is the LZMA stream decoded, and the header of
 * the overlay is checked once more before anything is copied to its place. */

#define LDR_OVL_HEADER 32

/* The overlays live in slots (memmap.h): the signer (group 1) and the language module (group 2) are in memory together, an overlay that has been loaded stays until the program is
 * restarted (ldr_forget) or the user switches it off, and loading one never touches the other. What an overlay needs while it runs - the bss of the signer, the scratch of the
 * decoders - is in pockets of the RAM that the BIOS leaves alone (memmap.h); the scratch pocket is also where the packed bytes of an overlay are staged while it is read. */
enum { LDR_GROUP_SIGNER = 1, LDR_GROUP_LANG = 2 };
enum { LDR_SLOT_SIGNER = 0, LDR_SLOT_LANG = 1, LDR_SLOTS = 2 };
#define LDR_SCRATCH_LO MM_P1_LO                      /* the scratch pocket: 133.5 KB */
#define LDR_SCRATCH_HI MM_P1_HI

enum {
    LDR_OK = 0,
    LDR_ERR_CARD = -1,                               /* the file on the card: detail is a CF_ERR_* of cardfile.h */
    LDR_ERR_PKG = -2,                                /* the package: detail is a PKG_ERR_* of pkg.h */
    LDR_ERR_BASE = -3,                               /* the overlay was made for another base image */
    LDR_ERR_GROUP = -4,                              /* no such group in the package */
    LDR_ERR_CODEC = -5,                              /* not an LZMA group with the properties the unpacker is built for */
    LDR_ERR_OVERLAY = -6,                            /* the header of the overlay is not right */
    LDR_ERR_LAYOUT = -7,                             /* the overlay and the staging area do not fit the region */
    LDR_ERR_NOPIN = -8,                              /* the release record of this image has not been filled in (tools/release.py) */
    LDR_ERR_SPACE = -9                               /* a buffer is too small for the group */
};

typedef struct {
    int      port;
    cf_file  file;
    pkg      pk;
} ldr_pkg;

typedef struct {
    uint32_t entry, load, size, bss, bss_size;
} ldr_overlay;

/* Opens the file `name` (20 characters) on the card in `port` and the package in it. kind: PKG_KIND_*; pin: the pinned hash of header and table. */
int ldr_open(ldr_pkg *p, int port, const char *name, int kind, const uint8_t pin[32], int *detail);
/* The slot of the overlay in `group_id`, or -1. */
int ldr_slot_of(uint16_t group_id);
/* The overlay that is in the slot now, or NULL: it was loaded and checked, and has not been wiped since. */
const ldr_overlay *ldr_resident(int slot);
/* Loads the overlay in group `group_id` into its slot: it is in place, its bss is cleared and the instruction cache flushed when this returns LDR_OK. The slot is wiped first; when the
 * loading fails the slot is wiped again (the other slot is not touched). */
int ldr_load_overlay(ldr_pkg *p, uint16_t group_id, const uint8_t base_id[32], ldr_overlay *ov, int *detail);
/* Reads a group completely into the scratch pocket (it has to fit there) and checks its hash: a test of the reading of long files. Touches no overlay. */
int ldr_check_group(ldr_pkg *p, uint16_t group_id, uint32_t *bytes, int *detail);
/* A group of a data package, unpacked to dst (rawlen bytes; the packed bytes are staged in `stage`, hash checked): the language card. With progress as above. */
int ldr_unpack_group(ldr_pkg *p, uint16_t group_id, uint8_t *dst, uint32_t dstcap, uint8_t *stage, uint32_t stagecap, uint32_t *rawlen, int *detail);
/* Runs the overlay (the signer): its entry point is int ovl_main(void). Its bss is cleared before - it is in the scratch pocket, which holds what the loader and the module left there -
 * and again when it returns, nothing of its working memory stays. */
int ldr_call(const ldr_overlay *ov);
/* The same for an overlay whose entry point takes arguments (the language module: render context, input state, refresh rate). Its bss is its state, it is kept between the calls. */
int ldr_call_args(const ldr_overlay *ov, void *a, void *b, int c);
/* Progress of the reading of a package: fn(user, frames read, frames expected) is called about every 8 frames of the card; a non-zero answer cancels the reading (the read then
 * fails and ldr_cancelled() is true). Set it before ldr_load_overlay, with NULL it is off. */
typedef int (*ldr_progress_fn)(void *user, uint32_t done, uint32_t total);
void ldr_set_progress(ldr_progress_fn fn, void *user);
int ldr_cancelled(void);
/* Wipes everything the loader put in the RAM: both slots, the scratch pocket and the data pocket of the language module, with the pointers into them (the language module's API and the glyph
 * hooks): a restart, or a reading that was given up. */
void ldr_forget(void);
/* The same for one slot only: that overlay is gone, the other stays. The scratch pocket is wiped too; for the language module so is its data pocket. */
void ldr_forget_slot(int slot);
/* Wipes the scratch pocket: the working memory of the signer, the decoded words of a language that was read. */
void ldr_scrub(void);
/* The header frame and the directory of the card in `port` (16 frames, each read up to three times) and what they say; LDR_OK or LDR_ERR_CARD with a CF_ERR_* in detail. */
int ldr_scan(int port, dirscan *d, int *detail);
/* one short line for the screen */
const char *ldr_describe(int code, int detail);
