#pragma once
#include <stdint.h>
#include "pkg/pkg.h"

/* Loading of an overlay out of a package: the group is read and its hash checked, the LZMA stream is decoded to the
 * address the header of the overlay names, the bss is cleared. Nothing in here is specific to the PSX: the region is given as a range of addresses (virtual, as the
 * overlay was linked) and the memory that stands for it, so the host tests run the same code on a buffer. After a successful load the caller flushes the instruction cache.
 *
 * Order of the checks: the base id of the package, the group, its codec, then the hash of the group (the card is read once, the bytes are the ones of the verified table),
 * then the header of the overlay in the first 32 unpacked bytes, and only then the whole image is unpacked to its place. The packed bytes are staged at the end of the
 * region, the unpacked image has to end below them. */

#define OVL_HEADER 32
#define OVL_PROBS 14135u                 /* working memory of the unpacker, entries of 16 bits (lc + lp <= 4: the properties of every group are its own) */

enum {
    OVL_OK = 0,
    OVL_ERR_PKG = -2,                    /* reading the group: detail is a PKG_ERR_* */
    OVL_ERR_BASE = -3,                   /* the overlay was made for another base image */
    OVL_ERR_GROUP = -4,                  /* no such group */
    OVL_ERR_CODEC = -5,                  /* not LZMA, lc + lp above 4 or pb above 4, no dictionary for LZMA_BASE (or one of the wrong length), or a broken stream */
    OVL_ERR_OVERLAY = -6,                /* the header of the overlay is not right */
    OVL_ERR_LAYOUT = -7,                 /* the overlay and the staging area do not fit the region */
    OVL_ERR_SPACE = -9                   /* a buffer is too small for the group */
};

/* Without the ranges below (all zero) the whole region is one slot: the image, the bss and the staged bytes all live in it, the staged bytes at its end. With them (hal/psx/memmap.h)
 * the region is the span of memory the loader may reach, and the three ranges are where each part of the overlay may be: the image in its slot, the bss in its slot or in a pocket, the
 * packed bytes at the end of a scratch range of their own. Nothing is written outside the ranges. The image may not overlap the staged bytes or the bss; the bss may overlap
 * the staged bytes (it is cleared after the unpacking). */
typedef struct {
    uint32_t virt_lo, virt_hi;           /* the addresses of the region as the overlay was linked */
    uint8_t *mem;                        /* the memory that holds the bytes of [virt_lo, virt_hi) */
    uint32_t code_lo, code_hi;           /* where the image may be (0, 0: the region) */
    uint32_t bss_lo, bss_hi;             /* where the bss may be (0, 0: the region) */
    uint32_t stage_lo, stage_hi;         /* where the packed bytes are staged, at the end (0, 0: the region) */
    const uint8_t *dict;                 /* the image of the base, the preset dictionary of a group packed with PKG_CODEC_LZMA_BASE (the code and the constants up to the release */
    uint32_t dict_len;                   /* record, tools/release.py); a multiple of 1 << max(lp, pb) of the group; 0: such a group is refused */
} ovl_region;

typedef struct {
    uint32_t entry, load, size, bss, bss_size;
} ovl_info;

int ovl_load(const pkg *p, uint16_t group_id, const uint8_t base_id[32], const ovl_region *r, uint16_t *probs, ovl_info *ov, int *detail);

/* A group of a data package (the language card), unpacked: the stored bytes are staged in `stage` (the group's len bytes, hash checked), the result is written to dst (its
 * rawlen bytes, *rawlen says how many). Stored groups go to dst directly and need no stage. probs: OVL_PROBS entries. Returns OVL_OK or an OVL_ERR_ (detail: a PKG_ERR_). */
int ovl_unpack_group(const pkg *p, uint16_t group_id, uint8_t *dst, uint32_t dstcap, uint8_t *stage, uint32_t stagecap, uint16_t *probs, uint32_t *rawlen, int *detail);
