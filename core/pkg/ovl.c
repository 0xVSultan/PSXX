#include "ovl.h"
#include <string.h>

/* every group has its own lc, lp, pb (the properties byte (pb * 5 + lp) * 9 + lc in its flags; tools/pkg_pack.py picks the best for a data group), and the overlays
 * are packed against the image of the base (PKG_CODEC_LZMA_BASE) */
#define LZMA_DICT
#include "../../tools/stub/lzma_unpack.h"

_Static_assert(LZMA_PROBS_MAX == OVL_PROBS, "OVL_PROBS is the size of the probability array for lc + lp = 4");

#ifdef PSXX_EXT_DEC
/* A release build of the main card has no decoder of its own: the unpacking stub of the boot card leaves one in its pocket (memmap.h, tools/stub/lzdec.c). If the tag that the stub
 * wrote after it is not there, the pocket was written over, and the group is refused instead of running whatever is there. */
#include "memmap.h"
typedef int (*lz_decode_fn)(const uint8_t *, uint8_t *, uint32_t, uint16_t *, unsigned, const uint8_t *, uint32_t);
static int lz_ext(const uint8_t *src, uint8_t *dst, uint32_t n, uint16_t *probs, unsigned props, const uint8_t *dict, uint32_t dict_len)
{
    if (*(volatile uint32_t *) MM_DEC_TAG != MM_DEC_MAGIC) return 1;
    return ((lz_decode_fn) MM_DEC_LO)(src, dst, n, probs, props, dict, dict_len);
}
#define lzma_unpack lz_ext
#endif

/* the properties of a group, if the unpacker takes them (lc + lp <= 4, pb <= 4); 1 << max(lp, pb) in *align */
static int props_ok(unsigned props, uint32_t *align)
{
    unsigned lc = props % 9, lp = props / 9 % 5, pb = props / 45;
    if (props > 224 || lc + lp > 4 || pb > 4) return 0;
    *align = 1u << (lp > pb ? lp : pb);
    return 1;
}

static uint32_t le32(const uint8_t *p) { return p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24); }

int ovl_load(const pkg *p, uint16_t group_id, const uint8_t base_id[32], const ovl_region *r, uint16_t *probs, ovl_info *ov, int *detail)
{
    const pkg_group *g;
    uint8_t h[OVL_HEADER], *stage;
    uint32_t entry, load, size, bss, bss_size, stage_virt, stage_end;
    uint32_t cl = r->code_hi ? r->code_lo : r->virt_lo, ch = r->code_hi ? r->code_hi : r->virt_hi;
    uint32_t bl = r->bss_hi ? r->bss_lo : r->virt_lo, bh = r->bss_hi ? r->bss_hi : r->virt_hi;
    uint32_t sl = r->stage_hi ? r->stage_lo : r->virt_lo, sh = r->stage_hi ? r->stage_hi : r->virt_hi;
    const uint8_t *dict = 0;
    uint32_t dict_len = 0, align, props;
    int rc;

    *detail = 0;
    if (pkg_check_base(p, base_id)) { *detail = PKG_ERR_BASE; return OVL_ERR_BASE; }
    g = pkg_find(p, group_id);
    if (!g) return OVL_ERR_GROUP;
    props = PKG_PROPS(g->flags);
    if (!props_ok(props, &align)) return OVL_ERR_CODEC;
    if (PKG_CODEC(g->flags) == PKG_CODEC_LZMA_BASE) {
        if (!r->dict || !r->dict_len || (r->dict_len & (align - 1))) return OVL_ERR_CODEC;
        dict = r->dict; dict_len = r->dict_len;
    } else if (PKG_CODEC(g->flags) != PKG_CODEC_LZMA) return OVL_ERR_CODEC;
    if (g->rawlen < OVL_HEADER) return OVL_ERR_OVERLAY;
    if (r->virt_hi <= r->virt_lo || cl < r->virt_lo || ch > r->virt_hi || cl >= ch || bl < r->virt_lo || bh > r->virt_hi || bl >= bh || sl < r->virt_lo || sh > r->virt_hi || sl >= sh) return OVL_ERR_LAYOUT;
    if (g->len > sh - sl - OVL_HEADER) return OVL_ERR_LAYOUT;
    stage_virt = sh - ((g->len + 15) & ~15u);                                    /* the packed bytes go to the end of the staging range */
    stage_end = sh;
    stage = r->mem + (stage_virt - r->virt_lo);
    rc = pkg_read_group(p, g, stage, g->len);
    if (rc) { *detail = rc; return OVL_ERR_PKG; }                                /* from here on the bytes are the ones of the verified table */

    if (lzma_unpack(stage, h, OVL_HEADER, probs, props, dict, dict_len)) return OVL_ERR_CODEC;     /* only the header, to see where the rest goes */
    if (memcmp(h, "PSXO", 4) || le32(h + 4) != 1 || le32(h + 28) != 0) return OVL_ERR_OVERLAY;
    entry = le32(h + 8); load = le32(h + 12); size = le32(h + 16); bss = le32(h + 20); bss_size = le32(h + 24);
    if (size != g->rawlen || load < cl || load >= ch || (load & 3) || size > ch - load) return OVL_ERR_LAYOUT;
    if (load < stage_end && load + size > stage_virt) return OVL_ERR_LAYOUT;     /* the image stays clear of the staged bytes */
    if (entry < load + OVL_HEADER || entry >= load + size || (entry & 3)) return OVL_ERR_OVERLAY;
    if (bss < bl || (bss & 3) || bss > bh || bss_size > bh - bss) return OVL_ERR_OVERLAY;
    if (bss >= cl && bss < ch && bss < load + size) return OVL_ERR_OVERLAY;     /* in the slot of the image the bss follows it */
    if (bss_size && bss < load + size && bss + bss_size > load) return OVL_ERR_OVERLAY;

    if (lzma_unpack(stage, r->mem + (load - r->virt_lo), size, probs, props, dict, dict_len)) return OVL_ERR_CODEC;
    memset(r->mem + (bss - r->virt_lo), 0, bss_size);
    ov->entry = entry; ov->load = load; ov->size = size; ov->bss = bss; ov->bss_size = bss_size;
    return OVL_OK;
}

int ovl_unpack_group(const pkg *p, uint16_t group_id, uint8_t *dst, uint32_t dstcap, uint8_t *stage, uint32_t stagecap, uint16_t *probs, uint32_t *rawlen, int *detail)
{
    const pkg_group *g = pkg_find(p, group_id);
    int rc;

    *detail = 0;
    if (!g) return OVL_ERR_GROUP;
    if (g->rawlen > dstcap) return OVL_ERR_SPACE;
    if (PKG_CODEC(g->flags) == PKG_CODEC_STORED) {
        rc = pkg_read_group(p, g, dst, dstcap);
        if (rc) { *detail = rc; return OVL_ERR_PKG; }
    } else {
        uint32_t align;
        if (PKG_CODEC(g->flags) != PKG_CODEC_LZMA || !props_ok(PKG_PROPS(g->flags), &align)) return OVL_ERR_CODEC;
        if (g->len > stagecap) return OVL_ERR_SPACE;
        rc = pkg_read_group(p, g, stage, stagecap);
        if (rc) { *detail = rc; return OVL_ERR_PKG; }
        if (lzma_unpack(stage, dst, g->rawlen, probs, PKG_PROPS(g->flags), 0, 0)) return OVL_ERR_CODEC;
    }
    *rawlen = g->rawlen;
    return OVL_OK;
}
