#include "loader.h"
#include <stdio.h>
#include <string.h>
#include <psxapi.h>
#include "mcard.h"

#include "pkg/ovl.h"
#include "release.h"
#include "lang_api.h"
#ifdef FONT_EXT
#include "fontext.h"
#endif
#include "ui_text.h"
#include "ui_ids.h"

static uint16_t probs[OVL_PROBS];                  /* 16 KB of working memory of the unpacker */
extern const uint8_t __text_start[];               /* the image of this program (exe_hi.ld): its code and constants up to the release record are the dictionary of the overlays */

static struct { ldr_progress_fn fn; void *user; uint32_t done, total; int cancelled; } prog;

void ldr_set_progress(ldr_progress_fn fn, void *user) { prog.fn = fn; prog.user = user; prog.done = prog.total = 0; prog.cancelled = 0; }
int ldr_cancelled(void) { return prog.cancelled; }

static int frame_rd(void *ctx, int frame, uint8_t out[CF_FRAME])
{
    int port = (int) (intptr_t) ctx;

    if (prog.fn && prog.total && (++prog.done & 7) == 0 && prog.fn(prog.user, prog.done, prog.total)) { prog.cancelled = 1; return -1; }
    for (int i = 0; i < 3; i++) if (mc_read(port, frame, out) == MC_OK) return 0;      /* a failed frame is read again twice */
    return -1;
}

static int pkg_rd(void *ctx, uint32_t off, uint8_t *buf, uint32_t len) { return cf_read((cf_file *) ctx, off, buf, len); }

int ldr_open(ldr_pkg *p, int port, const char *name, int kind, const uint8_t pin[32], int *detail)
{
    int rc;

    memset(p, 0, sizeof *p);
    p->port = port;
    rc = cf_open(&p->file, frame_rd, (void *) (intptr_t) port, name);
    if (rc) { *detail = rc; return LDR_ERR_CARD; }
    rc = pkg_open(&p->pk, pkg_rd, &p->file, p->file.size, kind, pin);
    if (rc) { *detail = rc; return LDR_ERR_PKG; }
    *detail = 0;
    return LDR_OK;
}

/* the slots of memmap.h: where the image of an overlay may be, where its bss may be (0: after the image) */
static const struct { uint16_t group; uint32_t code_lo, code_hi, bss_lo, bss_hi; } SLOT[LDR_SLOTS] = {
    {LDR_GROUP_SIGNER, MM_SIG_LO, MM_SIG_HI, MM_P1_LO, MM_P1_HI},
    {LDR_GROUP_LANG, MM_LANG_LO, MM_LANG_HI, 0, 0}
};
static ldr_overlay resident[LDR_SLOTS];
static uint8_t     have[LDR_SLOTS];

int ldr_slot_of(uint16_t group_id)
{
    for (int i = 0; i < LDR_SLOTS; i++) if (SLOT[i].group == group_id) return i;
    return -1;
}

const ldr_overlay *ldr_resident(int slot) { return slot >= 0 && slot < LDR_SLOTS && have[slot] ? &resident[slot] : 0; }

int ldr_load_overlay(ldr_pkg *p, uint16_t group_id, const uint8_t base_id[32], ldr_overlay *ov, int *detail)
{
    /* the region is the memory itself, from the data pocket to the end of the slots: the addresses are real; the packed bytes are staged in the scratch pocket */
    ovl_region region = {.virt_lo = MM_P0_LO, .virt_hi = MM_LANG_HI, .mem = (uint8_t *) MM_P0_LO, .stage_lo = LDR_SCRATCH_LO, .stage_hi = LDR_SCRATCH_HI};
    ovl_info oi;
    const pkg_group *g = pkg_find(&p->pk, group_id);
    int rc, slot = ldr_slot_of(group_id);

    *detail = 0;
    if (slot < 0) return LDR_ERR_GROUP;
    region.code_lo = SLOT[slot].code_lo; region.code_hi = SLOT[slot].code_hi;
    region.bss_lo = SLOT[slot].bss_hi ? SLOT[slot].bss_lo : SLOT[slot].code_lo; region.bss_hi = SLOT[slot].bss_hi ? SLOT[slot].bss_hi : SLOT[slot].code_hi;
    region.dict = __text_start;
    region.dict_len = (uint32_t) ((const uint8_t *) &psxx_release_info - __text_start);
    ldr_forget_slot(slot);                                                       /* what was there is gone, whatever happens next */
    prog.cancelled = 0;
    prog.done = 0;
    prog.total = g ? (g->len + CF_FRAME - 1) / CF_FRAME + 1 : 0;
    rc = ovl_load(&p->pk, group_id, base_id, &region, probs, &oi, detail);
    prog.total = 0;

    if (rc) { ldr_forget_slot(slot); return rc; }                                /* the codes of ovl.h are the ones of loader.h */
    FlushCache();                                                                /* the instruction cache must not hold what was there before */
    ov->entry = oi.entry; ov->load = oi.load; ov->size = oi.size; ov->bss = oi.bss; ov->bss_size = oi.bss_size;
    resident[slot] = *ov;
    have[slot] = 1;
    return LDR_OK;
}

int ldr_check_group(ldr_pkg *p, uint16_t group_id, uint32_t *bytes, int *detail)
{
    const pkg_group *g = pkg_find(&p->pk, group_id);
    int rc;

    *detail = 0;
    if (!g) return LDR_ERR_GROUP;
    if (g->len > LDR_SCRATCH_HI - LDR_SCRATCH_LO) return LDR_ERR_LAYOUT;
    prog.cancelled = 0;
    prog.done = 0;
    prog.total = (g->len + CF_FRAME - 1) / CF_FRAME + 1;
    rc = pkg_read_group(&p->pk, g, (uint8_t *) LDR_SCRATCH_LO, g->len);
    prog.total = 0;
    *bytes = g->len;
    if (rc) { *detail = rc; return LDR_ERR_PKG; }
    return LDR_OK;
}

int ldr_unpack_group(ldr_pkg *p, uint16_t group_id, uint8_t *dst, uint32_t dstcap, uint8_t *stage, uint32_t stagecap, uint32_t *rawlen, int *detail)
{
    const pkg_group *g = pkg_find(&p->pk, group_id);
    int rc;

    prog.cancelled = 0;
    prog.done = 0;
    prog.total = g ? (g->len + CF_FRAME - 1) / CF_FRAME + 1 : 0;
    rc = ovl_unpack_group(&p->pk, group_id, dst, dstcap, stage, stagecap, probs, rawlen, detail);
    prog.total = 0;
    return rc;
}

int ldr_call_args(const ldr_overlay *ov, void *a, void *b, int c) { return ((int (*)(void *, void *, int)) ov->entry)(a, b, c); }
int ldr_call(const ldr_overlay *ov)
{
    int r;

    memset((void *) ov->bss, 0, ov->bss_size);                                  /* a bss in the scratch pocket holds what the loader and the module left there */
    r = ldr_call_args(ov, 0, 0, 0);
    memset((void *) ov->bss, 0, ov->bss_size);
    return r;
}

const char *ldr_describe(int code, int detail)
{
    switch (code) {
    case LDR_OK: return "ok";
    case LDR_ERR_CARD: return cf_strerror(detail);
    case LDR_ERR_PKG: return pkg_strerror(detail);
    case LDR_ERR_BASE: return T(TXT_PACKAGE_OF_ANOTHER_RELEASE);
    case LDR_ERR_GROUP: return T(TXT_NO_SUCH_GROUP);
    case LDR_ERR_CODEC: return T(TXT_UNSUPPORTED_PACKING);
    case LDR_ERR_OVERLAY: return T(TXT_BAD_OVERLAY_HEADER);
    case LDR_ERR_LAYOUT: return T(TXT_OVERLAY_DOES_NOT_FIT);
    case LDR_ERR_NOPIN: return T(TXT_RELEASE_RECORD_EMPTY);
    case LDR_ERR_SPACE: return T(TXT_BUFFER_TOO_SMALL);
    default: return "error";
    }
}

const lang_api *psxx_lang;                         /* the language module, while one is on (lang_api.h); its code is in the slot that ldr_forget_slot wipes */

static void wipe(uint32_t lo, uint32_t hi) { memset((void *) lo, 0, hi - lo); }

void ldr_scrub(void) { wipe(LDR_SCRATCH_LO, LDR_SCRATCH_HI); }

void ldr_forget_slot(int slot)
{
    if (slot < 0 || slot >= LDR_SLOTS) return;
    if (slot == LDR_SLOT_SIGNER) ui_range_clear(UI_R_B);                          /* its texts are in the slot that is wiped */
    if (slot == LDR_SLOT_LANG) {
        ui_range_clear(UI_R_L);
        psxx_lang = 0;                                                           /* nothing may call into what is wiped, the glyph hooks included */
        ui_ext_clear();                                                          /* the texts of the language are in the data that goes */
#ifdef FONT_EXT
        font_hook_draw = 0;
        font_hook_width = 0;
#endif
        wipe(MM_P0_LO, MM_P0_HI);                                                /* the data of the language that was on */
    }
    have[slot] = 0;
    wipe(SLOT[slot].code_lo, SLOT[slot].code_hi);
    ldr_scrub();
}

void ldr_forget(void)
{
    for (int i = 0; i < LDR_SLOTS; i++) ldr_forget_slot(i);
}

int ldr_scan(int port, dirscan *d, int *detail)
{
    static uint8_t frames[DIRSCAN_FRAMES][DIRSCAN_FRAME];

    *detail = 0;
    for (int i = 0; i < DIRSCAN_FRAMES; i++)
        if (mc_read(port, i, frames[i]) != MC_OK && mc_read(port, i, frames[i]) != MC_OK && mc_read(port, i, frames[i]) != MC_OK) { *detail = CF_ERR_READ; return LDR_ERR_CARD; }
    dirscan_run(d, frames);
    return LDR_OK;
}
