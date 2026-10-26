#include "source_ui.h"
#include "log.h"
#include <stdio.h>
#include "ui.h"
#include <string.h>
#include <psxgpu.h>
#include "font.h"

#define GLYPH_BUDGET 360                      /* characters per frame: the 8 KB primitive buffer holds about 390 glyphs */
#define POLL_MS 250                           /* the poll interval of the screen */
#define AUTO_FRAMES(hz) ((hz) * 2 / 5)        /* a package that has been there this long (and the one slot that has it) is loaded without a button */

static int budget;

static void line(su *s, int row, const char *t0, int r, int g, int b)
{
    char t[56];
    int n = (int) strlen(t0);

    if (n > 54) n = 54;
    if (n > budget) n = budget > 0 ? budget : 0;
    memcpy(t, t0, (size_t) n);
    t[n] = 0;
    budget -= n;
    if (n) font_draw(s->ctx, 0, 8, 6 + row * 22, t, r, g, b);
}

void su_init(su *s, RenderContext *ctx, input_state *in, int hz, const char *title, const char *package_name, int kind, const uint8_t pin[32], const uint8_t base_id[32], uint16_t group)
{
    memset(s, 0, sizeof *s);
    s->ctx = ctx;
    s->in = in;
    s->hz = hz;
    s->title = title;
    s->name = package_name;
    s->kind = kind;
    s->pin = pin;
    s->base_id = base_id;
    s->group = group;
    cw_init(&s->cw, hz, package_name, kind, pin);
}

void su_enter(su *s, int frame)
{
    s->phase = SU_SELECT;
    s->note[0] = 0;
    s->found = 0;
    cw_begin(&s->cw, frame, POLL_MS);
}

/* the slot to load from, or -1: Auto takes the only package there is */
static int resolve(const su *s)
{
    if (s->src) return cw_ok(&s->cw, s->src - 1) ? s->src - 1 : -1;
    if (cw_ok(&s->cw, 0) && !cw_ok(&s->cw, 1)) return 0;
    if (!cw_ok(&s->cw, 0) && cw_ok(&s->cw, 1)) return 1;
    return -1;
}

static void fail(su *s, int code, int detail)
{
    LOG("[ldr] not loaded: %s\n", code == SU_ERR_CHANGED ? "the card changed while reading" : code == SU_ERR_CANCELLED ? "cancelled" : ldr_describe(code, detail));
    s->phase = SU_ERROR;
    s->err_code = code;
    s->err_detail = detail;
}

static void draw_reading(su *s)
{
    char t[64];

    budget = GLYPH_BUDGET;
    line(s, 0, s->title, 255, 255, 255);
    line(s, 1, s->what, 150, 200, 255);
    gpu_draw_rect(s->ctx, 8, 8, 76, 300, 14, 60, 60, 70);                 /* in the band of line 3 */
    gpu_draw_rect(s->ctx, 7, 8, 76, s->pct * 3, 14, 80, 220, 90);
    snprintf(t, sizeof t, T(TXT_N_DO_NOT_TAKE_THE_CARD_OUT), s->pct);
    line(s, 4, t, 255, 220, 120);
    line(s, 7, T(TXT_HINT_CANCEL), 150, 160, 200);
}

static int progress(void *user, uint32_t done, uint32_t total)
{
    su *s = user;

    s->pct = s->ptot ? (int) ((s->pbase + done) * 100u / s->ptot) : total ? (int) (done * 100u / total) : 0;
    if (s->pct > 100) s->pct = 100;
    draw_reading(s);
    gpu_present(s->ctx);
    input_poll(s->in, NULL);
    return (input_take_pressed(s->in) & PAD_CIRCLE) != 0;
}

/* the frames the loader reads for a group (ldr_load_overlay) */
static uint32_t frames_of(const su *s, uint16_t gid)
{
    const pkg_group *g = pkg_find(&s->pk.pk, gid);

    return g ? (g->len + CF_FRAME - 1) / CF_FRAME + 1 : 0;
}

/* the reading itself: the card must be the one that was looked at, before and after. An overlay package gives both its groups (the signer and the language module) in one reading, the ones
 * that are not in memory yet; a failure leaves nothing of this reading in memory. */
static int read_package(su *s, int port)
{
    dirscan d;
    int detail = 0, scan_detail = 0, rc = 0, loaded = 0;
    uint16_t gs[2];
    uint32_t fp0;

    s->port = port;
    s->pct = 0;
    snprintf(s->what, sizeof s->what, T(TXT_READING_THE_PACKAGE_FROM_SLOT), port + 1);
    LOG("[ldr] reading the package from slot %d\n", port + 1);
    rc = ldr_scan(port, &d, &detail);
    if (rc) { fail(s, rc, detail); return SU_RUNNING; }
    fp0 = d.fingerprint;
    if (!cw_ok(&s->cw, port) || fp0 != s->cw.s[port].fp) { fail(s, SU_ERR_CHANGED, 0); return SU_RUNNING; }
    rc = ldr_open(&s->pk, port, s->name, s->kind, s->pin, &detail);
    if (rc) { fail(s, rc, detail); return SU_RUNNING; }

    if (s->kind == PKG_KIND_DATA) {                                      /* a data card: the table is checked against the pin, the groups are read later as they are needed */
        if (ldr_scan(port, &d, &scan_detail) || d.fingerprint != fp0) { fail(s, SU_ERR_CHANGED, 0); return SU_RUNNING; }
        return SU_LOADED;
    }
    gs[0] = s->group;
    gs[1] = s->group2;
    s->pbase = s->ptot = 0;
    for (int i = 0; i < 2; i++) if (gs[i] && !ldr_resident(ldr_slot_of(gs[i]))) s->ptot += frames_of(s, gs[i]);
    ldr_set_progress(progress, s);
    for (int i = 0; i < 2 && !rc; i++) {
        ldr_overlay ov;

        if (!gs[i] || ldr_resident(ldr_slot_of(gs[i]))) continue;
        rc = ldr_load_overlay(&s->pk, gs[i], s->base_id, &ov, &detail);
        if (!rc) { if (!loaded) s->ov = ov; loaded |= 1 << i; s->pbase += frames_of(s, gs[i]); }
    }
    ldr_set_progress(NULL, NULL);
    if (!rc && (ldr_scan(port, &d, &scan_detail) || d.fingerprint != fp0)) { rc = SU_ERR_CHANGED; detail = 0; }      /* the card is not the one that was read from */
    if (rc) {
        int cancelled = ldr_cancelled();

        for (int i = 0; i < 2; i++) if (loaded & (1 << i)) ldr_forget_slot(ldr_slot_of(gs[i]));        /* what was read stays nowhere (the loader has wiped the slot that failed) */
        if (cancelled) { fail(s, SU_ERR_CANCELLED, 0); return SU_RUNNING; }
        if (rc == SU_ERR_CHANGED) fail(s, rc, 0);
        else if (ldr_scan(port, &d, &scan_detail) || d.fingerprint != fp0) fail(s, SU_ERR_CHANGED, 0);      /* not `detail`: the scan sets it, and it holds the reason of the error here */
        else fail(s, rc, detail);
        return SU_RUNNING;
    }
    LOG("[ldr] loaded %u bytes at %08x, bss %u bytes at %08x\n", (unsigned) s->ov.size, (unsigned) s->ov.load, (unsigned) s->ov.bss_size, (unsigned) s->ov.bss);
    return SU_LOADED;
}

int su_update(su *s, uint16_t pressed, int frame)
{
    int target;

    s->frame = frame;
    if (s->phase == SU_ERROR) {
        if (pressed & PAD_CIRCLE) return SU_CANCEL;
        if (pressed & PAD_CROSS) su_enter(s, frame);
        return SU_RUNNING;
    }
    cw_tick(&s->cw, frame);
    if (pressed & PAD_CIRCLE) return SU_CANCEL;
    target = resolve(s);
    s->note[0] = 0;
    if (!s->src && cw_ok(&s->cw, 0) && cw_ok(&s->cw, 1)) snprintf(s->note, sizeof s->note, T(TXT_TWO_N_CARDS_FOUND_TAKE_ONE_OUT), s->kind == PKG_KIND_DATA ? "C" : "B");
    if (target < 0) s->found = 0;
    else if (!s->found) s->found = frame + 1;
    if (target >= 0 && ((pressed & PAD_CROSS) || frame + 1 - s->found >= AUTO_FRAMES(s->hz))) return read_package(s, target);
    return SU_RUNNING;
}

void su_slot_text(const su *s, int port, char *buf, int n)
{
    cw_text(&s->cw, port, buf, (size_t) n);                                   /* (for the demo of the loader: the screens do not show it) */
}

static const char *explain(int code, int detail)
{
    if (code == SU_ERR_CHANGED) return T(TXT_THE_CARD_CHANGED_OR_WAS_TAKEN);
    if (code == SU_ERR_CANCELLED) return T(TXT_CANCELLED_NOTHING_WAS_KEPT);
    if (code == LDR_ERR_BASE || (code == LDR_ERR_PKG && detail == PKG_ERR_PIN)) return T(TXT_VERSION_MISMATCH_THE_PACKAGE);
    if (code == LDR_ERR_PKG && detail == PKG_ERR_HASH) return T(TXT_THE_PACKAGE_ON_THE_CARD_IS);
    if (code == LDR_ERR_CARD && detail == CF_ERR_NOTFOUND) return T(TXT_PUT_THE_CARD_WITH_THE_PACKAGE);
    return "";
}

/* what is wrong with the cards, in one sentence for a person: the first slot (of the source) with a card that is not the one that is wanted; NULL if there is none. The card of the main
 * program (a FreePSXBoot card) is the usual one in slot 1 and is not mentioned. */
static const char *problem(const su *s, char *t, size_t n)
{
    const char *k = s->kind == PKG_KIND_DATA ? "C" : "B";

    for (int p = 0; p < 2; p++) {
        const cw_slot *c = &s->cw.s[p];

        if ((s->src && s->src - 1 != p) || !c->have) continue;
        switch (c->state) {
        case CW_UNFORMATTED: return T(TXT_CARD_NOT_FORMATTED);
        case CW_NO_PACKAGE: snprintf(t, n, T(TXT_THAT_CARD_IS_NOT_THE_N_CARD), k); return t;
        case CW_READ_ERROR: return T(TXT_CARD_NOT_READABLE);
        case CW_PKG_BAD:
            if (c->code == LDR_ERR_BASE || (c->code == LDR_ERR_PKG && c->detail == PKG_ERR_PIN)) { snprintf(t, n, T(TXT_THAT_N_CARD_BELONGS_TO_ANOTHER_VERSION), k); return t; }
            return ldr_describe(c->code, c->detail);
        default: break;
        }
    }
    return NULL;
}

/* what a person sees: the title, one sentence, the buttons */
static void draw_simple(su *s, int target)
{
    char t[64];
    const char *p = target < 0 ? problem(s, t, sizeof t) : NULL;

    line(s, 0, s->title, 255, 255, 255);
    if (target >= 0) {
        snprintf(t, sizeof t, T(TXT_N_CARD_FOUND_IN_SLOT_N), s->kind == PKG_KIND_DATA ? "C" : "B", target + 1);
        line(s, 2, t, 120, 255, 120);
    } else if (s->note[0]) line(s, 2, s->note, 255, 220, 120);
    else if (p) {
        line(s, 2, p, 255, 160, 80);
        snprintf(t, sizeof t, T(TXT_PUT_THE_N_CARD_IN_N_TO), s->kind == PKG_KIND_DATA ? "C" : "B", T(TXT_A_SLOT));
        line(s, 3, t, 255, 220, 120);
    } else {                                                            /* no slot has it, whatever card is there: which card to put in */
        snprintf(t, sizeof t, T(TXT_PUT_THE_N_CARD_IN_N_TO), s->kind == PKG_KIND_DATA ? "C" : "B", T(TXT_A_SLOT));
        line(s, 2, t, 255, 220, 120);
    }
    line(s, 9, target >= 0 ? T(TXT_HINT_LOAD_CANCEL) : T(TXT_HINT_CANCEL), 150, 160, 200);
}

void su_draw(su *s)
{
    budget = GLYPH_BUDGET;
    if (s->phase == SU_ERROR) {
        const char *e = explain(s->err_code, s->err_detail);

        line(s, 0, s->title, 255, 255, 255);
        line(s, 1, T(TXT_NOT_LOADED), 255, 120, 120);
        line(s, 2, *e ? e : ldr_describe(s->err_code, s->err_detail), 255, 220, 120);
        line(s, 9, T(TXT_HINT_TRY_AGAIN_CANCEL), 150, 160, 200);
    } else draw_simple(s, resolve(s));
}

int su_verify_all(su *s)
{
    dirscan d;
    int detail = 0, scan_detail = 0, rc;
    uint32_t fp0;

    rc = ldr_scan(s->port, &d, &detail);
    if (rc) { fail(s, rc, detail); return SU_RUNNING; }
    fp0 = d.fingerprint;
    for (unsigned k = 0; k < s->pk.pk.ngroups; k++) {
        uint32_t bytes = 0;

        snprintf(s->what, sizeof s->what, T(TXT_GROUP_N_OF_N_BYTES_SLOT_N), k + 1, s->pk.pk.ngroups, (unsigned) s->pk.pk.g[k].len, s->port + 1);
        s->pct = 0;
        ldr_set_progress(progress, s);
        rc = ldr_check_group(&s->pk, s->pk.pk.g[k].id, &bytes, &detail);
        ldr_set_progress(NULL, NULL);
        if (rc) {
            int cancelled = ldr_cancelled();

            ldr_scrub();
            if (cancelled) fail(s, SU_ERR_CANCELLED, 0);
            else if (ldr_scan(s->port, &d, &scan_detail) || d.fingerprint != fp0) fail(s, SU_ERR_CHANGED, 0);
            else fail(s, rc, detail);
            return SU_RUNNING;
        }
        LOG("[ldr] group %u ok (%u bytes)\n", s->pk.pk.g[k].id, (unsigned) bytes);
    }
    ldr_scrub();
    if (ldr_scan(s->port, &d, &scan_detail) || d.fingerprint != fp0) { fail(s, SU_ERR_CHANGED, 0); return SU_RUNNING; }
    return SU_LOADED;
}

const ldr_overlay *su_overlay(const su *s) { return &s->ov; }
ldr_pkg *su_package(su *s) { return &s->pk; }
