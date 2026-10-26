/* The base image of the demonstration: the main screen shows both slots as the watch last saw them, and X opens the screens that choose the
 * source of the overlay package (Auto, slot 1, slot 2), wait for a package, read it with a progress bar and load it. The overlay (ovl_demo.c) is then run; it calls printf and
 * sha256 of this image (kept in the link with -Wl,-u, the export list of the CMake target). The release record (pin and base id) is filled in by tools/release.py. TTY: [cw], [ldr], [ovl].
 *
 *   main screen:  X choose the source and load      TRIANGLE look at both slots again      SQUARE read every group of the last package (long files)      START forget the overlay */
#include <stdio.h>
#include <string.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include "mcard.h"
#include "loader.h"
#include "release.h"
#include "source_ui.h"
#include "ui_text.h"
#include "ui_ids.h"
#include "hash/sha256.h"

#ifndef BASE_VARIANT
#define BASE_VARIANT 0
#endif

#define PKG_NAME "BESCES-00000PSXXPK01"
#define OVL_GROUP 1
#define GLYPH_BUDGET 360                              /* characters per frame: the 8 KB primitive buffer holds about 390 glyphs (see cardprobe.c) */

static RenderContext ctx;
static input_state   in;
static su            ui;
static int           hz, screen;                      /* 0 main, 1 the source screens */
static int           loaded, have_pkg;
static char          msg[3][48];
static int           budget;

static int ms_since(int f0) { return (VSync(-1) - f0) * 1000 / hz; }

static int pinned(void)
{
    for (int i = 0; i < 32; i++) if (psxx_release_info.key[i] || psxx_release_info.base_id[i]) return 1;
    return 0;
}

static void say(int i, const char *t)
{
    snprintf(msg[i], sizeof msg[i], "%s", t);
    printf("[ldr] %s\n", msg[i]);
}

static void do_groups(void)
{
    msg[2][0] = 0;
    if (!have_pkg) { say(2, "no package read yet"); return; }
    loaded = 0;                                                  /* the overlay region is the buffer */
    if (su_verify_all(&ui) == SU_LOADED) say(2, "every group of the package checked: all ok");
    else screen = 1;                                             /* the error screen of the source screens says what went wrong */
}

static void line(int row, const char *s, int r, int g, int b)
{
    char t[56];
    int n = (int) strlen(s);

    if (n > 54) n = 54;
    if (n > budget) n = budget > 0 ? budget : 0;
    memcpy(t, s, (size_t) n);
    t[n] = 0;
    budget -= n;
    if (n) font_draw(&ctx, 0, 8, 6 + row * 22, t, r, g, b);
}

static void draw_main(void)
{
    char t[64];

    budget = GLYPH_BUDGET;
    snprintf(t, sizeof t, "OVERLAY LOADER M3a  base %d  pin %02x%02x", BASE_VARIANT, psxx_release_info.key[0], psxx_release_info.key[1]);
    line(0, t, 255, 255, 255);
    su_slot_text(&ui, 0, t, sizeof t);
    line(2, t, 200, 200, 200);
    su_slot_text(&ui, 1, t, sizeof t);
    line(3, t, 200, 200, 200);
    for (int i = 0; i < 3; i++) line(5 + i, msg[i], 255, 220, 120);
    line(9, ICO_CROSS "load  " ICO_TRIANGLE "look  " ICO_SQUARE "groups  " ICO_START "forget", 150, 160, 200);
}

int main(void)
{
    int last = -1, frame = 0;
    uint8_t h[32];

    ui_reg_a();
    gpu_init(&ctx, 20, 20, 60);
    font_init(1);
    ticks_init();
    input_init(&in);
    hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
    sha256((const uint8_t *) "base", 4, h);
    printf("psxx overlay loader demo (M3a): base %d, pin %02x%02x.., base id %02x%02x.., hash %02x\n", BASE_VARIANT, psxx_release_info.key[0], psxx_release_info.key[1],
           psxx_release_info.base_id[0], psxx_release_info.base_id[1], h[0]);
    su_init(&ui, &ctx, &in, hz, "Load the overlay", PKG_NAME, PKG_KIND_OVERLAY, psxx_release_info.key, psxx_release_info.base_id, OVL_GROUP);
    cw_refresh(&ui.cw, 0);

    for (;;) {
        int f = VSync(-1);
        uint16_t pr;

        if (f == last) continue;
        last = f;
        frame++;
        input_poll(&in, NULL);
        pr = input_take_pressed(&in);

        if (screen == 0) {
            if (pr & PAD_CROSS) {
                if (!pinned()) say(0, "the release record is empty (tools/release.py)");
                else { screen = 1; msg[0][0] = msg[1][0] = msg[2][0] = 0; su_enter(&ui, frame); }
            }
            if (pr & PAD_TRIANGLE) cw_refresh(&ui.cw, frame);
            if (pr & PAD_SQUARE) do_groups();
            if (pr & PAD_START) { ldr_forget(); loaded = 0; msg[0][0] = msg[1][0] = msg[2][0] = 0; }
            draw_main();
        } else {
            int r = su_update(&ui, pr, frame);

            if (r == SU_LOADED) {
                int ret;
                char t[48];

                have_pkg = 1;
                snprintf(t, sizeof t, "loaded %u B at %08x", (unsigned) su_overlay(&ui)->size, (unsigned) su_overlay(&ui)->load);
                say(0, t);
                ret = ldr_call(su_overlay(&ui));
                loaded = 1;
                snprintf(t, sizeof t, "overlay returned %08x", (unsigned) ret);
                say(1, t);
                screen = 0;
            } else if (r == SU_CANCEL) {
                ldr_forget();                                    /* a screen that is left leaves no overlay that could run */
                loaded = 0;
                say(0, "cancelled");
                screen = 0;
            } else {
                su_draw(&ui);
            }
            if (screen == 0) draw_main();
        }
        gpu_present(&ctx);
    }
    return 0;
}
