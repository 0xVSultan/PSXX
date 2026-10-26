#pragma once
/* The check of the screen layout on the host (tests/test_screens_a.c, tests/test_screens_b.c, tests/test_langui.c). The screens are compiled with stand-ins that hand every
 * text, filled rectangle and picture (QR code, coin, dice) to lc_text, lc_rect and lc_pic; lc_frame then lays the frame out as the console does and checks it:
 *   - the font of hal/psx/font.c: 10 x 18 cells; the button icons (control characters 1..18) at their size in hal/psx/icons_data.h, centred on the 18 pixel line, so they
 *     stand out above and below it; the 16 x 16 glyphs of the language card twice as wide (lc_ext_width) and 16 high;
 *   - no two texts overlap (each run of letters and each icon is a box of its own; spaces are not);
 *   - a text does not lie on a picture, and does not cross the edge of a filled rectangle (inside one is fine: a key cap, a selection, a text field);
 *   - everything stays in the safe area: 8 pixels from the sides, 4 from the top and 8 from the bottom (TV sets and emulators crop the edges of the picture).
 * A problem is reported once per screen and pair of texts; lc_bad counts them. */
#define LC_CELL_W 10
#define LC_CELL_H 18

extern int lc_bad, lc_frames;
extern const char *lc_tag;                                 /* printed in front of the screen in a report: the language of the pass */
void lc_snapshot(int on);                                  /* the snapshot of the texts (below) records only while on: the English pass */
extern int (*lc_ext_width)(int cp);                       /* the advance of a glyph of another script that is loaded, 0 if there is none */

int  lc_width(const char *s);                             /* as font_width counts it */
void lc_text(int x, int y, const char *s);                /* font_draw */
void lc_rect(int x, int y, int w, int h);                 /* gpu_draw_rect */
void lc_pic(int x, int y, int w, int h, const char *what);   /* a picture: QR code, coin, dice, the disc */
void lc_frame(const char *screen, int yres);              /* checks the frame drawn since the last call and forgets it */
