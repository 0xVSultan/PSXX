#pragma once
#include "gpu.h"

/* Mixed case text for things that must be read exactly: addresses, keys, hex (the SDK's debug font has capital letters
 * only, which is useless for Base58 or bech32).
 *
 * A fixed size bitmap font (hal/psx/font_bdf.h, generated from a BDF file by tools/gen_bdf_font.py; currently Terminus
 * 10x18 bold, SIL OFL 1.1, see LICENSE.font): ASCII, Latin-1, Latin Extended-A and the Latin Extended-B letters the
 * font has (363 glyphs). Strings are UTF-8; characters the font does not have are drawn as '?'.
 * VRAM: two 4 bit glyph pages at (896, 0) and (960, 0), their CLUT at (896, 256), the button icons at (640, 256). */

/* Controller button icons, written into strings as single characters (about a line high, own colours; the
 * colour passed to font_draw does not apply to them). Adjacent string literals concatenate after escapes are parsed, so
 * "Hold " ICO_CIRCLE ICO_CROSS " to continue" is safe. */
#define ICO_CROSS        "\x01"
#define ICO_CIRCLE       "\x02"
#define ICO_SQUARE       "\x03"
#define ICO_TRIANGLE     "\x04"
#define ICO_START        "\x05"
#define ICO_SELECT       "\x06"
#define ICO_UP           "\x07"
#define ICO_DOWN         "\x08"
#define ICO_LEFT         "\x09"
#define ICO_RIGHT        "\x0a"
#define ICO_UPDOWN       "\x0b"
#define ICO_LEFTRIGHT    "\x0c"
#define ICO_L1           "\x0d"
#define ICO_L2           "\x0e"
#define ICO_R1           "\x0f"
#define ICO_R2           "\x10"
#define ICO_DPAD         "\x11"     /* all four arms white: "move" */
#define ICO_EYES         "\x12"     /* a pair of eyes: toggle the view */

/* Upload the glyph pages and the icons. Call once while the GPU is idle, after gpu_init(). `scale` is ignored (kept
 * for the callers): there is one size. */
void font_init(int scale);
/* Size of a character cell in pixels. */
int font_cell_w(void);
int font_cell_h(void);
/* Queue `s` (UTF-8) with its top-left corner at (x, y) in colour (r, g, b). Uses the OT slots z .. z + 5: z / z + 1 the
 * first glyph page and its texture page, z + 2 / z + 3 the second page, z + 4 / z + 5 the icons. */
void font_draw(RenderContext *ctx, int z, int x, int y, const char *s, int r, int g, int b);
/* Width in pixels of `s` as font_draw lays it out (icons by their own width). */
int font_width(const char *s);

/* UTF-8 helpers: next code point (advances *s, returns 0 at the end, '?' for an invalid byte), number of code points,
 * and encoding of a code point (up to 3 bytes, no terminator; returns the byte count). */
int font_utf8_next(const char **s);
int font_utf8_len(const char *s);
int font_utf8_encode(char *out, int cp);

/* The colour at the screen row y, for font_draw_big (rgb as for font_draw). */
typedef void (*font_colour_fn)(int y, uint8_t rgb[3], void *user);
/* The text k times bigger (2 k x k screen pixels per font pixel) with a vertical colour gradient; one cell is 2 k * font_cell_w()
 * pixels wide and k * font_cell_h() high. */
void font_draw_big(RenderContext *ctx, int z, int x, int y, const char *s, int k, font_colour_fn colour, void *user);
