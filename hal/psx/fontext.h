#pragma once
/* Glyphs of the other scripts (hanzi, hangul, kana, Cyrillic: the language card, core/lang) for font_draw. font_ext_load puts the glyphs of up to FONT_EXT_MAX characters of
 * one glyph set into VRAM (free texture pages at (896, 256) and (960, 256), their CLUT is the one of the glyph pages); font_draw then draws a character that the Latin font lacks
 * from them. A 16 pixel wide glyph is drawn twice as wide (32 x 16: square on the 640 x 240 screen, where a pixel is twice as tall as wide), the 10 x 18 Cyrillic as it is.
 * They use the OT slots 12 .. 15 (12 / 14 the sprites, 13 / 15 the texture pages): the screens that show them must not use those. Call with the GPU idle. */
#include <stdint.h>
#include "gpu.h"
#include "lang/lang.h"

#define FONT_EXT_MAX 240

/* The characters (code points, in any order, duplicates are fine) that the screen is about to draw; the glyphs come from `gs`. Characters the set lacks are not drawn as glyphs
 * ('?' then). Returns how many glyphs are in VRAM. */
int font_ext_load(const glyphset *gs, const uint16_t *cps, int n);
/* Forget them: font_draw is the Latin font alone again. */
void font_ext_clear(void);

/* The hooks of font_draw / font_width (font.c, in the base): font_ext_load sets them, font_ext_clear takes them away, and the module must clear them before it returns, because its code is
 * wiped with the overlay region. The draw hook returns the advance of the glyph it queued, 0 if it has none for the character; the width hook the same advance. */
extern int (*font_hook_draw)(RenderContext *ctx, int cp, int x, int y, int r, int g, int b);
extern int (*font_hook_width)(int cp);
