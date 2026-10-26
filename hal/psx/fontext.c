#include "fontext.h"
#include <psxgpu.h>
#include "gpu.h"

/* The glyphs of other scripts for font_draw (the language module, an overlay): the code that was in font.c, now loaded with the module. VRAM: the glyph pages (896, 0) and (960, 0) of
 * font.c, the texture pages of these glyphs at (896, 256) and (960, 256), 4 bit, the same CLUT. */
#define GLYPH_PAGE_X0 896
#define GLYPH_PAGE_X1 960
#define CLUT_X 896
#define CLUT_Y 256

#define EXT_Y 256                                    /* the texture pages are at (896, 256) and (960, 256); the CLUT of the glyph pages is in the first row, the glyphs start in row 1 */

static struct {
	const glyphset *gs;
	uint16_t cps[FONT_EXT_MAX], sidx[FONT_EXT_MAX];  /* the code points ascending, and their index in the set */
	int n, cw, ch, cols, rows, per, sx;              /* cell size on the page, cells in a row / in a column / on a page, screen pixels per font pixel across */
} ext;
static int ext_cur = -1;
static uint16_t ext_rows[18];

static int ext_find(int cp)
{
	int lo = 0, hi = ext.n - 1;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		if (ext.cps[mid] == cp) return mid;
		if (ext.cps[mid] < cp) lo = mid + 1; else hi = mid - 1;
	}
	return -1;
}

/* a 4 bit texture page of the glyphs, two words (eight texels) at a time, like pair4. A glyph drawn twice as wide that is not a hanzi (kana, hangul) gets one screen pixel
 * more after each of its pixels: its slanted 1 pixel strokes would otherwise break into steps that touch only at the corners; the strokes of the
 * hanzi are straight and close together, they stay as they are */
static uint32_t ext_pair(void *user, int x, int y)
{
	int page = (int) (intptr_t) user, cell_row = y / ext.ch, r = y % ext.ch;
	uint32_t w = 0;

	if (cell_row >= ext.rows || r >= ext.gs->h) return 0;
	for (int t = 0; t < 8; t++) {
		int tt = x * 4 + t, col = tt / ext.cw, c = tt % ext.cw, slot = page * ext.per + cell_row * ext.cols + col, on;
		if (col >= ext.cols || slot >= ext.n) continue;
		if (slot != ext_cur) { glyphset_rows(ext.gs, ext.sidx[slot], ext_rows); ext_cur = slot; }
		on = (ext_rows[r] >> (15 - c / ext.sx)) & 1;
		if (!on && c && ext.sx == 2 && (ext.cps[slot] < 0x4E00 || ext.cps[slot] >= 0xA000))         /* outside the CJK unified ideographs */
			on = (ext_rows[r] >> (15 - (c - 1) / 2)) & 1;
		if (on) w |= 1u << (4 * t);
	}
	return w;
}

/* a glyph of the set at (x, y): its own texture page primitive before the sprite (font_draw cannot keep one per string for a hook); the advance, or 0 for a character it lacks */
static int ext_draw(RenderContext *ctx, int cp, int x, int y, int r, int g, int b)
{
	int k = ext_find(cp), page, i;
	DR_TPAGE *tp;
	SPRT *sp;

	if (k < 0) return 0;
	page = k / ext.per;
	i = k % ext.per;
	tp = (DR_TPAGE *) gpu_new_primitive(ctx, 13 + 2 * page, sizeof(DR_TPAGE));
	setDrawTPage(tp, 0, 0, getTPage(0, 0, page ? GLYPH_PAGE_X1 : GLYPH_PAGE_X0, EXT_Y));
	sp = (SPRT *) gpu_new_primitive(ctx, 12 + 2 * page, sizeof(SPRT));
	setSprt(sp);
	setXY0(sp, x, y);
	setWH(sp, ext.cw, ext.ch);
	setUV0(sp, (i % ext.cols) * ext.cw, 1 + (i / ext.cols) * ext.ch);
	setClut(sp, CLUT_X, CLUT_Y);
	setRGB0(sp, GPU_FADE(r), GPU_FADE(g), GPU_FADE(b));
	return ext.cw;
}

static int ext_width(int cp) { return ext_find(cp) >= 0 ? ext.cw : 0; }

int font_ext_load(const glyphset *gs, const uint16_t *cps, int n)
{
	int m = 0;

	ext.gs = gs;
	ext.sx = gs->w == 16 ? 2 : 1;
	ext.cw = gs->w * ext.sx;
	ext.ch = gs->h < 16 ? 16 : gs->h;
	ext.cols = 256 / ext.cw;
	ext.rows = 255 / ext.ch;
	ext.per = ext.cols * ext.rows;
	for (int i = 0; i < n && m < FONT_EXT_MAX && m < 2 * ext.per; i++) {            /* sorted, without duplicates, only what the set has */
		int j = m;
		if (glyphset_find(gs, cps[i]) < 0) continue;
		while (j > 0 && ext.cps[j - 1] > cps[i]) { ext.cps[j] = ext.cps[j - 1]; j--; }
		if (j > 0 && ext.cps[j - 1] == cps[i]) { for (int k = j; k < m; k++) ext.cps[k] = ext.cps[k + 1]; continue; }
		ext.cps[j] = cps[i];
		m++;
	}
	for (int i = 0; i < m; i++) ext.sidx[i] = (uint16_t) glyphset_find(gs, ext.cps[i]);
	ext.n = m;
	ext_cur = -1;
	for (int p = 0; p * ext.per < m; p++)
		gpu_upload_rows(p ? GLYPH_PAGE_X1 : GLYPH_PAGE_X0, EXT_Y + 1, 64, ext.rows * ext.ch, ext_pair, (void *) (intptr_t) p);
	font_hook_draw = ext_draw;
	font_hook_width = ext_width;
	return m;
}

void font_ext_clear(void)
{
	ext.n = 0;
	font_hook_draw = 0;
	font_hook_width = 0;
}

