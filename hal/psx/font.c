#include "font.h"
#include "font_bdf.h"
#include "icons_data.h"
#ifdef FONT_EXT
#include "fontext.h"
#endif

/* VRAM layout (the framebuffers use x 0..639, y 0..479; the QR code page is at (640, 0)):
 *   glyph pages  4 bit textures at (896, 0) and (960, 0), 256 x 256 texels each: 25 x 14 characters of 10 x 18 pixels
 *   glyph CLUT   16 entries at (896, 256): index 0 transparent, index 1 white (the colour comes from the sprite)
 *   icon page    16 bit texture at (640, 256) (icons_data.h) */
#define GLYPH_PAGE_X0 896
#define GLYPH_PAGE_X1 960
#define GLYPH_PAGE_Y 0
#define CLUT_X 896
#define CLUT_Y 256
#define ICON_PAGE_X 640
#define ICON_PAGE_Y 256

#define CELL_W FONT_BDF_CELL_W
#define CELL_H FONT_BDF_CELL_H
#define PER_ROW (256 / CELL_W)                       /* 25 */
#define PAGE_ROWS (256 / CELL_H)                     /* 14 */
#define PER_PAGE (PER_ROW * PAGE_ROWS)               /* 350 */
#define NPAGES ((FONT_NGLYPHS + PER_PAGE - 1) / PER_PAGE)
#define NICONS ICON_COUNT
#define ICON_ADV_GAP 2                               /* pixels after an icon */

_Static_assert(NPAGES <= 2, "the glyph set needs more than two texture pages");

int font_cell_w(void) { return CELL_W; }
int font_cell_h(void) { return CELL_H; }

/* ---- UTF-8 ---- */

int font_utf8_next(const char **s)
{
	const unsigned char *p = (const unsigned char *) *s;
	int c = *p;

	if (c == 0) return 0;
	if (c < 0x80) { *s += 1; return c; }
	if (c >= 0xC2 && c <= 0xDF && (p[1] & 0xC0) == 0x80) { *s += 2; return ((c & 0x1F) << 6) | (p[1] & 0x3F); }
	if (c >= 0xE0 && c <= 0xEF && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
		*s += 3;
		return ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
	}
	*s += 1;                                          /* invalid byte */
	return '?';
}

int font_utf8_len(const char *s)
{
	int n = 0;
	while (font_utf8_next(&s)) n++;
	return n;
}

int font_utf8_encode(char *out, int cp)
{
	if (cp < 0x80) { out[0] = (char) cp; return 1; }
	if (cp < 0x800) { out[0] = (char) (0xC0 | (cp >> 6)); out[1] = (char) (0x80 | (cp & 0x3F)); return 2; }
	out[0] = (char) (0xE0 | (cp >> 12)); out[1] = (char) (0x80 | ((cp >> 6) & 0x3F)); out[2] = (char) (0x80 | (cp & 0x3F));
	return 3;
}

/* glyph index of a code point, or -1 */
static int glyph_of(int cp)
{
	int base = 0;
	if (cp >= 0x20 && cp <= 0x7E) return cp - 0x20;
	if (cp == 0xA0) return 0;                         /* no-break space */
	for (int r = 0; r < FONT_NRUNS; base += FONT_RUNS[r++][1])      /* the glyphs are in the order of the runs of consecutive code points */
		if ((unsigned) (cp - FONT_RUNS[r][0]) < FONT_RUNS[r][1]) return base + cp - FONT_RUNS[r][0];
	return -1;
}

/* ---- atlas upload ---- */

/* one texel of a glyph page: 1 where the glyph is lit */
static int texel(int page, int x, int y)
{
	int col = x / CELL_W, row = y / CELL_H, g;
	if (col >= PER_ROW || row >= PAGE_ROWS) return 0;
	g = page * PER_PAGE + row * PER_ROW + col;
	if (g >= FONT_NGLYPHS) return 0;
	return (FONT_BDF[g][y % CELL_H] >> (15 - x % CELL_W)) & 1;
}

/* 4 bit texture: x counts 16 bit VRAM words, four texels each (leftmost in the lowest nibble); two words per call */
static uint32_t pair4(void *user, int x, int y)
{
	int page = (int) (intptr_t) user;
	uint32_t w = 0;
	for (int t = 0; t < 8; t++)
		if (texel(page, x * 4 + t, y)) w |= 1u << (4 * t);
	return w;
}

static uint32_t clut_pair(void *user, int x, int y)
{
	(void) user; (void) y;
	return x == 0 ? 0xFFFF0000u : 0u;                 /* entry 0 = 0 (transparent), entry 1 = white */
}

static uint32_t icon_pair(void *user, int x, int y)
{
	(void) user;
	return ICON_PAL[ICON_PIX[y * ICONS_W + x]] | ((uint32_t) ICON_PAL[ICON_PIX[y * ICONS_W + x + 1]] << 16);
}

#ifdef FONT_EXT
/* the glyph hooks of the language module (fontext.h): NULL while it is not loaded */
int (*font_hook_draw)(RenderContext *ctx, int cp, int x, int y, int r, int g, int b);
int (*font_hook_width)(int cp);
#endif

void font_init(int scale)
{
	(void) scale;                                     /* one size only: the glyph pages hold the 10 x 18 pixel font */
	gpu_upload_rows(CLUT_X, CLUT_Y, 16, 1, clut_pair, 0);
	for (int p = 0; p < NPAGES; p++)
		gpu_upload_rows(p ? GLYPH_PAGE_X1 : GLYPH_PAGE_X0, GLYPH_PAGE_Y, 64, 256, pair4, (void *) (intptr_t) p);
	gpu_upload_rows(ICON_PAGE_X, ICON_PAGE_Y, ICONS_W, ICONS_H, icon_pair, 0);
}

/* ---- drawing ---- */

/* Braille patterns U+2800..U+28FF are drawn from the code point, with no glyph data: bit n of the pattern is dot n + 1 of the Unicode names; dots 1-3 are the left column
 * from the top, 4-6 the right one, 7 and 8 the bottom row (left, right). A dot is 3 x 2 pixels (the pixels are twice as tall as wide) in the 10 x 18 cell. */
static const uint8_t ROW_Y[4] = {1, 5, 10, 14};      /* the dot rows in the cell: the dots are 4 or 5 pixels apart, also from one line of braille to the next (cell 18) */
static void braille(RenderContext *ctx, int z, int x, int y, int mask, int r, int g, int b)
{
	for (int n = 0; n < 8; n++) {
		const int col = n < 6 ? n / 3 : n - 6, row = n < 6 ? n % 3 : 3;

		if (mask >> n & 1) gpu_draw_rect(ctx, z, x + 1 + 5 * col, y + ROW_Y[row], 3, 2, r, g, b);
	}
}

/* Slots used by one call (higher slots are drawn first): z glyph page 0 sprites, z + 1 its texture page, z + 2 / z + 3 the
 * same for page 1, z + 4 / z + 5 the icons. A texture page primitive is only queued if the string needs it. */
void font_draw(RenderContext *ctx, int z, int x, int y, const char *s, int r, int g, int b)
{
	DR_TPAGE *tp[3] = {0, 0, 0};
	int cp;

	while ((cp = font_utf8_next(&s)) != 0) {
		if (cp >= 1 && cp <= NICONS) {                /* a button icon: own colours, centred on the line */
			const int n = cp - 1, w = ICON_RECT[n].w, h = ICON_RECT[n].h;
			if (!tp[2]) {
				tp[2] = (DR_TPAGE *) gpu_new_primitive(ctx, z + 5, sizeof(DR_TPAGE));
				setDrawTPage(tp[2], 0, 0, getTPage(2, 0, ICON_PAGE_X, ICON_PAGE_Y));      /* 16 bit direct colour */
			}
			SPRT *sp = (SPRT *) gpu_new_primitive(ctx, z + 4, sizeof(SPRT));
			setSprt(sp);
			setXY0(sp, x, y + (CELL_H - h) / 2);
			setWH(sp, w, h);
			setUV0(sp, ICON_RECT[n].x, ICON_RECT[n].y);
			setClut(sp, 0, 0);
			setRGB0(sp, GPU_FADE(128), GPU_FADE(128), GPU_FADE(128));               /* neutral: texture colours unchanged */
			x += w + ICON_ADV_GAP;
			continue;
		}
		int gi;
		if (cp >= 0x2800 && cp <= 0x28FF) { braille(ctx, z, x, y, cp - 0x2800, r, g, b); x += CELL_W; continue; }
		gi = glyph_of(cp);
#ifdef FONT_EXT
		if (gi < 0 && font_hook_draw) {               /* a glyph of the language module */
			int adv = font_hook_draw(ctx, cp, x, y, r, g, b);
			if (adv) { x += adv; continue; }
		}
#endif
		if (gi < 0) gi = '?' - 0x20;
		if (cp != ' ' && cp != 0xA0) {
			int page = gi / PER_PAGE, w = gi % PER_PAGE;
			if (!tp[page]) {
				tp[page] = (DR_TPAGE *) gpu_new_primitive(ctx, z + 1 + 2 * page, sizeof(DR_TPAGE));
				setDrawTPage(tp[page], 0, 0, getTPage(0, 0, page ? GLYPH_PAGE_X1 : GLYPH_PAGE_X0, GLYPH_PAGE_Y));   /* 4 bit */
			}
			SPRT *sp = (SPRT *) gpu_new_primitive(ctx, z + 2 * page, sizeof(SPRT));
			setSprt(sp);
			setXY0(sp, x, y);
			setWH(sp, CELL_W, CELL_H);
			setUV0(sp, (w % PER_ROW) * CELL_W, (w / PER_ROW) * CELL_H);
			setClut(sp, CLUT_X, CLUT_Y);
			setRGB0(sp, GPU_FADE(r), GPU_FADE(g), GPU_FADE(b));
		}
		x += CELL_W;
	}
}

int font_width(const char *s)
{
	int w = 0, cp;
	while ((cp = font_utf8_next(&s)) != 0) {
#ifdef FONT_EXT
		if (font_hook_width && glyph_of(cp) < 0) { int ew = font_hook_width(cp); if (ew) { w += ew; continue; } }
#endif
		w += (cp >= 1 && cp <= NICONS) ? ICON_RECT[cp - 1].w + ICON_ADV_GAP : CELL_W;
	}
	return w;
}

/* The text scaled up: every font pixel becomes 2 k x k screen pixels (so it looks square again on the 640 x 240 screen, where a
 * pixel is twice as tall as wide), cut into strips of two font rows that are each a Gouraud shaded textured quad whose top and bottom
 * colours come from colour(y, rgb): the text can have a vertical colour gradient. Uses the slot z. */
void font_draw_big(RenderContext *ctx, int z, int x, int y, const char *s, int k, font_colour_fn colour, void *user)
{
	const int cw = CELL_W * 2 * k, strip = 2;
	int cp;

	/* The quads carry their own texture page, and that stays set on the GPU: in slot 0 the sprites that come after them (the text of font_draw, whose page was set in slot 1, before)
	 * would read the other glyph page. Within a slot the primitive added last is drawn first: this one, added before the quads, is drawn after them and sets page 0 again. */
	if (z == 0) {
		DR_TPAGE *tp = (DR_TPAGE *) gpu_new_primitive(ctx, 0, sizeof(DR_TPAGE));
		setDrawTPage(tp, 0, 0, getTPage(0, 0, GLYPH_PAGE_X0, GLYPH_PAGE_Y));
	}
	while ((cp = font_utf8_next(&s)) != 0) {
		int gi = glyph_of(cp);
		if (gi < 0) gi = '?' - 0x20;
		if (cp != ' ' && cp != 0xA0) {
			int page = gi / PER_PAGE, w = gi % PER_PAGE;
			int u0 = (w % PER_ROW) * CELL_W, v0 = (w / PER_ROW) * CELL_H;
			for (int r0 = 0; r0 < CELL_H; r0 += strip) {
				int r1 = r0 + strip < CELL_H ? r0 + strip : CELL_H;
				int ya = y + r0 * k, yb = y + r1 * k;
				uint8_t ca[3], cb[3];
				POLY_GT4 *q = (POLY_GT4 *) gpu_new_primitive(ctx, z, sizeof(POLY_GT4));
				colour(ya, ca, user);
				colour(yb, cb, user);
				setPolyGT4(q);
				setXY4(q, x, ya, x + cw, ya, x, yb, x + cw, yb);
				setUV4(q, u0, v0 + r0, u0 + CELL_W, v0 + r0, u0, v0 + r1, u0 + CELL_W, v0 + r1);
				q->tpage = getTPage(0, 0, page ? GLYPH_PAGE_X1 : GLYPH_PAGE_X0, GLYPH_PAGE_Y);
				q->clut = getClut(CLUT_X, CLUT_Y);
				setRGB0(q, GPU_FADE(ca[0]), GPU_FADE(ca[1]), GPU_FADE(ca[2]));
				setRGB1(q, GPU_FADE(ca[0]), GPU_FADE(ca[1]), GPU_FADE(ca[2]));
				setRGB2(q, GPU_FADE(cb[0]), GPU_FADE(cb[1]), GPU_FADE(cb[2]));
				setRGB3(q, GPU_FADE(cb[0]), GPU_FADE(cb[1]), GPU_FADE(cb[2]));
			}
		}
		x += cw;
	}
}
