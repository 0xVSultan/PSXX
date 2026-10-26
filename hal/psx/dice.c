#include "dice.h"
#include <psxgpu.h>

#define PAGE_X 832
#define PAGE_Y 256
#define CLUT_X 832
#define CLUT_Y 480
#define DICE_SIZE 64
#define WORDS_PER_ROW (DICE_SIZE / 4)               /* 16 */

/* The faces are made here, texel by texel, instead of being stored (12 KB of texels): a white rounded square with a light rim and pips. 4 bit texels:
 *   0 transparent | 1..3 the face, white and the two shades of the rim | 4, 5 the edge blended with the background | 6..9 a pip: 1/4, 1/2, 3/4 and all dark */
#define RGB555(r, g, b) ((uint16_t) (((r) >> 3) | ((g) >> 3) << 5 | ((b) >> 3) << 10 | 0x8000))
static const uint16_t CLUT[16] = {0, RGB555(255, 255, 255), RGB555(250, 250, 250), RGB555(238, 238, 238), RGB555(92, 92, 119), RGB555(173, 173, 185),
                                  RGB555(207, 207, 207), RGB555(160, 160, 160), RGB555(112, 112, 112), RGB555(65, 65, 65)};

_Static_assert(DICE_SIZE == 64, "dice.h and the VRAM layout assume 64 x 64 texel faces");

/* The pips of the faces on a 3 x 3 grid, bit 3 * row + column. */
static const uint16_t PIPS[6] = {1 << 4, 1 << 0 | 1 << 8, 1 << 0 | 1 << 4 | 1 << 8, 1 << 0 | 1 << 2 | 1 << 6 | 1 << 8, 1 << 0 | 1 << 2 | 1 << 4 | 1 << 6 | 1 << 8,
                                 1 << 0 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 6 | 1 << 8};

static int pow8(int u)                               /* (u / 256) ^ 8 * 256, u 0..256 */
{
	int u2 = (u * u) >> 8, u4 = (u2 * u2) >> 8;
	return (u4 * u4) >> 8;
}

/* One texel of die face `f` (0..5). The body is a squircle |x|^8 + |y|^8 = 1: the corners are rounder than a circle of the same radius and the sides straighter, as in the art
 * this replaces (ui/dice); e is how far inside the edge the texel centre is, 64 to a texel. A pip is a disc of 5.8 texels, its edge blended in 5 steps. */
static int texel(int f, int x, int y)
{
	int ux = x < 32 ? 63 - 2 * x : 2 * x - 63, uy = y < 32 ? 63 - 2 * y : 2 * y - 63;   /* 1..63: the distance from the middle, in half texels */
	int e = 256 - pow8(ux * 4) - pow8(uy * 4), c = 0;

	if (e < -24) return 0;
	if (e < 0) return 4;
	if (e < 24) return 5;
	/* the rim: the same shape 3 % and 7.5 % smaller marks where the two shades end, so the rim has the same width along the corners as along the sides */
	c = 256 - pow8(ux * 4 * 100 / 93) - pow8(uy * 4 * 100 / 93) >= 0 ? 1 : 256 - pow8(ux * 4 * 100 / 97) - pow8(uy * 4 * 100 / 97) >= 0 ? 2 : 3;
	for (int p = 0; p < 9; p++) {
		int dx, dy, m, w;
		if (!(PIPS[f] >> p & 1)) continue;
		dx = (2 * x + 1) * 2 - (68 + 60 * (p % 3));     /* the pip centres are at 17, 32, 47: in quarter texels */
		dy = (2 * y + 1) * 2 - (68 + 60 * (p / 3));
		m = 25 * 25 - dx * dx - dy * dy;                 /* positive inside; 200 to a texel at the edge */
		w = (m + 100) * 4 / 200;
		if (m + 100 < 0) w = 0;
		if (w > 4) w = 4;
		if (w) c = 5 + w;
	}
	return c;
}

static uint32_t face_pair(void *user, int x, int y)  /* the 16 bit words x and x + 1 of row y: eight texels, the leftmost in the lowest nibble */
{
	const int f = (int) (intptr_t) user;
	uint32_t v = 0;

	for (int i = 7; i >= 0; i--) v = v << 4 | (uint32_t) texel(f, 4 * x + i, y);
	return v;
}

static uint32_t clut_pair(void *user, int x, int y)
{
	const uint16_t *c = (const uint16_t *) user;
	(void) y;
	return c[x] | ((uint32_t) c[x + 1] << 16);
}

void dice_init(void)
{
	gpu_upload_rows(CLUT_X, CLUT_Y, 16, 1, clut_pair, (void *) CLUT);
	for (int f = 0; f < 6; f++)
		gpu_upload_rows(PAGE_X + WORDS_PER_ROW * (f % 3), PAGE_Y + DICE_SIZE * (f / 3), WORDS_PER_ROW, DICE_SIZE, face_pair, (void *) (intptr_t) f);
}

int dice_texel(int face, int x, int y) { return texel(face < 1 ? 0 : face > 6 ? 5 : face - 1, x, y); }

void dice_draw(RenderContext *ctx, int z, int x, int y, int w, int h, int face)
{
	POLY_FT4 *q = (POLY_FT4 *) gpu_new_primitive(ctx, z, sizeof(POLY_FT4));
	int f = face < 1 ? 0 : face > 6 ? 5 : face - 1;
	int u0 = (f % 3) * DICE_SIZE, v0 = (f / 3) * DICE_SIZE, e = DICE_SIZE - 1;

	setPolyFT4(q);
	setXY4(q, x, y, x + w, y, x, y + h, x + w, y + h);
	setUV4(q, u0, v0, u0 + e, v0, u0, v0 + e, u0 + e, v0 + e);
	q->tpage = getTPage(0, 0, PAGE_X, PAGE_Y);            /* 4 bit */
	q->clut  = getClut(CLUT_X, CLUT_Y);
	setRGB0(q, GPU_FADE(128), GPU_FADE(128), GPU_FADE(128));
}
