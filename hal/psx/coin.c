#include "coin.h"
#include <psxgpu.h>
#include "coin_data.h"
#include "coin_cm.h"
#include "memmap.h"

/* the textures are unpacked once, in coin_init (the first thing main does), into the slot of the signer: nothing is there before an overlay is loaded. The work memory
 * of the model, then the texels of the ring and the two emblems, one byte each (37.5 KB), and from there to VRAM */
#define CM_WORK ((uint8_t *) MM_SIG_LO)

#define PAGE_X 768
#define PAGE_Y 256
#define RING_X 800                                  /* the ring: u = 128, v = 0 */
#define RING_Y 256
#define HEADS_X 800                                 /* the crown: u = 128, v = 112 */
#define HEADS_Y 368
#define TAILS_X 768                                 /* the XMR: u = 0, v = 0 */
#define TAILS_Y 256
#define CLUT_X 768
#define CLUT_Y 480
#define RING_WORDS_PER_ROW (COIN_SIZE / 4)          /* 16 bit words per texture row */
#define IN_WORDS_PER_ROW (COIN_IN / 4)
#define RING_U ((RING_X - PAGE_X) * 4)              /* 128 */

_Static_assert(COIN_SIZE == 112 && COIN_IN == 80, "coin.h / the VRAM layout assume a 112 x 112 texel ring and 80 x 80 texel emblems");

typedef struct { const uint8_t *t; int w; } coin_tex;      /* texels, one byte each, w a row */

static uint32_t coin_pair(void *user, int x, int y)          /* the 16 bit words x and x + 1 of row y: eight texels, the leftmost in the lowest nibble */
{
	const coin_tex *c = (const coin_tex *) user;
	const uint8_t *s = c->t + y * c->w + 4 * x;
	uint32_t v = 0;

	for (int i = 7; i >= 0; i--) v = v << 4 | s[i];
	return v;
}

static uint32_t clut_pair(void *user, int x, int y)
{
	const uint16_t *c = (const uint16_t *) user;
	(void) y;
	return c[x] | ((uint32_t) c[x + 1] << 16);
}

void coin_init(void)
{
	static const uint8_t WH[6] = {COIN_SIZE, COIN_SIZE, COIN_IN, COIN_IN, COIN_IN, COIN_IN};
	uint16_t *p = (uint16_t *) CM_WORK;
	uint8_t *n = CM_WORK + 2 * COIN_CM_CTX, *tx = n + COIN_CM_CTX;
	coin_tex RING = {tx, COIN_SIZE}, HEADS = {tx + COIN_SIZE * COIN_SIZE, COIN_IN}, TAILS = {tx + COIN_SIZE * COIN_SIZE + COIN_IN * COIN_IN, COIN_IN};

	coin_cm_decode(COIN_CM, WH, 3, tx, p, n);
	gpu_upload_rows(CLUT_X, CLUT_Y, 16, 1, clut_pair, (void *) COIN_CLUT);
	gpu_upload_rows(RING_X, RING_Y, RING_WORDS_PER_ROW, COIN_SIZE, coin_pair, (void *) &RING);
	gpu_upload_rows(HEADS_X, HEADS_Y, IN_WORDS_PER_ROW, COIN_IN, coin_pair, (void *) &HEADS);
	gpu_upload_rows(TAILS_X, TAILS_Y, IN_WORDS_PER_ROW, COIN_IN, coin_pair, (void *) &TAILS);
}

/* one textured quad of the coin: `w` wide in the middle of (cx, cy), `h` tall, the texture rectangle (u, v, size) */
static void quad(RenderContext *ctx, int z, int cx, int cy, int w, int h, int u, int v, int size, int bright)
{
	POLY_FT4 *q = (POLY_FT4 *) gpu_new_primitive(ctx, z, sizeof(POLY_FT4));
	int x0 = cx - w / 2, y0 = cy - h / 2, x1 = x0 + w - 1, y1 = y0 + h - 1;   /* one pixel less each way: see below */

	setPolyFT4(q);
	setXY4(q, x0, y0, x1, y0, x0, y1, x1, y1);
	/* The picture is drawn at 2 : 1 across and 1 : 1 down, so with the far edge at u + size the step is a whole or half texel per pixel and every second pixel (every pixel
	 * down) samples exactly on a texel edge: which side it falls on then depends on rounding noise, and an emulator that renders in floating point gets it different in the two
	 * frame buffers (they are at different places in VRAM): the coin trembles. The quad is one pixel smaller each way for the same texels, so the step is a little over
	 * 1/2 (over 1) texel per pixel, the sample lies always inside its texel (the last pixel across samples size - 0.5; down the last row of the texture is not drawn, it is clear). */
	setUV4(q, u, v, u + size, v, u, v + size, u + size, v + size);
	q->tpage = getTPage(0, 0, PAGE_X, PAGE_Y);            /* 4 bit */
	q->clut  = getClut(CLUT_X, CLUT_Y);
	setRGB0(q, GPU_FADE(bright), GPU_FADE(bright), GPU_FADE(bright));
}

/* A flat polygon of the effects, blended with the picture: abr 0 = half of it + half of the colour (darkens with a dark colour), abr 1 = added (lightens). The blend mode is
 * a texture page word queued in the same slot after the polygons, so it is drawn before them (the last queued comes first). */
static void blend_mode(RenderContext *ctx, int z, int abr)
{
	DR_TPAGE *tp = (DR_TPAGE *) gpu_new_primitive(ctx, z, sizeof(DR_TPAGE));
	setDrawTPage(tp, 0, 0, getTPage(0, abr, 0, 0));
}

static void flat4(RenderContext *ctx, int z, const int xy[8], int c)
{
	POLY_F4 *q = (POLY_F4 *) gpu_new_primitive(ctx, z, sizeof(POLY_F4));

	setPolyF4(q);
	setSemiTrans(q, 1);
	setXY4(q, xy[0], xy[1], xy[2], xy[3], xy[4], xy[5], xy[6], xy[7]);
	setRGB0(q, GPU_FADE(c), GPU_FADE(c), GPU_FADE(c));
}

/* The shadow: a flat ellipse on the ground at (cx, gy), five strips under each other. The higher the coin is above the ground (`lift` pixels), the smaller and fainter. */
void coin_shadow(RenderContext *ctx, int z, int cx, int gy, int lift)
{
	static const uint8_t HW[9] = {0, 169, 222, 248, 255, 248, 222, 169, 0};   /* half width of the strip edges, of 256: an ellipse at -1, -0.75 ... 1 */
	const int a = 100 - lift * 13 / 10, h = 16 - lift / 4, c = lift * 3 / 8;    /* c stays below the background (about 20), so the shadow is darker than it at any height */
	int y[9];

	for (int k = 0; k < 9; k++) y[k] = gy - h / 2 + h * k / 8;
	for (int k = 0; k < 8; k++) {
		const int xy[8] = {cx - a * HW[k] / 256, y[k], cx + a * HW[k] / 256, y[k], cx - a * HW[k + 1] / 256, y[k + 1], cx + a * HW[k + 1] / 256, y[k + 1]};
		flat4(ctx, z, xy, c);
	}
	blend_mode(ctx, z, 0);
}

void coin_draw(RenderContext *ctx, int z, int cx, int cy, int w, int side, int bright)
{
	int cw;

	if (w < 2) w = 2;
	bright = bright * (64 + 64 * w / COIN_DRAW_W) / 128;    /* turned away from the light it is darker: half as bright edge on */
	cw = w * COIN_IN / COIN_SIZE;                          /* the emblem is smaller than the ring by the same factor in both directions */
	if (cw < 2) cw = 2;
	quad(ctx, z, cx, cy, w, COIN_DRAW_H, RING_U, RING_Y - PAGE_Y, COIN_SIZE, bright);
	if (side == COIN_TAILS_SIDE) quad(ctx, z - 1, cx, cy, cw, COIN_IN, (TAILS_X - PAGE_X) * 4, TAILS_Y - PAGE_Y, COIN_IN, bright);
	else quad(ctx, z - 1, cx, cy, cw, COIN_IN, (HEADS_X - PAGE_X) * 4, HEADS_Y - PAGE_Y, COIN_IN, bright);   /* z - 1 comes after z: on top of the ring */
}

/* |cos(pi k / 32)| and sin(pi k / 32), times 256, k = 0..32 */
static const uint16_t ACOS[33] = {256, 255, 251, 245, 237, 226, 213, 198, 181, 162, 142, 121, 98, 74, 50, 25, 0,
                                  25, 50, 74, 98, 121, 142, 162, 181, 198, 213, 226, 237, 245, 251, 255, 256};
static const uint16_t SIN[33] = {0, 25, 50, 74, 98, 121, 142, 162, 181, 198, 213, 226, 237, 245, 251, 255, 256,
                                 255, 251, 245, 237, 226, 213, 198, 181, 162, 142, 121, 98, 74, 50, 25, 0};

void coin_flip_frame(int step, int steps, int start_side, int height, int *w, int *dy, int *side)
{
	const int hop = COIN_BOUNCE_STEPS;
	int t;

	if (step >= steps - hop) {                        /* landed: two small hops of the coin, the second lower; the side is the final one */
		const int b = step - (steps - hop);               /* 0..hop */
		*w = COIN_DRAW_W;
		*side = 1 - start_side;
		*dy = b >= hop ? 0 : b < 7 ? -(SIN[b * 32 / 7] * 8 / 256) : -(SIN[(b - 7) * 32 / 5] * 3 / 256);
		return;
	}
	steps -= hop;
	t = step * 256 / steps;                           /* 0..256 */
	int ease = 256 - ((256 - t) * (256 - t)) / 256;   /* fast start, soft landing */
	int a = 96 * ease / 256;                          /* 0..96 in steps of pi/32: three half turns */
	int half = a / 32, k = a % 32;

	if (step >= steps) { half = 3; k = 0; }
	*w = COIN_DRAW_W * ACOS[k] / 256;
	*side = (half & 1) ? 1 - start_side : start_side;
	*dy = -(SIN[(t * 32) / 256] * height / 256);      /* up and back */
}
