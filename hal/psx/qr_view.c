#include "qr_view.h"

#define PAGE_X 640
#define PAGE_Y 0
#define QUIET 4

int qr_view_scale(const qr_code *qr)
{
	int s = 180 / (qr->size + 2 * QUIET);                        /* at most 180 pixels: from below the title (UI_TOP + 20) to above the hint line (UI_HINT2, ui.h) */
	return s < 2 ? 2 : s > 5 ? 5 : s;
}

int qr_view_pixels(const qr_code *qr, int scale)
{
	return (qr->size + 2 * QUIET) * scale;
}

static uint32_t zero_pair(void *user, int x, int y) { (void) user; (void) x; (void) y; return 0; }

typedef struct { const qr_code *qr; int scale; } view_t;

/* dark module = opaque black (bit 15 set, so it is not the transparent colour 0), light = opaque white */
static uint32_t pixel(const view_t *v, int x, int y)
{
	int dark = qr_module(v->qr, x / v->scale - QUIET, y / v->scale - QUIET);
	return dark ? 0x8000u : 0xFFFFu;
}

static uint32_t pair(void *user, int x, int y)
{
	const view_t *v = (const view_t *) user;
	return pixel(v, x, y) | (pixel(v, x + 1, y) << 16);
}

void qr_view_upload(const qr_code *qr, int scale)
{
	view_t v = {qr, scale};
	int w = qr_view_pixels(qr, scale);
	/* one extra (white) row and column: the stretched quad samples up to texel w */
	gpu_upload_rows(PAGE_X, PAGE_Y, (w + 2) & ~1, w + 1, pair, &v);
}

void qr_view_draw(RenderContext *ctx, int z, int x, int y, const qr_code *qr, int scale)
{
	int w = qr_view_pixels(qr, scale);
	gpu_draw_stretched16(ctx, z, x, y, w, w, 2 * w, PAGE_X, PAGE_Y);   /* 640 wide mode: pixels are 2:1 */
}

void qr_view_clear(void)
{
	gpu_upload_rows(PAGE_X, PAGE_Y, 256, 256, zero_pair, 0);
}
