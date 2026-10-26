#include "gpu.h"
#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <psxetc.h>
#include <hwregs_c.h>

static void ot_clear_r(uint32_t *ot, size_t length);

int gpu_fade = 256;
static int bg_r, bg_g, bg_b;

void gpu_set_fade(RenderContext *ctx, int fade) {
	if (fade < 0) fade = 0;
	if (fade > 256) fade = 256;
	gpu_fade = fade;
	setRGB0(&(ctx->buffers[0].draw_env), (bg_r * fade) >> 8, (bg_g * fade) >> 8, (bg_b * fade) >> 8);
	setRGB0(&(ctx->buffers[1].draw_env), (bg_r * fade) >> 8, (bg_g * fade) >> 8, (bg_b * fade) >> 8);
}

static void setup_context(RenderContext *ctx, int w, int h, int r, int g, int b) {
	bg_r = r; bg_g = g; bg_b = b;
	// Place the two framebuffers vertically in VRAM.
	SetDefDrawEnv(&(ctx->buffers[0].draw_env), 0, 0, w, h);
	SetDefDispEnv(&(ctx->buffers[0].disp_env), 0, 0, w, h);
	SetDefDrawEnv(&(ctx->buffers[1].draw_env), 0, h, w, h);
	SetDefDispEnv(&(ctx->buffers[1].disp_env), 0, h, w, h);

	// Show the full active area (SetDefDispEnv leaves screen at its defaults).
	ctx->buffers[0].disp_env.screen.y = 0;
	ctx->buffers[0].disp_env.screen.h = h;
	ctx->buffers[1].disp_env.screen.y = 0;
	ctx->buffers[1].disp_env.screen.h = h;

	// Set the default background color and enable auto-clearing.
	setRGB0(&(ctx->buffers[0].draw_env), r, g, b);
	setRGB0(&(ctx->buffers[1].draw_env), r, g, b);
	ctx->buffers[0].draw_env.isbg = 1;
	ctx->buffers[1].draw_env.isbg = 1;

	// Initialize the first buffer and clear its OT so that it can be used for drawing.
	ctx->active_buffer = 0;
	ctx->next_packet   = ctx->buffers[0].buffer;
	ot_clear_r(ctx->buffers[0].ot, GPU_OT_LENGTH);

	// Set the video mode, display ranges etc. once, then turn the output on.
	// Afterwards only the display start address changes (see gpu_flip).
	PutDispEnv(&(ctx->buffers[1].disp_env));
	SetDispMask(1);
}

static void gpu_wait_idle(void) {
	for (int i = 0; i < 2000000; i++) {
		if (!(DMA_CHCR(DMA_GPU) & (1 << 24)) &&
		    (GPU_GP1 & 0x14000000) == 0x14000000)
			return;
	}
	LOG("gpu_wait_idle: timeout\n");
}

static void gpu_cmd(uint32_t word) {
	for (int i = 0; i < 2000; i++) {
		if (GPU_GP1 & 0x04000000)       // ready to receive command word
			break;
		if (i == 1999) {
			static int warned;
			if (warned++ < 3)
				LOG("gpu_cmd: timeout, GPUSTAT=%08x\n", (unsigned) GPU_GP1);
		}
	}
	GPU_GP0 = word;
}

// Same effect as PutDrawEnv(): draw mode, drawing area, offset, background fill.
static void put_draw_env(const DRAWENV *e) {
	gpu_cmd(0xE1000000 | (e->tpage & 0x1FF) | (e->dtd ? 1 << 9 : 0) | (e->dfe ? 1 << 10 : 0));
	gpu_cmd(0xE3000000 | ((e->clip.y & 0x3FF) << 10) | (e->clip.x & 0x3FF));
	gpu_cmd(0xE4000000 | (((e->clip.y + e->clip.h - 1) & 0x3FF) << 10) |
	                     ((e->clip.x + e->clip.w - 1) & 0x3FF));
	// DRAWENV.ofs is relative to the drawing area, the GPU offset is absolute.
	gpu_cmd(0xE5000000 | (((e->clip.y + e->ofs[1]) & 0x7FF) << 11) |
	                     ((e->clip.x + e->ofs[0]) & 0x7FF));
	if (e->isbg) {
		gpu_cmd(0x02000000 | e->r0 | (e->g0 << 8) | (e->b0 << 16));
		gpu_cmd(((uint32_t) e->clip.y << 16) | (uint16_t) e->clip.x);
		gpu_cmd(((uint32_t) e->clip.h << 16) | (uint16_t) e->clip.w);
	}
}

// Same effect as ClearOTagR(): reverse ordering table, last entry = terminator.
static void ot_clear_r(uint32_t *ot, size_t length) {
	ot[0] = 0x00FFFFFF;
	for (size_t i = 1; i < length; i++)
		ot[i] = (uint32_t) &ot[i - 1] & 0x00FFFFFF;
}

// Same effect as DrawOTag(): start a linked-list DMA to GP0 and return.
static void gpu_send_ot(const uint32_t *ot_head) {
	GPU_GP1 = 0x04000002;  // DMA direction: CPU -> GP0
	DMA_MADR(DMA_GPU) = (uint32_t) ot_head & 0x00FFFFFF;
	DMA_BCR(DMA_GPU)  = 0;
	DMA_CHCR(DMA_GPU) = 0x01000401;
}

void gpu_init(RenderContext *ctx, int r, int g, int b) {
	ResetGraph(0);
	ctx->yres = (GetVideoMode() == MODE_PAL) ? 256 : 240;
	setup_context(ctx, GPU_XRES, ctx->yres, r, g, b);
	/* GP1(07h): the vertical display range, 240 lines (NTSC) or 256 lines (PAL) from the line y1. The Sony library starts the NTSC picture at line 16 and the PAL one at line 35 (the
	 * 0x23 below). An NTSC picture that starts at 16 is cut at the top by about 4 lines in DuckStation (its default crop of the overscan; a TV hides about as much) and the title of
	 * every screen lost its upper edge, so the NTSC picture starts 3 lines lower. SCPH-7001, DuckStation: the lines 5 .. 227 of the layout (ui.h) are what that crop shows then. */
	{
		uint32_t y1 = GetVideoMode() == MODE_PAL ? 0x23 : 0x13;
		GPU_GP1 = 0x07000000 | y1 | ((y1 + (uint32_t) ctx->yres) << 10);
	}
}

void gpu_flip(RenderContext *ctx, int wait_vblank) {
	// Wait for the GPU to finish drawing, then (optionally) for vblank to prevent tearing.
	gpu_wait_idle();
	if (wait_vblank)
		VSync(0);

	RenderBuffer *draw_buffer = &(ctx->buffers[ctx->active_buffer]);
	RenderBuffer *disp_buffer = &(ctx->buffers[ctx->active_buffer ^ 1]);

	// Display the framebuffer the GPU has just finished drawing and start
	// rendering the display list that was filled up in the main loop.
	// GP1(05h): display area start in VRAM. Direct write, no SDK queue.
	GPU_GP1 = 0x05000000 | ((uint32_t) disp_buffer->disp_env.disp.y << 10) |
	          (uint32_t) disp_buffer->disp_env.disp.x;
	put_draw_env(&(draw_buffer->draw_env));
	gpu_send_ot(&(draw_buffer->ot[GPU_OT_LENGTH - 1]));

	// Switch over to the next buffer, clear it and reset the packet allocation pointer.
	ctx->active_buffer ^= 1;
	ctx->next_packet    = disp_buffer->buffer;
	ot_clear_r(disp_buffer->ot, GPU_OT_LENGTH);
}

void gpu_present(RenderContext *ctx) {
	RenderBuffer *draw_buffer = &(ctx->buffers[ctx->active_buffer]);
	RenderBuffer *other       = &(ctx->buffers[ctx->active_buffer ^ 1]);

	// The other buffer is on screen while the GPU renders into this one, so nothing is torn during drawing.
	gpu_wait_idle();
	put_draw_env(&(draw_buffer->draw_env));
	gpu_send_ot(&(draw_buffer->ot[GPU_OT_LENGTH - 1]));
	gpu_wait_idle();
	// GP1(05h): now show the finished frame.
	GPU_GP1 = 0x05000000 | ((uint32_t) draw_buffer->disp_env.disp.y << 10) |
	          (uint32_t) draw_buffer->disp_env.disp.x;

	ctx->active_buffer ^= 1;
	ctx->next_packet    = other->buffer;
	ot_clear_r(other->ot, GPU_OT_LENGTH);
}

void gpu_upload_rows(int vx, int vy, int w, int h, gpu_pixels_fn fn, void *user) {
	gpu_cmd(0xA0000000);
	gpu_cmd(((uint32_t) vy << 16) | (uint16_t) vx);
	gpu_cmd(((uint32_t) h << 16) | (uint16_t) w);
	for (int y = 0; y < h; y++)
		for (int x = 0; x < w; x += 2)
			GPU_GP0 = fn(user, x, y);
}

void gpu_draw_sprite16(RenderContext *ctx, int z, int x, int y, int w, int h, int page_x, int page_y, int u, int v) {
	// The texture page has to be selected before the sprite is drawn: primitives with a higher Z come first.
	DR_TPAGE *tp = (DR_TPAGE *) gpu_new_primitive(ctx, z + 1, sizeof(DR_TPAGE));
	setDrawTPage(tp, 0, 0, getTPage(2, 0, page_x, page_y));   /* 2 = 16 bit direct colour */

	SPRT *sp = (SPRT *) gpu_new_primitive(ctx, z, sizeof(SPRT));
	setSprt(sp);
	setXY0(sp, x, y);
	setWH(sp, w, h);
	setUV0(sp, u, v);
	setClut(sp, 0, 0);
	setRGB0(sp, GPU_FADE(128), GPU_FADE(128), GPU_FADE(128));          /* neutral: texture colours unchanged */
}

void gpu_draw_stretched16(RenderContext *ctx, int z, int x, int y, int w, int h, int dw, int page_x, int page_y) {
	POLY_FT4 *q = (POLY_FT4 *) gpu_new_primitive(ctx, z, sizeof(POLY_FT4));
	setPolyFT4(q);
	setXY4(q, x, y, x + dw, y, x, y + h, x + dw, y + h);
	// texels w and h are the (white) padding that qr_view_upload writes, so the edges sample cleanly
	setUV4(q, 0, 0, w, 0, 0, h, w, h);
	q->tpage = getTPage(2, 0, page_x, page_y);
	q->clut  = 0;
	setRGB0(q, GPU_FADE(128), GPU_FADE(128), GPU_FADE(128));
}

void *gpu_new_primitive(RenderContext *ctx, int z, size_t size) {
	// Place the primitive after all previously allocated primitives, then
	// insert it into the OT and bump the allocation pointer.
	RenderBuffer *buffer = &(ctx->buffers[ctx->active_buffer]);
	uint8_t      *prim   = ctx->next_packet;

	addPrim(&(buffer->ot[z]), prim);
	ctx->next_packet += size;

	// Make sure we haven't yet run out of space for future primitives.
	assert(ctx->next_packet <= &(buffer->buffer[GPU_BUFFER_LENGTH]));

	return (void *) prim;
}

void gpu_draw_rect(RenderContext *ctx, int z, int x, int y, int w, int h, int r, int g, int b) {
	TILE *tile = (TILE *) gpu_new_primitive(ctx, z, sizeof(TILE));
	setTile(tile);
	setXY0 (tile, x, y);
	setWH  (tile, w, h);
	setRGB0(tile, GPU_FADE(r), GPU_FADE(g), GPU_FADE(b));
}
