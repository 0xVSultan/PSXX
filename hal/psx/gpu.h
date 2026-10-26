#pragma once
/* Polled GPU layer for the PSX HAL.
 *
 * Does not use the SDK's draw queue (DrawSync, DrawOTag, PutDrawEnv, LoadImage): when started from a FreePSXBoot
 * card the kernel swallows the DMA2 IRQ and those calls time out. Everything here polls the hardware. */
#include <stddef.h>
#include <stdint.h>
#include <psxgpu.h>

#define GPU_OT_LENGTH 16
#define GPU_BUFFER_LENGTH 8192
#define GPU_XRES 640

typedef struct {
	DISPENV disp_env;
	DRAWENV draw_env;

	uint32_t ot[GPU_OT_LENGTH];
	uint8_t  buffer[GPU_BUFFER_LENGTH];
} RenderBuffer;

typedef struct {
	RenderBuffer buffers[2];
	uint8_t      *next_packet;
	int          active_buffer;
	int          yres;              /* 256 on PAL, 240 on NTSC */
} RenderContext;

/* ResetGraph and a double buffered context with the given background colour. Text: see font.h. */
void gpu_init(RenderContext *ctx, int r, int g, int b);
/* Finish the frame: draw the primitives queued since the last flip and show the previous frame.
 * wait_vblank != 0 blocks until the next vertical blank (tear free pacing); 0 returns as soon as the GPU is idle. */
void gpu_flip(RenderContext *ctx, int wait_vblank);

/* Low latency variant: draw the queued primitives and show them right away (no frame of delay), once the GPU is
 * done. Call it just after a vertical blank so the switch happens before the picture starts, e.g. when
 * VSync(-1) changed. */
void gpu_present(RenderContext *ctx);

/* Upload a w x h block of 16 bit pixels (w even) to VRAM at (vx, vy). `fn` returns two pixels packed as
 * (pixel(x, y) | pixel(x + 1, y) << 16) for the pair starting at (x, y). Polled, no DMA. Call while the GPU is idle
 * (between gpu_present()/gpu_flip() and the next drawing). */
typedef uint32_t (*gpu_pixels_fn)(void *user, int x, int y);
void gpu_upload_rows(int vx, int vy, int w, int h, gpu_pixels_fn fn, void *user);

/* Draw a w x h sprite (w, h <= 256) from a 16 bit texture whose texture page is at (page_x, page_y) in VRAM
 * (page_x a multiple of 64) and whose top-left texel is (u, v) within the page. Uses z and z + 1. */
void gpu_draw_sprite16(RenderContext *ctx, int z, int x, int y, int w, int h, int page_x, int page_y, int u, int v);

/* Same as gpu_draw_sprite16, but stretched to dw x h on screen (dw a multiple of w, for the 2:1 pixel aspect of
 * the 640 wide mode). A textured quad with its own texture page; uses z only. */
void gpu_draw_stretched16(RenderContext *ctx, int z, int x, int y, int w, int h, int dw, int page_x, int page_y);

void *gpu_new_primitive(RenderContext *ctx, int z, size_t size);
void gpu_draw_rect(RenderContext *ctx, int z, int x, int y, int w, int h, int r, int g, int b);

/* A global fade: every colour the primitives of this layer, the font and the coin / dice textures are drawn with is scaled by
 * gpu_fade / 256 (256 = unchanged, 0 = black), the background colour with it. gpu_set_fade() sets it. */
extern int gpu_fade;
#define GPU_FADE(c) (((c) * gpu_fade) >> 8)
void gpu_set_fade(RenderContext *ctx, int fade);
