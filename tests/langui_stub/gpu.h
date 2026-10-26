#pragma once
/* host stand-in for hal/psx/gpu.h (tests/test_langui.c, tests/test_screens_a.c, tests/test_screens_b.c): what the screens and the headers they include use */
#include <stddef.h>
#include <stdint.h>

#define GPU_XRES 640

typedef struct { int xres, yres; } RenderContext;
typedef uint32_t (*gpu_pixels_fn)(void *user, int x, int y);

extern int gpu_fade;
#define GPU_FADE(c) (((c) * gpu_fade) >> 8)

void gpu_init(RenderContext *ctx, int r, int g, int b);
void gpu_flip(RenderContext *ctx, int wait_vblank);
void gpu_present(RenderContext *ctx);
void gpu_upload_rows(int vx, int vy, int w, int h, gpu_pixels_fn fn, void *user);
void gpu_draw_sprite16(RenderContext *ctx, int z, int x, int y, int w, int h, int page_x, int page_y, int u, int v);
void gpu_draw_stretched16(RenderContext *ctx, int z, int x, int y, int w, int h, int dw, int page_x, int page_y);
void *gpu_new_primitive(RenderContext *ctx, int z, size_t size);
void gpu_draw_rect(RenderContext *ctx, int z, int x, int y, int w, int h, int r, int g, int b);
void gpu_set_fade(RenderContext *ctx, int fade);
