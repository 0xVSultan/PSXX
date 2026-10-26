/*
 * PSX hello world, used to verify booting from a FreePSXBoot memory card.
 * Adapted from the PSn00bSDK basic graphics example (C) 2020-2023 Lameguy64, spicyjpeg - MPL licensed.
 * All GPU access goes through the polled layer in gpu.c (see there for why).
 */
#include "gpu.h"
#include "font.h"

int main(int argc, const char **argv) {
	RenderContext ctx;
	gpu_init(&ctx, 63, 0, 127);
	font_init(1);

	int x  = 0, y  = 0;
	int dx = 1, dy = 1;

	for (;;) {
		// Update the position and velocity of the bouncing square.
		if (x < 0 || x > (GPU_XRES - 64))
			dx = -dx;
		if (y < 0 || y > (ctx.yres - 64))
			dy = -dy;

		x += dx;
		y += dy;

		// Square at Z = 1, text in front of it (Z = 0; primitives with higher Z are drawn first).
		gpu_draw_rect(&ctx, 1, x, y, 64, 64, 255, 255, 0);
		font_draw(&ctx, 0, 8, 16, "Hello world!", 255, 255, 255);

		gpu_flip(&ctx, 1);
	}

	return 0;
}
