/* Layout test for FreePSXBoot cards: the hello world, plus a large uninitialised array so that the program's BSS
 * reaches higher RAM addresses. Used to find out whether the end address of the image matters. */
#include <stdio.h>
#include "gpu.h"
#include "font.h"

#ifndef BSS_KB
#define BSS_KB 24
#endif

static volatile unsigned char big[BSS_KB * 1024];

int main(void) {
	RenderContext ctx;
	int x = 0, y = 0, dx = 1, dy = 1;

	printf("bss_test: big at %p, %d KB\n", (void *) big, BSS_KB);
	big[0] = 1;
	big[sizeof big - 1] = 2;
	gpu_init(&ctx, 63, 0, 127);
	font_init(1);
	printf("bss_test: gpu ok\n");

	for (;;) {
		if (x < 0 || x > (GPU_XRES - 64)) dx = -dx;
		if (y < 0 || y > (ctx.yres - 64)) dy = -dy;
		x += dx; y += dy;
		gpu_draw_rect(&ctx, 1, x, y, 64, 64, 255, 255, 0);
		font_draw(&ctx, 0, 8, 16, "BSS TEST OK", 255, 255, 255);
		gpu_flip(&ctx, 1);
	}
	return 0;
}
