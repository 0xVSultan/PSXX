#pragma once
#include "gpu.h"

/* Dice faces 1..6 of the dice roll screen: 64 x 64 texel 4 bit textures (made by dice.c at start-up: no stored data), drawn as a
 * textured quad of any size (on the 640 wide screen a 2:1 wide quad looks square).
 * VRAM: texture page (832, 256) in 4 bit mode, faces at (832 + 16 * ((f - 1) % 3), 256 + 64 * ((f - 1) / 3)), the
 * shared CLUT at (832, 480). */

/* The texel (x, y) 0..63 of face `face` as dice_init uploads it, 0..9 (0 transparent): for tests. */
int dice_texel(int face, int x, int y);
/* Upload the textures. Call once while the GPU is idle, after gpu_init(). */
void dice_init(void);
/* Queue die face `face` (1..6) in the rectangle (x, y, w, h). Uses slot z. */
void dice_draw(RenderContext *ctx, int z, int x, int y, int w, int h, int face);
