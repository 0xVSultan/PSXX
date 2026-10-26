#pragma once
#include "gpu.h"

/* The coin of the coin flip screen (coin_data.h, tools/gen_coin.py): the two sides have the same rim, so there is one 112 x 112 texel ring with a hole and two
 * 80 x 80 texel emblems (the crown, the XMR), all 4 bit with one CLUT. A side is two textured quads that are twice as wide as high (the pixels of the 640 wide mode are 2:1):
 * the ring, and the emblem on top of it (the next slot, z - 1).
 * VRAM: texture page (768, 256) in 4 bit mode; the ring at (800, 256), the crown at (800, 368), the XMR at (768, 256); the CLUT at (768, 480). Free area of the layout
 * described in font.h and qr_view.h. */

#define COIN_HEADS_SIDE 0           /* the crown */
#define COIN_TAILS_SIDE 1           /* XMR */
#define COIN_DRAW_W (2 * 112)
#define COIN_DRAW_H 112

/* Upload the textures. Call once while the GPU is idle, after gpu_init(). */
void coin_init(void);
/* Queue the coin centred at (cx, cy), `w` pixels wide (0..COIN_DRAW_W, for the flip), `bright` 0..128. Uses the slots z and z - 1. */
void coin_draw(RenderContext *ctx, int z, int cx, int cy, int w, int side, int bright);
/* The flip animation: frame `step` of `steps` (0..steps), the coin starts on `start_side` and ends on the other
 * side after one and a half turns, bouncing up. Returns via the arguments what to pass to coin_draw. */
/* The shadow on the ground at (cx, gy) of a coin `lift` pixels above it (0..30). Uses the slot z (the polygons and their blend mode), which must be above the coin's. */
void coin_shadow(RenderContext *ctx, int z, int cx, int gy, int lift);
/* The last COIN_BOUNCE_STEPS of the `steps` of the flip are the coin hopping on the spot after it landed. */
#define COIN_BOUNCE_STEPS 12
void coin_flip_frame(int step, int steps, int start_side, int height, int *w, int *dy, int *side);   /* `height`: the toss, in pixels (up to 40: the shadow) */
