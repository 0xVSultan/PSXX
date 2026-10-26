#pragma once
#include "gpu.h"
#include "qr.h"

/* Shows a QR code as one 16 bit sprite: the modules (scaled, with a 4 module quiet zone) are written into a VRAM
 * texture page at (640, 0) once, then drawn with a single primitive per frame. */

/* Pixel scale used for this code so that it fits in about 190 pixels (clamped to 2..5). */
int qr_view_scale(const qr_code *qr);
/* Width/height of the texture in pixels including the quiet zone (at most 256); on screen it is drawn twice as wide. */
int qr_view_pixels(const qr_code *qr, int scale);
/* Render into VRAM. Call while the GPU is idle (between frames). */
void qr_view_upload(const qr_code *qr, int scale);
/* Queue the sprite with its top-left corner at (x, y). */
void qr_view_draw(RenderContext *ctx, int z, int x, int y, const qr_code *qr, int scale);
/* Overwrite the texture page with zeros: a secret QR code must not stay in VRAM. */
void qr_view_clear(void);
