#pragma once
#include <stdint.h>
#include "gpu.h"

/* The disc picture of the CD seek test. The disc is drawn to scale: the data area of a CD is a ring in which the
 * written sectors fill the area from the inside out, so the radius follows the square root of the sector number.
 * The capacity is 80 minutes (360000 sectors, 737 MB of mode 1 data) or the disc's own length if that is longer. The
 * written part (golden rings, one ring per CDV_RING_MB megabytes) is clearly separated from the empty part (dark).
 * A crosshair wanders over the written area; where it is when the button is pressed picks the sector to seek to.
 *
 * VRAM: a 16 bit texture at (640, 0), the page the QR code uses (it is uploaded again when the QR code is shown). */

#define CDV_TEX 156                    /* texture size in pixels, drawn twice as wide (640 wide mode) */
#define CDV_RING_MB 50
#define CDV_SECTOR_BYTES 2048

/* Compute the geometry for a disc whose written area ends at `leadout` (absolute sector), upload the texture (GPU idle)
 * and put the crosshair somewhere. */
void cdview_init(uint32_t leadout);
/* Move the crosshair one frame. */
void cdview_step(void);
/* Draw the disc with its top-left corner at (x, y) and the crosshair on it. Uses z 6..8. */
void cdview_draw(RenderContext *ctx, int x, int y);
/* Absolute sector under the crosshair, and the crosshair's radius (1/16 pixel) and angle (65536 = turn). */
uint32_t cdview_target(void);
void cdview_pos(uint16_t *r, uint16_t *a);
/* Sizes in sectors: capacity of the picture and the written part (both without the 150 sector lead-in offset). */
uint32_t cdview_capacity(void);
uint32_t cdview_used(void);
