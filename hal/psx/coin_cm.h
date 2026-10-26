#pragma once
/* The coin textures as one stream of a context model: the ring (112 x 112 texels), then the two emblems (80 x 80), row
 * by row. A texel is its 4 bit CLUT index, the high bit first; every bit has a probability of its own for the texel to the left, the texel above and the bits of this
 * texel so far (16 x 16 x 16 of them), adapted at a rate of 1 / (n + 2) the n-th time, at most 1 / 32. The range coder is the one of LZMA with 16 bit probabilities; the
 * first byte of the stream (always 0) is left out. The work memory is 12 KB (p: 4096 x 16 bit, n: 4096 bytes). Nothing here is specific to the PSX (tests/test_coin.c). */
#include <stdint.h>

#define COIN_CM_CTX 4096

typedef struct { const uint8_t *in; uint32_t range, code; } coin_rc;

static unsigned coin_cm_bit(coin_rc *r, uint16_t *p, uint8_t *n, unsigned k)
{
	uint32_t q = p[k], bound = (r->range >> 16) * q;
	unsigned c = n[k], d = (c < 30 ? c : 30) + 2, b;

	if (r->code < bound) { r->range = bound; p[k] = (uint16_t) (q + (65536 - q) / d); b = 0; }
	else { r->code -= bound; r->range -= bound; p[k] = (uint16_t) (q - q / d); b = 1; }
	if (c < 30) n[k] = (uint8_t) (c + 1);
	while (r->range < (1u << 24)) { r->range <<= 8; r->code = (r->code << 8) | *r->in++; }
	return b;
}

/* the `count` images of the sizes wh[2 i] x wh[2 i + 1], one after the other, to out: one texel per byte */
static void coin_cm_decode(const uint8_t *src, const uint8_t *wh, int count, uint8_t *out, uint16_t *p, uint8_t *n)
{
	coin_rc r = {src + 4, 0xFFFFFFFFu, (uint32_t) src[0] << 24 | (uint32_t) src[1] << 16 | (uint32_t) src[2] << 8 | src[3]};

	for (unsigned i = 0; i < COIN_CM_CTX; i++) { p[i] = 32768; n[i] = 0; }
	for (; count > 0; count--, wh += 2) {
		int w = wh[0], h = wh[1];
		for (int y = 0; y < h; y++)
			for (int x = 0; x < w; x++, out++) {
				unsigned c = ((x ? (unsigned) out[-1] : 0u) << 4 | (y ? (unsigned) out[-w] : 0u)) << 4, node = 1;
				for (int b = 0; b < 4; b++) node = node << 1 | coin_cm_bit(&r, p, n, c + node);
				*out = (uint8_t) (node & 15);
			}
	}
}
