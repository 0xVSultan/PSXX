/* the 32 bit pair SHA-512 compression functions (loop and unrolled) against the plain 64 bit one, on random states and blocks */
#include <stdio.h>
#include <string.h>
#include "hash/sha512.h"
#include "sha512_ref.h"

static uint32_t x = 0x2545F491u;
static uint32_t rnd(void) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; }

int main(void)
{
	uint64_t h0[8], h1[8], h2[8];
	uint8_t p[128];
	int bad = 0;

	for (int n = 0; n < 20000; n++) {
		for (int i = 0; i < 8; i++) h0[i] = h1[i] = h2[i] = n == 0 ? ~0ULL : n == 1 ? 0 : ((uint64_t) rnd() << 32) | rnd();
		for (int i = 0; i < 128; i++) p[i] = n == 0 ? 0xFF : (uint8_t) rnd();
		ref_sha512_block(h0, p);
		sha512_block_loop(h1, p);
		sha512_block_x8(h2, p);
		if (memcmp(h0, h1, sizeof h0)) bad++;
		if (memcmp(h0, h2, sizeof h0)) bad++;
	}
	printf("sha512 block: %d mismatches\n", bad);
	return bad != 0;
}
