/* bn_mul_wide_comba / bn_sqr_wide_comba (core/ec/bn_comba.h) against the schoolbook loops, on random and edge values */
#include <stdio.h>
#include <string.h>
#include "ec/bn.h"
#include "ec/bn_comba.h"

static void ref_mul(uint32_t t[16], const uint32_t a[8], const uint32_t b[8])
{
	for (int i = 0; i < 16; i++) t[i] = 0;
	for (int i = 0; i < 8; i++) {
		uint32_t carry = 0;
		for (int j = 0; j < 8; j++) {
			uint64_t u = (uint64_t) a[i] * b[j] + t[i + j] + carry;
			t[i + j] = (uint32_t) u;
			carry = (uint32_t) (u >> 32);
		}
		t[i + 8] = carry;
	}
}

static uint32_t x = 0x2545F491u;
static uint32_t rnd(void) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x; }

int main(void)
{
	uint32_t a[8], b[8], r[16], c[16], s[16];
	int bad = 0;

	for (int n = 0; n < 200000; n++) {
		for (int i = 0; i < 8; i++) {
			int mode = n % 5;
			a[i] = mode == 0 ? 0xFFFFFFFFu : mode == 1 ? (rnd() & 1 ? 0xFFFFFFFFu : 0) : rnd();
			b[i] = mode == 0 ? 0xFFFFFFFFu : mode == 2 ? (rnd() & 1 ? 0xFFFFFFFFu : 0x80000000u) : rnd();
		}
		ref_mul(r, a, b);
		bn_mul_wide_comba(c, a, b);
		if (memcmp(r, c, sizeof r)) bad++;
		ref_mul(r, a, a);
		bn_sqr_wide_comba(s, a);
		if (memcmp(r, s, sizeof r)) bad++;
	}
	printf("bn comba: %d mismatches\n", bad);
	return bad != 0;
}
