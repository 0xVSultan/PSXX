/* keccak_f1600 (straight-line, 32 bit pairs, core/hash/keccak_fast.c) against the compact reference loops below; and
 * keccak256 against known digests. */
#include <stdio.h>
#include <string.h>
#include "hash/keccak.h"

#include "keccak_ref.h"

int main(void)
{
	uint64_t a[25], b[25];
	uint32_t x = 0x2545F491u;
	uint8_t d[32];
	int bad = 0;

	for (int n = 0; n < 20000; n++) {
		for (int i = 0; i < 25; i++) {
			uint64_t v = 0;
			for (int k = 0; k < 2; k++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; v = (v << 32) | (n == 0 ? 0 : x); }
			a[i] = b[i] = v;
		}
		ref_f1600(a);
		keccak_f1600(b);
		if (memcmp(a, b, sizeof a)) bad++;
	}
	memset(a, 0, sizeof a);
	memcpy(b, a, sizeof a);
	for (int n = 0; n < 1000; n++) { ref_f1600(a); keccak_f1600(b); }
	if (memcmp(a, b, sizeof a)) bad++;
	{                                                           /* every length around the block boundaries, unaligned inputs */
		static uint8_t buf[600], d1[32], d2[32];
		for (int i = 0; i < 600; i++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; buf[i] = (uint8_t) x; }
		for (size_t off = 0; off < 4; off++)
			for (size_t n = 0; n < 400; n++) {
				keccak256(buf + off, n, d1);
				ref_keccak256(buf + off, n, d2);
				if (memcmp(d1, d2, 32)) bad++;
			}
	}
	keccak256((const uint8_t *) "", 0, d);                    /* the well known digest of the empty string */
	if (d[0] != 0xc5 || d[1] != 0xd2 || d[2] != 0x46 || d[31] != 0x70) bad++;
	printf("keccak: %d mismatches\n", bad);
	return bad != 0;
}
