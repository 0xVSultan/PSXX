/* secp256k1_pubkey_create_uncompressed (fixed base table, signed digits) on the edge cases of tests/secp_fb_vectors.txt */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/secp256k1.h"

static void unhex(const char *s, uint8_t *o, int n) { for (int i = 0; i < n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); o[i] = (uint8_t) v; } }

int main(int argc, char **argv)
{
	FILE *f = fopen(argc > 1 ? argv[1] : "tests/secp_fb_vectors.txt", "r");
	char kh[80], ph[200];
	int total = 0, bad = 0, last = -1, steps = 0, pr;

	do {                                   /* the table in steps, as the start screen builds it: the progress only grows */
		pr = secp256k1_table_step();
		if (pr < last || pr > 100) bad++;
		last = pr;
		steps++;
	} while (pr < 100 && steps < 1000);
	if (steps < 50 || steps > 100) { bad++; printf("unexpected number of steps: %d\n", steps); }

	if (!f) { printf("cannot open the vector file\n"); return 2; }
	while (fscanf(f, "%79s %199s", kh, ph) == 2) {
		uint8_t k[32], want[65], got[65];
		unhex(kh, k, 32);
		unhex(ph, want, 65);
		total++;
		if (secp256k1_pubkey_create_uncompressed(got, k) || memcmp(got, want, 65)) { bad++; printf("FAIL k=%s\n", kh); }
	}
	printf("secp256k1 fixed base: %d vectors, %d failures\n", total, bad);
	return bad != 0;
}
