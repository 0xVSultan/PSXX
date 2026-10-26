/* ed25519_scalarmult_base (fixed base table, signed digits) on the edge cases of tests/ed_fb_vectors.txt */
#include <stdio.h>
#include <string.h>
#include "ec/ed25519.h"

static void unhex(const char *s, uint8_t *o, int n) { for (int i = 0; i < n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); o[i] = (uint8_t) v; } }

int main(int argc, char **argv)
{
	FILE *f = fopen(argc > 1 ? argv[1] : "tests/ed_fb_vectors.txt", "r");
	char kh[80], ph[80];
	int total = 0, bad = 0, last = -1, steps = 0, pr;

	do {                                   /* the table in steps, as the start screen builds it: the progress only grows */
		pr = ed25519_table_step();
		if (pr < last || pr > 100) bad++;
		last = pr;
		steps++;
	} while (pr < 100 && steps < 1000);
	if (steps < 50 || steps > 100) { bad++; printf("unexpected number of steps: %d\n", steps); }

	if (!f) { printf("cannot open the vector file\n"); return 2; }
	while (fscanf(f, "%79s %79s", kh, ph) == 2) {
		uint8_t k[32], want[32], got[32];
		unhex(kh, k, 32);
		unhex(ph, want, 32);
		total++;
		ed25519_scalarmult_base(got, k);
		if (memcmp(got, want, 32)) { bad++; printf("FAIL k=%s\n", kh); }
	}
	printf("ed25519 fixed base: %d vectors, %d failures\n", total, bad);
	return bad != 0;
}
