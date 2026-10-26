/* Prints the UR parts of a hex input for tests/test_ur.py:  test_ur <max_frag> <hexdata> [parts to print] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ur.h"
int main(int argc, char **argv)
{
	static uint8_t d[8192];
	char out[1024];
	if (argc < 3) return 2;
	size_t n = strlen(argv[2]) / 2;
	for (size_t i = 0; i < n; i++) { unsigned v; sscanf(argv[2] + 2 * i, "%2x", &v); d[i] = (uint8_t) v; }
	ur_plan p;
	int parts = ur_plan_make(&p, d, n, (size_t) atoi(argv[1]));
	if (parts < 0) return 1;
	unsigned cnt = argc > 3 ? (unsigned) atoi(argv[3]) : (unsigned) parts;
	printf("%d %zu %zu\n", parts, p.cbor_len, ur_part_chars(&p));
	for (unsigned s = 1; s <= cnt; s++) {
		int r = ur_part(&p, d, s, out, sizeof out);
		if (r < 0 || (size_t) r > ur_part_chars(&p)) return 3;
		puts(out);
	}
	return 0;
}
