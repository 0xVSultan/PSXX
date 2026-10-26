/* Host test for lzma_unpack.h: lzma_test <stream> <expected image> (built with -DLZMA_DICT: lzma_test <stream> <expected image> <preset dictionary> [props byte],
 * the props byte (pb * 5 + lp) * 9 + lc of the stream, default LZMA_LC, LZMA_LP, LZMA_PB).
 * Exit code 0 = the decoder reproduces the image. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lzma_unpack.h"

static uint8_t *slurp(const char *path, long *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	*n = ftell(f);
	fseek(f, 0, SEEK_SET);
	p = malloc((size_t) *n + 16);
	if (p && fread(p, 1, (size_t) *n, f) != (size_t) *n) p = NULL;
	fclose(f);
	return p;
}

int main(int argc, char **argv)
{
	long cn, in_;
	uint8_t *c, *img, *out;
	uint16_t *probs;

	if (argc < 3 || !(c = slurp(argv[1], &cn)) || !(img = slurp(argv[2], &in_))) return 2;
	out = calloc((size_t) in_ + 16, 1);
	probs = malloc(LZMA_PROBS_MAX * sizeof *probs);
#ifdef LZMA_DICT
	{
		long dn;
		uint8_t *dict;
		if (argc < 4 || !(dict = slurp(argv[3], &dn))) return 2;
		unsigned props = argc > 4 ? (unsigned) atoi(argv[4]) : (LZMA_PB * 5 + LZMA_LP) * 9 + LZMA_LC;
		if (lzma_unpack(c, out, (uint32_t) in_, probs, props, dict, (uint32_t) dn)) return 3;
	}
#else
	if (lzma_unpack(c, out, (uint32_t) in_, probs)) return 3;
#endif
	return memcmp(out, img, (size_t) in_) ? 1 : 0;
}
