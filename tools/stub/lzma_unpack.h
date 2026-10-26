/* Minimal LZMA1 decoder for the self-extracting stub (tools/packexe.py) and its host test (lzma_test.c).
 *
 * Raw LZMA stream as made by liblzma (FORMAT_RAW, FILTER_LZMA1) with fixed lc / lp / pb; the output size is known, so an
 * end marker, if present, is ignored. The output buffer doubles as the dictionary (no wrap around, no separate window).
 * No libc, no division, no 64 bit arithmetic; the probability array (LZMA_PROBS 16 bit entries) is supplied by the caller.
 * The input is trusted (the packer verifies it), so nothing is bounds checked.
 *
 * With LZMA_DICT defined (the decoder of the program, core/pkg/ovl.c), lzma_unpack() takes the properties byte ((pb * 5 + lp) * 9 + lc, lc + lp <= 4: probs has
 * LZMA_PROBS_MAX entries) instead of the fixed LZMA_LC / LZMA_LP / LZMA_PB, and a preset dictionary (liblzma's preset_dict): the bytes dict[0..dict_len) stand before
 * the output, a match may reach back into them, and the last of them is the byte before the first one. The positions are counted from the start of the output here
 * and from the start of the dictionary by liblzma, so dict_len has to be a multiple of 1 << max(lp, pb). The caller checks both. The stub is built without it. */
#pragma once
#include <stdint.h>

#ifndef LZMA_TICK
#define LZMA_TICK() ((void) 0)          /* a hook run once per decoded symbol (the stub's time measurement) */
#endif

#ifndef LZMA_LC
#define LZMA_LC 2
#define LZMA_LP 0
#define LZMA_PB 1
#endif

#define LZ_LEN_SIZE (2 + 16 * 8 + 16 * 8 + 256)
#define LZ_IS_MATCH 0
#define LZ_IS_REP (LZ_IS_MATCH + (12 << 4))
#define LZ_REP_G0 (LZ_IS_REP + 12)
#define LZ_REP_G1 (LZ_REP_G0 + 12)
#define LZ_REP_G2 (LZ_REP_G1 + 12)
#define LZ_REP0_LONG (LZ_REP_G2 + 12)
#define LZ_POS_SLOT (LZ_REP0_LONG + (12 << 4))
#define LZ_POS_DEC (LZ_POS_SLOT + (4 << 6))
#define LZ_ALIGN (LZ_POS_DEC + 115)
#define LZ_LEN (LZ_ALIGN + 16)
#define LZ_REP_LEN (LZ_LEN + LZ_LEN_SIZE)
#define LZ_LIT (LZ_REP_LEN + LZ_LEN_SIZE)
#define LZMA_PROBS (LZ_LIT + (0x300 << (LZMA_LC + LZMA_LP)))
#define LZMA_PROBS_MAX (LZ_LIT + (0x300 << 4))

typedef struct { const uint8_t *in; uint32_t range, code; } lz_rc;

static int lz_bit(lz_rc *rc, uint16_t *p)
{
	uint32_t bound = (rc->range >> 11) * *p;
	int b;

	if (rc->code < bound) { rc->range = bound; *p = (uint16_t) (*p + ((2048 - *p) >> 5)); b = 0; }
	else { rc->range -= bound; rc->code -= bound; *p = (uint16_t) (*p - (*p >> 5)); b = 1; }
	if (rc->range < (1u << 24)) { rc->range <<= 8; rc->code = (rc->code << 8) | *rc->in++; }
	return b;
}

static unsigned lz_tree(lz_rc *rc, uint16_t *probs, int nbits)
{
	unsigned m = 1;
	for (int i = 0; i < nbits; i++) m = (m << 1) | (unsigned) lz_bit(rc, &probs[m]);
	return m - (1u << nbits);
}

static unsigned lz_rtree(lz_rc *rc, uint16_t *probs, int nbits)
{
	unsigned m = 1, sym = 0;
	for (int i = 0; i < nbits; i++) {
		unsigned b = (unsigned) lz_bit(rc, &probs[m]);
		m = (m << 1) | b;
		sym |= b << i;
	}
	return sym;
}

static unsigned lz_direct(lz_rc *rc, int n)
{
	unsigned res = 0;
	do {
		uint32_t t;
		rc->range >>= 1;
		rc->code -= rc->range;
		t = 0u - (rc->code >> 31);
		rc->code += rc->range & t;
		res = (res << 1) + (t + 1);
		if (rc->range < (1u << 24)) { rc->range <<= 8; rc->code = (rc->code << 8) | *rc->in++; }
	} while (--n);
	return res;
}

static unsigned lz_len(lz_rc *rc, uint16_t *p, unsigned pos_state)
{
	if (!lz_bit(rc, &p[0])) return lz_tree(rc, &p[2 + (pos_state << 3)], 3);
	if (!lz_bit(rc, &p[1])) return 8 + lz_tree(rc, &p[2 + 128 + (pos_state << 3)], 3);
	return 16 + lz_tree(rc, &p[2 + 256], 8);
}

/* the byte `d + 1` places back from the output position, and the byte before the output position */
#ifdef LZMA_DICT
#define LZ_BACK(d) (pos > (d) ? dst[pos - (d) - 1] : dict[dict_len + pos - (d) - 1])
#define LZ_PREV (pos ? dst[pos - 1] : dict_len ? dict[dict_len - 1] : 0)
#else
#define LZ_BACK(d) dst[pos - (d) - 1]
#define LZ_PREV (pos ? dst[pos - 1] : 0)
#endif

/* Decode `dst_size` bytes from `src` to `dst`. Returns 0, or -1 if the stream does not start with the 0 byte. */
#ifdef LZMA_DICT
static int lzma_unpack(const uint8_t *src, uint8_t *dst, uint32_t dst_size, uint16_t *probs, unsigned props, const uint8_t *dict, uint32_t dict_len)
#else
static int lzma_unpack(const uint8_t *src, uint8_t *dst, uint32_t dst_size, uint16_t *probs)
#endif
{
	lz_rc rc;
	uint32_t pos = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
	unsigned state = 0;
#ifdef LZMA_DICT
	const unsigned lc = props % 9, lp = props / 9 % 5, pb = props / 45, nprobs = LZ_LIT + (0x300u << (lc + lp));
#else
	const unsigned lc = LZMA_LC, lp = LZMA_LP, pb = LZMA_PB, nprobs = LZMA_PROBS;
#endif

	if (src[0] != 0) return -1;
	rc.code = ((uint32_t) src[1] << 24) | ((uint32_t) src[2] << 16) | ((uint32_t) src[3] << 8) | src[4];
	rc.range = 0xFFFFFFFFu;
	rc.in = src + 5;
	for (unsigned i = 0; i < nprobs; i++) probs[i] = 1024;

	while (pos < dst_size) {
		unsigned pos_state = pos & ((1u << pb) - 1), len;

		LZMA_TICK();

		if (!lz_bit(&rc, &probs[LZ_IS_MATCH + (state << 4) + pos_state])) {
			uint16_t *lit = &probs[LZ_LIT + 0x300 * ((((pos & ((1u << lp) - 1)) << lc)) + ((unsigned) LZ_PREV >> (8 - lc)))];
			unsigned sym = 1;

			if (state >= 7) {
				unsigned match = LZ_BACK(rep0);
				do {
					unsigned mb = (match >> 7) & 1, b;
					match <<= 1;
					b = (unsigned) lz_bit(&rc, &lit[((1 + mb) << 8) + sym]);
					sym = (sym << 1) | b;
					if (mb != b) break;
				} while (sym < 0x100);
			}
			while (sym < 0x100) sym = (sym << 1) | (unsigned) lz_bit(&rc, &lit[sym]);
			dst[pos++] = (uint8_t) sym;
			state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
			continue;
		}
		if (lz_bit(&rc, &probs[LZ_IS_REP + state])) {
			if (!lz_bit(&rc, &probs[LZ_REP_G0 + state])) {
				if (!lz_bit(&rc, &probs[LZ_REP0_LONG + (state << 4) + pos_state])) {    /* short rep: one byte */
					state = state < 7 ? 9 : 11;
					dst[pos] = LZ_BACK(rep0);
					pos++;
					continue;
				}
			} else {
				uint32_t d;
				if (!lz_bit(&rc, &probs[LZ_REP_G1 + state])) d = rep1;
				else {
					if (!lz_bit(&rc, &probs[LZ_REP_G2 + state])) d = rep2;
					else { d = rep3; rep3 = rep2; }
					rep2 = rep1;
				}
				rep1 = rep0;
				rep0 = d;
			}
			len = lz_len(&rc, &probs[LZ_REP_LEN], pos_state);
			state = state < 7 ? 8 : 11;
		} else {
			unsigned slot;

			rep3 = rep2; rep2 = rep1; rep1 = rep0;
			len = lz_len(&rc, &probs[LZ_LEN], pos_state);
			state = state < 7 ? 7 : 10;
			slot = lz_tree(&rc, &probs[LZ_POS_SLOT + ((len < 4 ? len : 3) << 6)], 6);
			if (slot < 4) rep0 = slot;
			else {
				int nb = (int) (slot >> 1) - 1;
				rep0 = (2 | (slot & 1)) << nb;
				if (slot < 14) rep0 += lz_rtree(&rc, &probs[LZ_POS_DEC + rep0 - slot], nb);
				else {
					rep0 += lz_direct(&rc, nb - 4) << 4;
					rep0 += lz_rtree(&rc, &probs[LZ_ALIGN], 4);
				}
			}
		}
		len += 2;
		for (unsigned i = 0; i < len && pos < dst_size; i++, pos++) dst[pos] = LZ_BACK(rep0);
	}
	return 0;
}
