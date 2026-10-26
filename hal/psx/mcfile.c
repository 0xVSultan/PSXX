#include "mcfile.h"
#include <string.h>

#define RGB(r, g, b) ((uint16_t) ((r) | ((g) << 5) | ((b) << 10)))

static int fail(int mc) { return mc == MC_NO_CARD ? MCF_NO_CARD : MCF_IO; }

void mcf_name(char out[MCF_NAME], const char *tag, int number)
{
	memcpy(out, "BESCES-00000", 12);
	memcpy(out + 12, tag, 6);
	out[18] = (char) ('0' + number / 10);
	out[19] = (char) ('0' + number % 10);
	out[20] = 0;
}

int mcf_scan_raw(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block, int *free_count, int *nkeys)
{
	uint8_t f[MC_FRAME];
	int r = mc_read(port, 0, f), n = 0;

	*nfiles = 0;
	*next = 1;
	*free_block = 0;
	*free_count = 0;
	*nkeys = 0;
	if (r) return fail(r);
	if (f[0] != 'M' || f[1] != 'C') return MCF_BAD_CARD;               /* not formatted: the BIOS card manager does that */
	for (int b = 1; b <= 15; b++) {
		r = mc_read(port, b, f);
		if (r) return fail(r);
		if ((f[0] & 0xF0) == 0xA0) {                                   /* free (never used or deleted: 0xA0, 0xA1 first, 0xA2 middle, 0xA3 last) */
			if (!*free_block) *free_block = b;
			(*free_count)++;
		}
		if (f[0] == 0x51 && memcmp(f + 22, MCF_KEY_TAG, 6) == 0) (*nkeys)++;
		if ((f[0] & 0xF0) == 0x50 && memcmp(f + 22, tag, 6) == 0 && f[28] >= '0' && f[28] <= '9' && f[29] >= '0' && f[29] <= '9') {
			int num = (f[28] - '0') * 10 + (f[29] - '0');
			if (num + 1 > *next) *next = num + 1;
			if (n < max) {
				out[n].block = b;
				memcpy(out[n].name, f + 10, 20);
				out[n].name[20] = 0;
				n++;
			}
			(*nfiles)++;
		}
	}
	if (*next > 99) *next = 1;
	return MCF_OK;
}

int mcf_scan(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block)
{
	int free_count, nkeys;

	return mcf_scan_raw(port, tag, out, max, nfiles, next, free_block, &free_count, &nkeys);
}

static uint8_t dir_xor(const uint8_t *f) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= f[i]; return x; }

int mcf_invalidate(int port, int block)
{
	uint8_t f[MC_FRAME];
	int chain[15], n = 0, b = block, r;

	if (block < 1 || block > 15) return MCF_NOT_FOUND;
	for (;;) {                                                         /* the chain first, all of it checked before anything is written */
		int next;

		r = mc_read(port, b, f);
		if (r) return fail(r);
		if (dir_xor(f) != f[127]) return MCF_BAD_CARD;
		if (n == 0 ? f[0] != 0x51 : (f[0] != 0x52 && f[0] != 0x53)) return n == 0 ? MCF_NOT_FOUND : MCF_BAD_CARD;
		chain[n++] = b;
		next = f[8] | (f[9] << 8);
		if (next == 0xFFFF) break;
		b = next + 1;
		if (b < 1 || b > 15 || n >= 15) return MCF_BAD_CARD;
		for (int i = 0; i < n; i++) if (chain[i] == b) return MCF_BAD_CARD;
	}
	for (int i = 0; i < n; i++) {                                      /* the first block first: that one write removes the file from the directory */
		r = mc_read(port, chain[i], f);
		if (r) return fail(r);
		f[0] = (uint8_t) (0xA0 | (f[0] & 0x0F));
		f[127] = dir_xor(f);
		r = mc_write(port, chain[i], f);
		if (r) return fail(r);
	}
	return MCF_OK;
}

/* a 16 x 16 icon: a disc (written inside, empty outside) or a padlock; 4 bit pixels, low nibble first */
static void make_icon(uint8_t f[MC_FRAME], int icon)
{
	for (int y = 0; y < 16; y++)
		for (int x = 0; x < 16; x += 2) {
			uint8_t px[2];
			for (int k = 0; k < 2; k++) {
				int xx = x + k, c = 0;
				if (icon == MCF_ICON_DISC) {
					int dx = 2 * xx - 15, dy = 2 * y - 15, d2 = dx * dx + dy * dy;
					if (d2 > 225 || d2 <= 25) c = 0;
					else if (d2 <= 49) c = 3;
					else if (d2 >= 196) c = 2;
					else c = d2 < 130 ? 1 : 4;
				} else {
					if (y >= 7 && y <= 14 && xx >= 3 && xx <= 12) c = (y == 10 && (xx == 7 || xx == 8)) || (y == 11 && (xx == 7 || xx == 8)) ? 3 : 1;
					else if (y >= 1 && y <= 6 && ((xx >= 4 && xx <= 5) || (xx >= 10 && xx <= 11))) c = 2;
					else if (y >= 1 && y <= 2 && xx >= 4 && xx <= 11) c = 2;
				}
				px[k] = (uint8_t) c;
			}
			f[y * 8 + x / 2] = (uint8_t) (px[0] | (px[1] << 4));
		}
}

int mcf_begin(int port, int block, const char *title, int icon)
{
	static const uint16_t PAL[16] = {0, RGB(30, 24, 4), RGB(24, 24, 26), RGB(12, 12, 14), RGB(3, 5, 12)};
	uint8_t f[MC_FRAME];
	int r;

	memset(f, 0, MC_FRAME);
	f[0] = 'S'; f[1] = 'C'; f[2] = 0x11; f[3] = 1;                     /* "SC", one icon frame, one block */
	for (int i = 0; i < 60 && title[i]; i++) f[4 + i] = (uint8_t) title[i];
	for (int i = 0; i < 16; i++) { f[96 + 2 * i] = (uint8_t) PAL[i]; f[97 + 2 * i] = (uint8_t) (PAL[i] >> 8); }
	r = mc_write(port, 64 * block, f);
	if (r) return fail(r);
	memset(f, 0, MC_FRAME);
	make_icon(f, icon);
	r = mc_write(port, 64 * block + 1, f);
	return r ? fail(r) : MCF_OK;
}

int mcf_write(int port, int block, int frame, const uint8_t *data)
{
	int r = mc_write(port, 64 * block + frame, data);
	return r ? fail(r) : MCF_OK;
}

int mcf_read(int port, int block, int frame, uint8_t *data)
{
	int r = mc_read(port, 64 * block + frame, data);
	return r ? fail(r) : MCF_OK;
}

int mcf_commit(int port, int block, const char *tag, int number)
{
	uint8_t f[MC_FRAME], x = 0;
	char name[MCF_NAME];
	int r;

	mcf_name(name, tag, number);
	memset(f, 0, MC_FRAME);
	f[0] = 0x51;                                                       /* in use, first (and only) block */
	f[4] = 0x00; f[5] = 0x20;                                          /* 8192 bytes */
	f[8] = 0xFF; f[9] = 0xFF;                                          /* no next block */
	memcpy(f + 10, name, 20);
	for (int i = 0; i < 127; i++) x ^= f[i];
	f[127] = x;
	r = mc_write(port, block, f);
	return r ? fail(r) : MCF_OK;
}
