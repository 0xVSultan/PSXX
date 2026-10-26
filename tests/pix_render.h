/* The pixel renderer of the host previews (tests/kb_preview.c, tests/pix_stubs.c): what the screens hand to gpu_draw_rect, font_draw and font_draw_big is queued with its slot and
 * drawn in the order of the console (a higher slot first) into a 640 x 240 picture with the real font and button icons, written as a PNG with the lines doubled (4 : 3).
 * One program includes it once (the stand-ins of the GPU and the font are defined here). */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "font.h"
#include "font_bdf.h"
#include "icons_data.h"

#define W 640
#define H 240

enum { OP_RECT, OP_TEXT, OP_BIG };
typedef struct { int kind, z, seq, x, y, w, h, r, g, b, k; char *s; font_colour_fn col; } op_t;
static op_t ops[8192];
static int nops, frame_no = 16;                  /* VSync: the blinking cursor is on */
static uint8_t fb[H][W][3];

#ifndef PIX_NO_VSYNC
int VSync(int mode) { (void) mode; return frame_no; }
int GetVideoMode(void) { return 0; }
#endif

/* ---- the font ---- */

int font_cell_w(void) { return FONT_BDF_CELL_W; }
int font_cell_h(void) { return FONT_BDF_CELL_H; }

int font_utf8_next(const char **s)
{
	const unsigned char *p = (const unsigned char *) *s;
	int c = *p;
	if (c == 0) return 0;
	if (c < 0x80) { *s += 1; return c; }
	if (c >= 0xC2 && c <= 0xDF && (p[1] & 0xC0) == 0x80) { *s += 2; return ((c & 0x1F) << 6) | (p[1] & 0x3F); }
	if (c >= 0xE0 && c <= 0xEF && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) { *s += 3; return ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); }
	*s += 1;
	return '?';
}
int font_utf8_len(const char *s) { int n = 0; while (font_utf8_next(&s)) n++; return n; }
int font_utf8_encode(char *out, int cp)
{
	if (cp < 0x80) { out[0] = (char) cp; return 1; }
	if (cp < 0x800) { out[0] = (char) (0xC0 | (cp >> 6)); out[1] = (char) (0x80 | (cp & 0x3F)); return 2; }
	out[0] = (char) (0xE0 | (cp >> 12)); out[1] = (char) (0x80 | ((cp >> 6) & 0x3F)); out[2] = (char) (0x80 | (cp & 0x3F));
	return 3;
}

static int glyph_of(int cp)
{
	int base = 0;
	if (cp >= 0x20 && cp <= 0x7E) return cp - 0x20;
	if (cp == 0xA0) return 0;
	for (int r = 0; r < FONT_NRUNS; base += FONT_RUNS[r++][1])
		if ((unsigned) (cp - FONT_RUNS[r][0]) < FONT_RUNS[r][1]) return base + cp - FONT_RUNS[r][0];
	return -1;
}

int font_width(const char *s)
{
	int w = 0, cp;
	while ((cp = font_utf8_next(&s)) != 0) w += (cp >= 1 && cp <= ICON_COUNT) ? ICON_RECT[cp - 1].w + 2 : FONT_BDF_CELL_W;
	return w;
}

static void add(int kind, int z, int x, int y, int w, int h, int r, int g, int b, int k, const char *s, font_colour_fn col)
{
	op_t *o;
	if (nops >= 8192) return;
	o = &ops[nops];
	o->kind = kind; o->z = z; o->seq = nops; o->x = x; o->y = y; o->w = w; o->h = h; o->r = r; o->g = g; o->b = b; o->k = k;
	o->s = s ? strdup(s) : NULL;
	o->col = col;
	nops++;
}

void gpu_draw_rect(RenderContext *c, int z, int x, int y, int w, int h, int r, int g, int b) { (void) c; add(OP_RECT, z, x, y, w, h, r, g, b, 0, NULL, NULL); }
void font_draw(RenderContext *c, int z, int x, int y, const char *s, int r, int g, int b) { (void) c; add(OP_TEXT, z, x, y, 0, 0, r, g, b, 0, s, NULL); }
void font_draw_big(RenderContext *c, int z, int x, int y, const char *s, int k, font_colour_fn col, void *user)
{
	(void) c; (void) user;
	add(OP_BIG, z, x, y, 0, 0, 0, 0, 0, k, s, col);
}

/* ---- the picture ---- */

static void put(int x, int y, int r, int g, int b)
{
	if (x < 0 || y < 0 || x >= W || y >= H) return;
	fb[y][x][0] = (uint8_t) r; fb[y][x][1] = (uint8_t) g; fb[y][x][2] = (uint8_t) b;
}

static void fill(int x, int y, int w, int h, int r, int g, int b)
{
	for (int j = 0; j < h; j++) for (int i = 0; i < w; i++) put(x + i, y + j, r, g, b);
}

static int lit(int gi, int x, int y) { return (FONT_BDF[gi][y] >> (15 - x)) & 1; }

static const uint8_t ROW_Y[4] = {1, 5, 10, 14};      /* as in hal/psx/font.c */
static void draw_text(const op_t *o)
{
	const char *s = o->s;
	int x = o->x, cp;
	while ((cp = font_utf8_next(&s)) != 0) {
		if (cp >= 1 && cp <= ICON_COUNT) {
			int n = cp - 1, w = ICON_RECT[n].w, h = ICON_RECT[n].h, y0 = o->y + (FONT_BDF_CELL_H - h) / 2;
			for (int j = 0; j < h; j++)
				for (int i = 0; i < w; i++) {
					uint16_t v = ICON_PAL[ICON_PIX[(ICON_RECT[n].y + j) * ICONS_W + ICON_RECT[n].x + i]];
					if (v) put(x + i, y0 + j, (v & 31) << 3, ((v >> 5) & 31) << 3, ((v >> 10) & 31) << 3);
				}
			x += w + 2;
			continue;
		}
		int gi;
		if (cp >= 0x2800 && cp <= 0x28FF) {                 /* braille: the dots as hal/psx/font.c draws them */
			for (int n = 0; n < 8; n++) {
				const int col = n < 6 ? n / 3 : n - 6, row = n < 6 ? n % 3 : 3;
				if ((cp - 0x2800) >> n & 1) fill(x + 1 + 5 * col, o->y + ROW_Y[row], 3, 2, o->r, o->g, o->b);
			}
			x += FONT_BDF_CELL_W;
			continue;
		}
		gi = glyph_of(cp);
		if (gi < 0) gi = '?' - 0x20;
		if (cp != ' ' && cp != 0xA0)
			for (int j = 0; j < FONT_BDF_CELL_H; j++)
				for (int i = 0; i < FONT_BDF_CELL_W; i++)
					if (lit(gi, i, j)) put(x + i, o->y + j, o->r, o->g, o->b);
		x += FONT_BDF_CELL_W;
	}
}

static void draw_big(const op_t *o)
{
	const char *s = o->s;
	int x = o->x, cp;
	while ((cp = font_utf8_next(&s)) != 0) {
		int gi = glyph_of(cp);
		if (gi < 0) gi = '?' - 0x20;
		if (cp != ' ' && cp != 0xA0)
			for (int j = 0; j < FONT_BDF_CELL_H; j++) {
				uint8_t rgb[3];
				o->col(o->y + j * o->k, rgb, NULL);
				for (int i = 0; i < FONT_BDF_CELL_W; i++)
					if (lit(gi, i, j)) fill(x + i * 2 * o->k, o->y + j * o->k, 2 * o->k, o->k, rgb[0], rgb[1], rgb[2]);
			}
		x += FONT_BDF_CELL_W * 2 * o->k;
	}
}

static int by_slot(const void *a, const void *b)
{
	const op_t *p = a, *q = b;
	return p->z != q->z ? q->z - p->z : p->seq - q->seq;      /* a higher slot is drawn first */
}

static void render(void)
{
	qsort(ops, (size_t) nops, sizeof ops[0], by_slot);
	for (int y = 0; y < H; y++) for (int x = 0; x < W; x++) { fb[y][x][0] = 18; fb[y][x][1] = 18; fb[y][x][2] = 64; }
	for (int i = 0; i < nops; i++) {
		const op_t *o = &ops[i];
		if (o->kind == OP_RECT) fill(o->x, o->y, o->w, o->h, o->r, o->g, o->b);
		else if (o->kind == OP_TEXT) draw_text(o);
		else draw_big(o);
		free(o->s);
	}
	nops = 0;
}

/* ---- PNG: no compression (stored blocks), the lines doubled ---- */

static uint32_t crc_tab[256];
static uint32_t crc32(uint32_t c, const uint8_t *d, size_t n)
{
	if (!crc_tab[1]) for (uint32_t i = 0; i < 256; i++) { uint32_t v = i; for (int k = 0; k < 8; k++) v = v & 1 ? 0xEDB88320u ^ (v >> 1) : v >> 1; crc_tab[i] = v; }
	c = ~c;
	while (n--) c = crc_tab[(c ^ *d++) & 255] ^ (c >> 8);
	return ~c;
}

static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) (v >> 24); p[1] = (uint8_t) (v >> 16); p[2] = (uint8_t) (v >> 8); p[3] = (uint8_t) v; }

static void chunk(FILE *f, const char *type, const uint8_t *d, size_t n)
{
	uint8_t h[8], *all = malloc(n + 4);
	be32(h, (uint32_t) n);
	memcpy(h + 4, type, 4);
	fwrite(h, 1, 8, f);
	if (n) fwrite(d, 1, n, f);
	memcpy(all, type, 4);                                 /* the CRC covers the type and the data */
	if (n) memcpy(all + 4, d, n);
	be32(h, crc32(0, all, n + 4));
	free(all);
	fwrite(h, 1, 4, f);
}

static void write_png(const char *path)
{
	const int ph = H * 2, row = 1 + W * 3;
	size_t raw = (size_t) row * ph, nb = (raw + 65534) / 65535, z = 2 + raw + nb * 5 + 4, o = 0, pos = 0;
	uint8_t *rawd = malloc(raw), *zd = malloc(z), ihdr[13];
	uint32_t a = 1, b = 0;
	FILE *f = fopen(path, "wb");

	if (!f) { perror(path); exit(1); }
	for (int y = 0; y < ph; y++) { rawd[(size_t) y * row] = 0; memcpy(rawd + (size_t) y * row + 1, fb[y / 2], W * 3); }
	zd[o++] = 0x78; zd[o++] = 0x01;
	while (pos < raw) {
		size_t n = raw - pos > 65535 ? 65535 : raw - pos;
		zd[o++] = pos + n == raw; zd[o++] = (uint8_t) n; zd[o++] = (uint8_t) (n >> 8); zd[o++] = (uint8_t) ~n; zd[o++] = (uint8_t) (~n >> 8);
		memcpy(zd + o, rawd + pos, n);
		o += n; pos += n;
	}
	for (size_t i = 0; i < raw; i++) { a = (a + rawd[i]) % 65521; b = (b + a) % 65521; }
	be32(zd + o, (b << 16) | a); o += 4;
	be32(ihdr, W); be32(ihdr + 4, (uint32_t) ph); ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = ihdr[11] = ihdr[12] = 0;
	fwrite("\x89PNG\r\n\x1a\n", 1, 8, f);
	chunk(f, "IHDR", ihdr, 13);
	chunk(f, "IDAT", zd, o);
	chunk(f, "IEND", NULL, 0);
	fclose(f);
	free(rawd); free(zd);
}

