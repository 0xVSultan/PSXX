/* The memory probe: which main RAM does the BIOS write while a program of ours runs, and which RAM is really free for the whole
 * life of the program? The answer decides whether the big tables and the overlays may live outside the span 0x80110000 .. 0x80180000 and the overlay region.
 *
 * Method: in three windows of the main RAM (below the BIOS shell, above the shell up to our image, above our image up to the stack) every block of 256 bytes that is all zero at the start
 * is filled with a pattern (address xor 0xA5A5A5A5); blocks that hold something already are the live memory of the BIOS and are left alone ("busy"). The program then does what our
 * applications do (idle, buttons, memory cards, the screen, the CD drive, long computation, writing a file to a card) and after each stage every pattern block is compared: a block that
 * changed was written by somebody (the BIOS, an interrupt handler, the drivers), and the stage in which it was first seen is remembered. A block that never changed is free in the
 * sense that matters: nothing of the BIOS used it in the whole run, in these situations. The result is a map of the whole RAM on the screen, a report on the TTY ([mem] lines) and
 * a file PSXXMP.. on the card in slot 2 (read it with tools/memprobe_read.py). The BIOS is identified by the version string and the CRC-32 of its ROM.
 *
 * It writes nothing to the RAM that was not zero, and nothing to the card except the report (one block, at the end of the run and again after the last stage).
 *
 *   CROSS  start the run     START  another round of the stages (a "restart": the numbers of the stages go on)     TRIANGLE  write the report again     SELECT  the report on the TTY
 *
 * Run it as the boot program (the card image of the probe, tools/memprobe-card.ps1), on every BIOS of interest, ideally on the real console. */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include "mcard.h"
#include "mcfile.h"
#include "cdrom.h"
#include "hash/crc32.h"
#include "hash/sha256.h"

#ifndef IMAGE_START                                       /* (the host test puts a model of the console in their place) */
extern char __text_start[], _end[];
#define IMAGE_START ((uint32_t) (uintptr_t) __text_start)
#define IMAGE_END ((uint32_t) (uintptr_t) _end)
#define ROM_PTR ((const volatile uint8_t *) 0xBFC00000u)
#endif

#define BLK 256u                                         /* bytes per block */
#define BLK_WORDS (BLK / 4)
#define NBLK_MAX 6200
#define MAXCP 60                                         /* checkpoints (a stage ends with one) */
#define BUSY 255
#define MARK 0xA5A5A5A5u
#define REPORT_CAP 7936                                  /* the frames 2 .. 63 of a block */
#define STACK_TOP 0x801FE000u                            /* the stack is above this (8 KB) */
#define TAG "PSXXMP"

typedef struct { uint32_t lo, hi; int first; } win_t;

static win_t   W[3];
static int     nblk;
static uint8_t st[NBLK_MAX];                              /* 0 pattern intact, BUSY not filled (not zero at the start), 1.. the checkpoint in which the block was first seen changed */
static uint8_t fwd[NBLK_MAX];                             /* the word of the block that changed first */
static uint32_t fval[NBLK_MAX];                           /* its new value */

typedef struct { uint32_t frame; int stage, newc; uint32_t heap_top; const char *name; } cp_t;
static cp_t    CP[MAXCP + 1];
static int     ncp;

static char    rep[REPORT_CAP + 1];
static int     rep_len;
static char    rom_text[48];
static uint32_t rom_crc;
static int      start_free, start_busy;

static RenderContext ctx;
static input_state   in;
static int           hz, running, done, round_no, report_rc = 99, report_block;
static const char   *stage_name = "";

static void rp(const char *fmt, ...)                      /* the report: to the buffer (and later the TTY) */
{
	va_list ap;
	int n;

	if (rep_len >= REPORT_CAP - 120) return;
	va_start(ap, fmt);
	n = vsnprintf(rep + rep_len, (size_t) (REPORT_CAP - rep_len), fmt, ap);
	va_end(ap);
	if (n > 0) rep_len += n;
}

/* ---- the windows and the blocks ---- */

static void windows(void)
{
	uint32_t end = (IMAGE_END + 0x1FFFu) & ~0xFFFu;                  /* our image and its BSS end here, plus a page of margin */

	W[0].lo = 0x80010000u; W[0].hi = 0x80030000u;
	W[1].lo = 0x800A8000u; W[1].hi = 0x80110000u;                          /* the BIOS shell ends at 0x800A8000; the heap starts at 0x80100000 */
	W[2].lo = end;         W[2].hi = STACK_TOP - 0x1000u;
	nblk = 0;
	for (int w = 0; w < 3; w++) { W[w].first = nblk; nblk += (int) ((W[w].hi - W[w].lo) / BLK); }
}

static int block_of(uint32_t a)
{
	for (int w = 0; w < 3; w++) if (a >= W[w].lo && a < W[w].hi) return W[w].first + (int) ((a - W[w].lo) / BLK);
	return -1;
}

static uint32_t addr_of(int i)
{
	for (int w = 0; w < 3; w++) if (i >= W[w].first && i < (w < 2 ? W[w + 1].first : nblk)) return W[w].lo + (uint32_t) (i - W[w].first) * BLK;
	return 0;
}

static void fill(void)
{
	for (int w = 0; w < 3; w++)
		for (uint32_t a = W[w].lo; a < W[w].hi; a += BLK) {
			volatile uint32_t *p = (volatile uint32_t *) (uintptr_t) a;
			int i = block_of(a), zero = 1;

			for (unsigned k = 0; k < BLK_WORDS; k++) if (p[k]) { zero = 0; break; }
			if (!zero) { st[i] = BUSY; continue; }
			for (unsigned k = 0; k < BLK_WORDS; k++) p[k] = (a + 4 * k) ^ MARK;
			st[i] = 0;
		}
}

/* compare the pattern blocks; returns how many changed since the last scan */
static int scan(int cp, uint32_t *sa, uint32_t *sv, int ns)
{
	int newc = 0, got = 0;

	for (int w = 0; w < 3; w++)
		for (uint32_t a = W[w].lo; a < W[w].hi; a += BLK) {
			int i = block_of(a);
			volatile uint32_t *p = (volatile uint32_t *) (uintptr_t) a;

			if (st[i]) continue;
			for (unsigned k = 0; k < BLK_WORDS; k++)
				if (p[k] != ((a + 4 * k) ^ MARK)) {
					st[i] = (uint8_t) cp; fwd[i] = (uint8_t) k; fval[i] = p[k];
					newc++;
					if (got < ns) { sa[got] = a + 4 * k; sv[got] = p[k]; got++; }
					break;
				}
		}
	return newc;
}

static uint32_t heap_top(void)                           /* the highest block of 0x80100000 .. 0x80110000 that is busy or was written: where the BIOS heap reaches */
{
	uint32_t top = 0;

	for (uint32_t a = 0x80100000u; a < 0x80110000u; a += BLK) { int i = block_of(a); if (i >= 0 && st[i]) top = a + BLK; }
	return top;
}

/* ---- the BIOS ---- */

static void rom_id(void)
{
	const volatile uint8_t *rom = ROM_PTR;
	int n = 0;

	for (int i = 0; i < 40; i++) { uint8_t c = rom[0x7FF32 + i]; if (c < 32 || c > 126) break; rom_text[n++] = (char) c; }
	rom_text[n] = 0;
	rom_crc = crc32((const uint8_t *) ROM_PTR, 0x80000u);
}

/* ---- the stages ---- */

static void frames(int n)                                 /* wait n frames doing nothing else (the idle shell) */
{
	int f0 = VSync(-1);
	while (VSync(-1) - f0 < n) {}
}

static uint32_t sw_last, sw_total;
static void sw_poke(void) { uint32_t n = ticks_cycles(); sw_total += (uint32_t) (n - sw_last); sw_last = n; }

static const char *const ST_NAME[] = {"after fill, 100 frames", "idle, 10 s", "buttons, 10 s", "memory cards", "the screen, 5 s", "CD drive", "computation, 3 s", "report on the card"};
#define NST 8

static void draw(void);

static void stage_run(int s)
{
	uint8_t buf[MC_FRAME];

	stage_name = ST_NAME[s];
	switch (s) {
	case 0: frames(100); break;
	case 1: frames(10 * hz); break;
	case 2:                                                 /* the user presses buttons: the pad is polled like in the applications */
		for (int f = 0, last = -1; f < 10 * hz;) {
			int v = VSync(-1);
			if (v == last) continue;
			last = v; f++;
			input_poll(&in, NULL);
			(void) input_take_pressed(&in);
			draw();
			gpu_present(&ctx);
		}
		break;
	case 3:
		for (int rep_ = 0; rep_ < 5; rep_++)
			for (int port = 0; port < 2; port++)
				for (int fr = 0; fr < 16; fr++) mc_read(port, fr, buf);
		break;
	case 4:
		for (int f = 0, last = -1; f < 5 * hz;) {
			int v = VSync(-1);
			if (v == last) continue;
			last = v; f++;
			draw();
			gpu_present(&ctx);
		}
		break;
	case 5: {
		cd_disc d;
		cd_seek_result r;
		if (cd_open(&d) == CD_OK) for (int i = 0; i < 3; i++) cd_seek(150u + 5000u * (unsigned) (i + 1), &r);
		break;
	}
	case 6: {
		uint8_t h[32], m[64];
		sw_last = ticks_cycles();
		sw_total = 0;
		memset(m, 0x5A, sizeof m);
		while (sw_total < 3u * 33868800u) { sha256(m, sizeof m, h); m[0] ^= h[0]; sw_poke(); }
		break;
	}
	default: break;                                         /* 7: the report is written by the caller, after the scan of the previous stage */
	}
}

/* ---- the report ---- */

static const char *class_text(int c, char *b)
{
	if (c == 0) return "free";
	if (c == BUSY) return "BUSY at the start";
	sprintf(b, "written, first at checkpoint %d", c);
	return b;
}

static void build_report(void)
{
	char b[48];
	uint32_t sp = (uint32_t) (uintptr_t) &b;
	int nfree = 0, nbusy = 0, nchg = 0;

	rep_len = 0;
	rep[0] = 0;
	rp("PSXX MEMPROBE 1\n");
	rp("BIOS %s\nROM CRC32 %08x\n", rom_text, (unsigned) rom_crc);
	rp("image 0x%08x .. 0x%08x, stack near 0x%08x, %s\n", (unsigned) IMAGE_START, (unsigned) IMAGE_END, (unsigned) sp, GetVideoMode() == MODE_PAL ? "PAL" : "NTSC");
	rp("blocks of %u bytes; at the start %d were zero (filled), %d held something (BUSY)\n", BLK, start_free, start_busy);
	rp("known leftovers of the loader, BUSY and dead after the start: the packed block at 0x80180000 and the decoder tables at 0x801B0000\n");
	rp("windows:\n");
	for (int w = 0; w < 3; w++) rp(" W%d 0x%08x .. 0x%08x\n", w + 1, (unsigned) W[w].lo, (unsigned) W[w].hi - 1);
	rp("checkpoints (frame counter, blocks newly written, top of the heap area 0x80100000+):\n");
	for (int c = 1; c <= ncp; c++) rp(" %2d %-24s frame %6lu new %4d heap 0x%08x\n", c, CP[c].name, (unsigned) CP[c].frame, CP[c].newc, (unsigned) CP[c].heap_top);
	for (int i = 0; i < nblk; i++) { if (st[i] == 0) nfree++; else if (st[i] == BUSY) nbusy++; else nchg++; }
	rp("blocks: %d free (%d KB), %d busy at the start (%d KB), %d written (%d KB)\n", nfree, nfree / 4, nbusy, nbusy / 4, nchg, nchg / 4);
	rp("ranges (merged blocks of one kind):\n");
	for (int w = 0; w < 3; w++) {
		int i = W[w].first, e = (w < 2 ? W[w + 1].first : nblk);
		while (i < e) {
			int j = i;
			while (j + 1 < e && st[j + 1] == st[i]) j++;
			if (st[i] == 0 && j - i + 1 < 16 && i != W[w].first && j + 1 != e) { i = j + 1; continue; }     /* small free islands between written blocks are not listed */
			rp(" 0x%08x .. 0x%08x %4d.%02d KB  %s\n", (unsigned) addr_of(i), (unsigned) (addr_of(j) + BLK - 1), (j - i + 1) / 4, (j - i + 1) % 4 * 25, class_text(st[i], b));
			i = j + 1;
		}
	}
	rp("first writes (checkpoint, address, value):\n");
	{
		int listed = 0;
		for (int i = 0; i < nblk && listed < 40; i++)
			if (st[i] && st[i] != BUSY) { rp(" %2d 0x%08x %08x\n", st[i], (unsigned) (addr_of(i) + 4u * fwd[i]), (unsigned) fval[i]); listed++; }
	}
}

/* the file is made on the first call (the directory entry last); the later calls write the report into the same block again */
static int write_report(void)
{
	mcf_entry e[1];
	int nfiles, next = 0, block = report_block, r;
	uint8_t f[MC_FRAME];

	if (!block) {
		r = mcf_scan(1, TAG, e, 0, &nfiles, &next, &block);
		if (r) return r;
		if (!block) return MCF_FULL;
		r = mcf_begin(1, block, "PSXX memory probe", MCF_ICON_DISC);
		if (r) return r;
	}
	for (int fr = 0; fr < 62; fr++) {
		memset(f, 0, sizeof f);
		for (int k = 0; k < MC_FRAME; k++) { int at = fr * MC_FRAME + k; if (at < rep_len) f[k] = (uint8_t) rep[at]; }
		r = mcf_write(1, block, 2 + fr, f);
		if (r) return r;
	}
	if (!report_block) {
		report_block = block;
		return mcf_commit(1, block, TAG, next);
	}
	return MCF_OK;
}

static void tty_report(void)
{
	char line[128];
	int o = 0;

	for (int i = 0; i < rep_len; i++) {
		if (rep[i] == '\n' || o >= 120) { line[o] = 0; printf("[mem] %s\n", line); o = 0; if (rep[i] != '\n') line[o++] = rep[i]; }
		else line[o++] = rep[i];
	}
	if (o) { line[o] = 0; printf("[mem] %s\n", line); }
}

/* ---- the screen ---- */

static int budget;
static void T(int x, int y, const char *s, int r, int g, int b)
{
	int n = (int) strlen(s);
	if (n > budget) return;
	budget -= n;
	font_draw(&ctx, 0, x, y, s, r, g, b);
}

static void color_of(int page_blocks_start, int *r, int *g, int *b)
{
	int busy = 0, freeb = 0, first = 0;

	for (int k = 0; k < 16; k++) {
		int v = st[page_blocks_start + k];
		if (v == BUSY) busy++;
		else if (v == 0) freeb++;
		else if (!first || v < first) first = v;
	}
	if (first) { static const uint8_t C[8][3] = {{255, 60, 60}, {255, 150, 40}, {240, 220, 60}, {200, 90, 220}, {90, 160, 255}, {60, 220, 220}, {255, 120, 170}, {200, 200, 200}}; const uint8_t *c = C[(first - 1) & 7]; *r = c[0]; *g = c[1]; *b = c[2]; }
	else if (busy && freeb) { *r = 90; *g = 170; *b = 120; }
	else if (busy) { *r = 130; *g = 130; *b = 130; }
	else { *r = 40; *g = 200; *b = 80; }
}

static void draw_map(void)                                /* the whole 2 MB: 8 rows of 256 KB, 64 cells of 4 KB; runs of one colour are one rectangle (at most 100 of them a frame: the buffer is 8 KB, the text takes most) */
{
	const int x0 = 24, y0 = 112, cw = 8, ch = 9;
	int rects = 0;

	for (int row = 0; row < 8; row++) {
		int run_r = -1, run_g = 0, run_b = 0, run_start = 0;
		for (int c = 0; c <= 64; c++) {
			int r = -2, g = 0, b = 0;
			if (c < 64) {
				uint32_t a = 0x80000000u + (uint32_t) (row * 64 + c) * 0x1000u;
				int i = block_of(a);
				if (a >= IMAGE_START && a < ((IMAGE_END + 0xFFFu) & ~0xFFFu)) { r = 60; g = 90; b = 220; }      /* our own image */
				else if (a >= STACK_TOP) { r = 60; g = 90; b = 220; }
				else if (i >= 0 && addr_of(i) == a) color_of(i, &r, &g, &b);
				else { r = 30; g = 30; b = 50; }                                                        /* not probed: the kernel, the shell, ... */
			}
			if (r != run_r || g != run_g || b != run_b) {
				if (run_r >= 0 && c > run_start && rects++ < 100) gpu_draw_rect(&ctx, 2, x0 + run_start * cw, y0 + row * ch, (c - run_start) * cw - 1, ch - 1, run_r, run_g, run_b);
				run_r = r; run_g = g; run_b = b; run_start = c;
			}
		}
	}
}

static void draw(void)
{
	char l[64];

	budget = 260;
	T(16, 2, "Memory probe: who writes the RAM?", 255, 255, 255);
	T(16, 22, rom_text, 150, 160, 200);
	snprintf(l, sizeof l, "CRC32 %08x  round %d  checkpoints %d", (unsigned) rom_crc, round_no, ncp);
	T(16, 42, l, 150, 160, 200);
	if (running) { snprintf(l, sizeof l, "stage: %s", stage_name); T(16, 62, l, 255, 220, 80); }
	else if (done) T(16, 62, report_rc ? "done: the report is not on the card" : "done: report on the card in slot 2", report_rc ? 255 : 100, report_rc ? 120 : 255, 120);
	else T(16, 62, "X: start the run   (card in slot 2 for the report)", 255, 255, 255);
	if (ncp) { snprintf(l, sizeof l, "last: %d new blocks, heap to 0x%08x", CP[ncp].newc, (unsigned) CP[ncp].heap_top); T(16, 82, l, 150, 160, 200); }
	T(16, 214, "green free  grey busy  colour written  blue ours", 150, 160, 200);
	draw_map();
}

/* ---- the run ---- */

static void checkpoint(int s)
{
	uint32_t sa[4], sv[4];

	if (ncp >= MAXCP) return;
	ncp++;
	CP[ncp].frame = (uint32_t) VSync(-1);
	CP[ncp].stage = s;
	CP[ncp].name = ST_NAME[s];
	CP[ncp].newc = scan(ncp, sa, sv, 4);
	CP[ncp].heap_top = heap_top();
}

static void run_round(void)
{
	running = 1;
	round_no++;
	for (int s = 0; s < NST; s++) {
		draw();
		gpu_present(&ctx);
		if (s < NST - 1) { stage_run(s); checkpoint(s); }
		else {                                                  /* the card write is itself a stage: the report so far goes on the card, then the last scan */
			build_report();
			report_rc = write_report();
			checkpoint(s);
			build_report();
			report_rc = write_report();
		}
	}
	running = 0;
	done = 1;
	tty_report();
	draw();
	gpu_present(&ctx);
}

int main(void)
{
	int last = -1;

	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
	rom_id();
	windows();
	memset(st, BUSY, sizeof st);
	fill();
	for (int i = 0; i < nblk; i++) { if (st[i] == BUSY) start_busy++; else start_free++; }

	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(&in, NULL);
		pr = input_take_pressed(&in);
		draw();
		gpu_present(&ctx);
		if ((pr & PAD_CROSS) && !running && !done) run_round();
		else if ((pr & PAD_START) && done) { done = 0; report_rc = 99; run_round(); }
		else if ((pr & PAD_TRIANGLE) && done) { build_report(); report_rc = write_report(); }
		else if ((pr & PAD_SELECT) && done) { build_report(); tty_report(); }
	}
	return 0;
}
