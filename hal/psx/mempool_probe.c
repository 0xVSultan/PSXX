/* K5a: what the memory of the console can give to Argon2id, measured. Runs once at the start (CROSS runs it again); the results are on the
 * screen and, in full, on the TTY ([mp] lines).
 *
 *   memory map     where the image and its BSS end, the stack, how much of the main RAM up to 0x801F0000 is free and holds a pattern
 *   G block        the compression function of Argon2 (one 1 KiB block), cycles and microseconds
 *   Argon2id A     128 KiB, 1 pass, all in the RAM: time, and the tag against the one computed on the host (tests/test_argon2.c --print)
 *   SPU RAM        508 blocks of 1 KiB written and read back by DMA, in order and at random: microseconds per block, errors
 *   VRAM           256 blocks (a strip beside the picture), by PIO and by DMA, the same
 *   Argon2id B     512 KiB, 2 passes, 128 blocks in the RAM, 256 in the VRAM, 128 in the SPU RAM: time, accesses per tier, tag against the host
 *
 * The comparison of the tags is the check that every tier gives back what was put in. Run as the boot program (the card image of this probe) or as an EXE. */
#include <stdio.h>
#include <string.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include "mempool.h"
#include "hash/argon2.h"

extern char __text_start[], __bss_start[], _end[];

#define GLYPH_BUDGET 360                         /* characters per frame: the 8 KB primitive buffer holds about 390 glyphs (see cardprobe.c) */
#define APP_RAM_END 0x801F0000u
#define NROWS 11

static RenderContext ctx;
static input_state   in;
static char          rows[NROWS][44];
static int           hz, step = -1, budget;
static int           vram_ok[2], spu_ok, vram_mode_used = -1;

static uint64_t ram_pool[128 * ARGON2_QWORDS];   /* the RAM tier: 128 blocks */
static uint64_t blk[ARGON2_QWORDS], blk2[ARGON2_QWORDS];

/* ---- the stopwatch: the hardware counter is 16 bit (15 ms), so every long loop pokes it ---- */
static uint32_t sw_last;
static uint64_t sw_total, sw_t0;
static void sw_poke(void) { uint32_t n = ticks_cycles(); sw_total += (uint32_t) (n - sw_last); sw_last = n; }
static void sw_start(void) { sw_poke(); sw_t0 = sw_total; }
static uint32_t sw_cycles(void) { sw_poke(); return (uint32_t) (sw_total - sw_t0); }
static uint32_t sw_us(void) { return (uint32_t) ((uint64_t) sw_cycles() * 1000 / 33869); }

static uint32_t rnd_state = 0x2545F491u;
static uint32_t rnd(void) { rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5; return rnd_state; }

static void fill_pattern(uint64_t *b, uint32_t seed)
{
	uint32_t s = seed * 2654435761u + 1;

	for (int i = 0; i < ARGON2_QWORDS; i++) {
		s = s * 1664525u + 1013904223u;
		b[i] = ((uint64_t) s << 32) | (s ^ (uint32_t) i * 40503u);
	}
}

static const uint8_t PW[] = "psx-mempool-probe";
static const char EXPECT_A[] = "01a3dce35c164e054ce5d177d91674896a5a8df21d3457830e19ea37e065ded9";   /* t=1 m=128 p=1, tests/test_argon2.c --print */
static const char EXPECT_B[] = "e1308bc63a7aeb2b6456e7401917876576decfd7b9ffeec60e803f3ace9f074e";   /* t=2 m=512 p=1 */

static int tag_ok(const uint8_t tag[32], const char *expect)
{
	char hex[65];

	for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", tag[i]);
	return strcmp(hex, expect) == 0;
}

static void run_argon(const char *name, uint32_t t, uint32_t m, uint32_t ram_blocks, uint32_t vram_blocks, uint32_t spu_blocks, int vmode, const char *expect, char *out, size_t cap)
{
	static mempool mp;
	argon2_mem mem;
	argon2_params p;
	uint8_t salt[16], tag[32];
	uint32_t us;
	int ok;

	memset(salt, 0x5a, sizeof salt);
	memset(&p, 0, sizeof p);
	p.t_cost = t; p.m_cost_kib = m; p.lanes = 1; p.taglen = 32;
	p.pwd = PW; p.pwdlen = sizeof PW - 1; p.salt = salt; p.saltlen = sizeof salt;
	memset(&mp, 0, sizeof mp);
	mp.ram = ram_pool; mp.ram_blocks = ram_blocks; mp.vram_blocks = vram_blocks; mp.spu_blocks = spu_blocks; mp.vram_mode = vmode; mp.poke = sw_poke;
	mempool_mem(&mp, &mem);
	sw_start();
	ok = argon2id(&p, &mem, tag) == 0 && tag_ok(tag, expect);
	us = sw_us();
	printf("[mp] Argon2id %s: t=%u m=%u KiB, blocks RAM %u VRAM %u SPU %u (vram %s), %u ms, %u us per block, accesses RAM %u VRAM %u SPU %u, tag %s\n", name, (unsigned) t, (unsigned) m,
	       (unsigned) ram_blocks, (unsigned) vram_blocks, (unsigned) spu_blocks, vmode == VRAM_DMA ? "DMA" : "PIO", (unsigned) (us / 1000), (unsigned) (us / (m / 4 * 4 * t)),
	       (unsigned) mp.n_ram, (unsigned) mp.n_vram, (unsigned) mp.n_spu, ok ? "OK" : "WRONG");
	snprintf(out, cap, "%s %uK t%u %u ms %s", name, (unsigned) m, (unsigned) t, (unsigned) (us / 1000), ok ? "OK" : "WRONG");
}

static void test_map(void)
{
	uint32_t end = ((uint32_t) _end + 1023) & ~1023u, bad = 0, n = 0, sp;
	volatile uint32_t *p;

	sp = (uint32_t) &sp;
	for (p = (volatile uint32_t *) end; (uint32_t) p < APP_RAM_END; p++, n++) *p = (uint32_t) p * 2654435761u;
	for (p = (volatile uint32_t *) end; (uint32_t) p < APP_RAM_END; p++) if (*p != (uint32_t) p * 2654435761u) bad++;
	printf("[mp] image %08x text, bss %08x .. end %08x, stack near %08x; free RAM %08x .. %08x = %u KB, pattern %s (%u words wrong)\n", (unsigned) (uint32_t) __text_start, (unsigned) (uint32_t) __bss_start,
	       (unsigned) (uint32_t) _end, (unsigned) sp, (unsigned) end, (unsigned) APP_RAM_END, (unsigned) ((APP_RAM_END - end) / 1024), bad ? "BAD" : "ok", (unsigned) bad);
	snprintf(rows[1], sizeof rows[1], "bss %08x end %08x sp %08x", (unsigned) (uint32_t) __bss_start, (unsigned) (uint32_t) _end, (unsigned) sp);
	snprintf(rows[2], sizeof rows[2], "free %u KB to 801F0000, %s", (unsigned) ((APP_RAM_END - end) / 1024), bad ? "PATTERN BAD" : "pattern ok");
}

static void test_g(void)
{
	uint32_t cyc;
	const int N = 200;

	fill_pattern(blk, 1);
	fill_pattern(blk2, 2);
	sw_start();
	for (int i = 0; i < N; i++) {
		static uint64_t out[ARGON2_QWORDS];

		argon2_fill_block(out, blk, blk2, i & 1);
		blk[0] ^= out[5];
		if ((i & 7) == 0) sw_poke();
	}
	cyc = sw_cycles() / N;
	printf("[mp] G block (compression function): %u cycles = %u us\n", (unsigned) cyc, (unsigned) ((uint64_t) cyc * 1000 / 33869));
	snprintf(rows[3], sizeof rows[3], "G block %u us (%u cycles)", (unsigned) ((uint64_t) cyc * 1000 / 33869), (unsigned) cyc);
}

static void test_spu(void)
{
	uint32_t w = 0, r = 0, rr = 0, bad = 0, order[SPU_POOL_BLOCKS];
	int fail = 0;

	spu_pool_init();
	sw_start();
	for (int i = 0; i < SPU_POOL_BLOCKS; i++) {
		fill_pattern(blk, 100 + i);
		fail |= spu_pool_write(SPU_POOL_BASE + i * ARGON2_BLOCK_BYTES, blk, ARGON2_BLOCK_BYTES);
		sw_poke();
	}
	w = sw_us() / SPU_POOL_BLOCKS;
	sw_start();
	for (int i = 0; i < SPU_POOL_BLOCKS; i++) {
		fail |= spu_pool_read(SPU_POOL_BASE + i * ARGON2_BLOCK_BYTES, blk2, ARGON2_BLOCK_BYTES);
		fill_pattern(blk, 100 + i);
		if (memcmp(blk, blk2, ARGON2_BLOCK_BYTES)) bad++;
		sw_poke();
	}
	r = sw_us() / SPU_POOL_BLOCKS;
	for (int i = 0; i < SPU_POOL_BLOCKS; i++) order[i] = (uint32_t) i;
	for (int i = SPU_POOL_BLOCKS - 1; i > 0; i--) { uint32_t j = rnd() % (uint32_t) (i + 1), t = order[i]; order[i] = order[j]; order[j] = t; }
	sw_start();
	for (int i = 0; i < SPU_POOL_BLOCKS; i++) {
		fail |= spu_pool_read(SPU_POOL_BASE + order[i] * ARGON2_BLOCK_BYTES, blk2, ARGON2_BLOCK_BYTES);
		fill_pattern(blk, 100 + order[i]);
		if (memcmp(blk, blk2, ARGON2_BLOCK_BYTES)) bad++;
		sw_poke();
	}
	rr = sw_us() / SPU_POOL_BLOCKS;
	spu_ok = !fail && !bad;
	printf("[mp] SPU RAM, %d blocks of 1 KiB by DMA: write %u us, read %u us, random read %u us per block; %u wrong blocks, %s\n", SPU_POOL_BLOCKS, (unsigned) w, (unsigned) r, (unsigned) rr, (unsigned) bad,
	       fail ? "the SPU did not answer in time" : "no timeout");
	snprintf(rows[5], sizeof rows[5], "SPU w%u r%u rr%u us bad%u%s", (unsigned) w, (unsigned) r, (unsigned) rr, (unsigned) bad, fail ? " TIMEOUT" : "");
}

static void test_vram(int mode, int row)
{
	uint32_t w, r, rr, bad = 0, order[VRAM_POOL_BLOCKS];

	sw_start();
	for (int i = 0; i < VRAM_POOL_BLOCKS; i++) {
		fill_pattern(blk, 500 + i);
		vram_pool_write(i, blk, mode);
		sw_poke();
	}
	w = sw_us() / VRAM_POOL_BLOCKS;
	sw_start();
	for (int i = 0; i < VRAM_POOL_BLOCKS; i++) {
		vram_pool_read(i, blk2, mode);
		fill_pattern(blk, 500 + i);
		if (memcmp(blk, blk2, ARGON2_BLOCK_BYTES)) bad++;
		sw_poke();
	}
	r = sw_us() / VRAM_POOL_BLOCKS;
	for (int i = 0; i < VRAM_POOL_BLOCKS; i++) order[i] = (uint32_t) i;
	for (int i = VRAM_POOL_BLOCKS - 1; i > 0; i--) { uint32_t j = rnd() % (uint32_t) (i + 1), t = order[i]; order[i] = order[j]; order[j] = t; }
	sw_start();
	for (int i = 0; i < VRAM_POOL_BLOCKS; i++) {
		vram_pool_read((int) order[i], blk2, mode);
		fill_pattern(blk, 500 + order[i]);
		if (memcmp(blk, blk2, ARGON2_BLOCK_BYTES)) bad++;
		sw_poke();
	}
	rr = sw_us() / VRAM_POOL_BLOCKS;
	vram_ok[mode] = bad == 0;
	printf("[mp] VRAM strip, %d blocks of 1 KiB by %s: write %u us, read %u us, random read %u us per block; %u wrong blocks\n", VRAM_POOL_BLOCKS, mode == VRAM_DMA ? "DMA" : "PIO", (unsigned) w,
	       (unsigned) r, (unsigned) rr, (unsigned) bad);
	snprintf(rows[row], sizeof rows[row], "VRAM %s w%u r%u rr%u us bad%u", mode == VRAM_DMA ? "DMA" : "PIO", (unsigned) w, (unsigned) r, (unsigned) rr, (unsigned) bad);
}

/* one test a frame, so the screen is drawn between them */
static void do_step(void)
{
	switch (step) {
	case 0: test_map(); break;
	case 1: test_g(); break;
	case 2: run_argon("A", 1, 128, 128, 0, 0, VRAM_PIO, EXPECT_A, rows[4], sizeof rows[4]); break;
	case 3: test_spu(); break;
	case 4: test_vram(VRAM_PIO, 6); break;
	case 5: test_vram(VRAM_DMA, 7); break;
	case 6: {
		int vm = vram_ok[VRAM_DMA] ? VRAM_DMA : VRAM_PIO;

		vram_mode_used = vm;
		run_argon("B", 2, 512, 128, 256, 128, vm, EXPECT_B, rows[8], sizeof rows[8]);
		break;
	}
	}
	step++;
}

static void line(int row, const char *s, int r, int g, int b)
{
	char t[48];
	int n = (int) strlen(s);

	if (n > 44) n = 44;
	if (n > budget) n = budget > 0 ? budget : 0;
	memcpy(t, s, (size_t) n);
	t[n] = 0;
	budget -= n;
	if (n) font_draw(&ctx, 0, 8, 2 + row * 20, t, r, g, b);
}

static void draw(void)
{
	budget = GLYPH_BUDGET;
	snprintf(rows[0], sizeof rows[0], "MEMPOOL K5a %s  step %d/7", hz == 50 ? "PAL" : "NTSC", step < 7 ? step : 7);
	for (int i = 0; i < NROWS - 1; i++)
		if (rows[i][0]) {
			int bad = strstr(rows[i], "WRONG") || strstr(rows[i], "BAD") || strstr(rows[i], "TIMEOUT") || (strstr(rows[i], "bad") && !strstr(rows[i], "bad0"));
			line(i, rows[i], i == 0 ? 255 : bad ? 255 : 200, i == 0 ? 255 : bad ? 90 : 220, i == 0 ? 255 : bad ? 90 : 200);
		}
	line(NROWS - 1, step >= 7 ? ICO_CROSS "again" : "running...", 150, 160, 200);
}

int main(void)
{
	int last = -1;

	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
	printf("psxx memory pool probe (K5a): the tests run once, results as [mp] lines\n");
	step = 0;
	sw_last = ticks_cycles();

	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(&in, NULL);
		pr = input_take_pressed(&in);
		if (step >= 7 && (pr & PAD_CROSS)) { memset(rows, 0, sizeof rows); step = 0; }
		draw();
		gpu_present(&ctx);
		if (step < 7) do_step();                 /* after the draw: the screen shows "running" while the test works */
	}
	return 0;
}
