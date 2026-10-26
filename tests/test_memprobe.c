/* The memory probe (hal/psx/memprobe.c) on the host, against a model of the console: 2 MB of RAM at 0x80000000 (mapped at that address), a ROM, a card, and a "BIOS" that writes a few
 * words into the RAM at chosen moments of the run. The probe is compiled into this file; what is checked is what the real run depends on: the blocks that are not zero at the start are
 * left alone (BUSY), the others get the pattern and are reported as written exactly when and where the model wrote, the heap top follows the writes, nothing else is reported as written,
 * the ranges of the report add up, the report is on the (model) card, a second round goes on numbering, and the ROM is identified.
 * Windows only (the RAM is mapped at the address of the console). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

#define IMAGE_START 0x80110000u
#define IMAGE_END 0x80136000u
static uint8_t fake_rom[0x80000];
#define ROM_PTR ((const volatile uint8_t *) fake_rom)
#define main memprobe_main
#include "memprobe.c"
#undef main

/* ---- the console ---- */

static long vframes;
static uint16_t press_next;
static int fired[8], phase;
static int bad, total;
#define CHECK(c, ...) do { total++; if (!(c)) { bad++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void poke(uint32_t a, uint32_t v) { *(volatile uint32_t *) (uintptr_t) a = v; }

static void verify(void);

/* the "BIOS" writes while the probe works: in which stage, what (called from every function of the model that the stages use, since some stages never wait for a frame) */
static void sim(void)
{
	if (!strcmp(stage_name, "idle, 10 s") && !fired[0]) { fired[0] = 1; poke(0x80101020u, 0x80101230u); }       /* the heap grows into the second page */
	if (!strcmp(stage_name, "memory cards") && !fired[1]) { fired[1] = 1; poke(0x80028004u, 0x12345678u); }
	if (!strcmp(stage_name, "CD drive") && !fired[2]) { fired[2] = 1; poke(0x800C0000u, 0xDEADBEEFu); poke(0x800C0100u, 1); }   /* two neighbouring blocks */
	if (!strcmp(stage_name, "computation, 3 s") && !fired[3]) { fired[3] = 1; poke(0x80101120u, 0x80101400u); }                   /* the heap grows again */
}

int GetVideoMode(void) { return MODE_NTSC; }
int VSync(int mode)
{
	(void) mode;
	++vframes;
	if (vframes > 3000000) { printf("FAIL: the probe does not end\n"); exit(1); }
	sim();
	if (done && round_no == 1 && !phase) { phase = 1; press_next = PAD_START; }                                                      /* a second round */
	else if (done && round_no == 2) verify();
	return (int) vframes;
}
void gpu_init(RenderContext *c, int r, int g, int b) { (void) r; (void) g; (void) b; c->xres = 640; c->yres = 240; }
void gpu_present(RenderContext *c) { (void) c; }
void gpu_draw_rect(RenderContext *c, int z, int x, int y, int w, int h, int r, int g, int b) { (void) c; (void) z; (void) x; (void) y; (void) w; (void) h; (void) r; (void) g; (void) b; }
void font_init(int s) { (void) s; }
void font_draw(RenderContext *c, int z, int x, int y, const char *s, int r, int g, int b) { (void) c; (void) z; (void) x; (void) y; (void) s; (void) r; (void) g; (void) b; }
void input_init(input_state *i) { memset(i, 0, sizeof *i); }
int input_poll(input_state *i, entropy_pool *p) { (void) i; (void) p; return 1; }
uint16_t input_take_pressed(input_state *i) { uint16_t r = press_next; (void) i; press_next = 0; return r; }
void ticks_init(void) {}
uint32_t ticks_cycles(void) { static uint32_t n; sim(); return n += 400; }
int mc_read(int port, int frame, uint8_t out[MC_FRAME]) { (void) port; (void) frame; sim(); memset(out, 0, MC_FRAME); return MC_OK; }
int mc_write(int port, int frame, const uint8_t in_[MC_FRAME]) { (void) port; (void) frame; (void) in_; return MC_OK; }
int mc_present(int port) { (void) port; return 1; }
int cd_open(cd_disc *d) { sim(); memset(d, 0, sizeof *d); return CD_NO_DISC; }
int cd_seek(uint32_t s, cd_seek_result *r) { (void) s; (void) r; return CD_NO_DISC; }

/* the card: one block of the model, frames 2 .. 63; the directory entry (commit) counts */
static uint8_t card[64][MC_FRAME];
static int commits, begins, card_writes;
int mcf_scan(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block)
{ (void) port; (void) tag; (void) out; (void) max; *nfiles = commits; *next = commits + 1; *free_block = 3; return MCF_OK; }
int mcf_begin(int port, int block, const char *title, int icon) { (void) port; (void) block; (void) title; (void) icon; begins++; return MCF_OK; }
int mcf_write(int port, int block, int frame, const uint8_t *data)
{
	(void) port;
	if (block != 3 || frame < 2 || frame > 63) { printf("FAIL: card write %d/%d\n", block, frame); exit(1); }
	memcpy(card[frame], data, MC_FRAME);
	card_writes++;
	return MCF_OK;
}
int mcf_commit(int port, int block, const char *tag, int number) { (void) port; (void) block; (void) tag; (void) number; commits++; return MCF_OK; }
void mcf_name(char out[MCF_NAME], const char *tag, int number) { snprintf(out, MCF_NAME, "BESCES-00000%s%02d", tag, number); }

/* ---- the checks, after the second round ---- */

static int st_at(uint32_t a) { int i = block_of(a); return i < 0 ? -1 : st[i]; }

static void verify(void)
{
	static char text[REPORT_CAP + 1];
	int freeb = 0, busyb = 0, wr = 0;

	CHECK(ncp == 16, "checkpoints: %d (two rounds of eight stages)", ncp);
	CHECK(commits == 1 && begins == 1, "the report file is made once (%d begins, %d commits)", begins, commits);
	CHECK(card_writes >= 2 * 62, "the report is written more than once (%d frame writes)", card_writes);
	CHECK(!strcmp(rom_text, "System ROM Version 2.0 05/10/95 E"), "ROM text '%s'", rom_text);
	CHECK(rom_crc == crc32((const uint8_t *) fake_rom, sizeof fake_rom), "ROM CRC");
	/* what was busy at the start stays busy and untouched; what the BIOS wrote was seen in the right stage */
	CHECK(st_at(0x80020000u) == BUSY && st_at(0x80020300u) == BUSY && st_at(0x80020400u) == 0, "busy blocks of the first window");
	CHECK(st_at(0x80100000u) == BUSY && st_at(0x80100F00u) == BUSY && st_at(0x80101000u) == 2, "heap: busy page, then the first write in checkpoint 2 (st %d)", st_at(0x80101000u));
	CHECK(st_at(0x80101100u) == 7, "second heap write in the computation stage, checkpoint 7 (st %d)", st_at(0x80101100u));
	CHECK(st_at(0x80028000u) == 4, "write during the card stage: checkpoint 4 (st %d)", st_at(0x80028000u));
	CHECK(st_at(0x800C0000u) == 6 && st_at(0x800C0100u) == 6, "two blocks written during the CD stage: checkpoint 6");
	CHECK(st_at(0x800F3000u) == BUSY, "BIOS data at 0x800F3000 is busy");
	CHECK(st_at(0x80180000u) == BUSY && st_at(0x801B0000u) == BUSY, "the loader leftovers are busy");
	CHECK(st_at(0x80060000u) == -1 && st_at(0x80110000u) == -1, "outside the windows: no state");
	CHECK(st_at(0x801E0000u) == 0, "free memory above stays free");
	for (int i = 0; i < nblk; i++) { if (st[i] == 0) freeb++; else if (st[i] == BUSY) busyb++; else wr++; }
	CHECK(wr == 5, "five written blocks (%d)", wr);
	CHECK(freeb + busyb + wr == nblk, "the blocks add up");
	/* the heap top follows the writes */
	CHECK(CP[1].heap_top == 0x80101000u && CP[2].heap_top == 0x80101100u, "heap top at the checkpoints 1 and 2: 0x%08x 0x%08x", (unsigned) CP[1].heap_top, (unsigned) CP[2].heap_top);
	CHECK(CP[7].heap_top == 0x80101200u, "heap top after the second write: 0x%08x", (unsigned) CP[7].heap_top);
	CHECK(CP[2].newc == 1 && CP[4].newc == 1 && CP[6].newc == 2 && CP[7].newc == 1, "new blocks per checkpoint %d %d %d %d", CP[2].newc, CP[4].newc, CP[6].newc, CP[7].newc);
	CHECK(CP[9].newc == 0 && CP[16].newc == 0, "the second round writes nothing new");
	/* the report: on the (model) card exactly as it was built last, and with the facts in it */
	for (int f = 0; f < 62; f++) memcpy(text + f * MC_FRAME, card[2 + f], MC_FRAME);
	text[REPORT_CAP] = 0;
	CHECK(!strcmp(text, rep), "the text on the card is the report");
	CHECK(strstr(rep, "written, first at checkpoint 2") && strstr(rep, "BUSY at the start") && strstr(rep, " free"), "the report has the three kinds of ranges");
	CHECK(strstr(rep, "ROM CRC32") != NULL && strstr(rep, "System ROM Version 2.0") != NULL, "the BIOS is in the report");
	printf("memory probe: %d checks, %d bad, %ld frames\n", total, bad, vframes);
	if (bad) printf("%s\n", rep);
	exit(bad != 0);
}

int main(int argc, char **argv)
{
	(void) argc; (void) argv;
#ifndef _WIN32
	printf("memory probe test: Windows only, skipped\n");
	return 0;
#else
	if (!VirtualAlloc((void *) (uintptr_t) 0x80000000u, 0x200000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) { printf("memory probe test: no memory at the console address, skipped\n"); return 0; }
	setvbuf(stdout, NULL, _IONBF, 0);
	for (unsigned i = 0; i < sizeof fake_rom; i++) fake_rom[i] = (uint8_t) (i * 7 + 3);
	memcpy(fake_rom + 0x7FF32, "System ROM Version 2.0 05/10/95 E", 34);
	/* what the BIOS and the loader hold at the start */
	for (uint32_t a = 0x80030000u; a < 0x800A8000u; a += 4) poke(a, a | 1);                 /* the shell */
	for (uint32_t a = 0x80020000u; a < 0x80020400u; a += 4) poke(a, 0x11111111u);           /* live data in the first window */
	for (uint32_t a = 0x80100000u; a < 0x80101000u; a += 4) poke(a, 0x22222222u);           /* the heap page */
	for (uint32_t a = 0x800F3000u; a < 0x800F3400u; a += 4) poke(a, 0x33333333u);           /* the BIOS data of 13.1a */
	for (uint32_t a = 0x80110000u; a < 0x80136000u; a += 4) poke(a, 0x44444444u);           /* our image */
	for (uint32_t a = 0x80180000u; a < 0x80186000u; a += 4) poke(a, 0x55555555u);           /* the packed block */
	for (uint32_t a = 0x801B0000u; a < 0x801B4000u; a += 4) poke(a, 0x66666666u);           /* the decoder tables */
	press_next = PAD_CROSS;
	memprobe_main();
	return 0;
#endif
}
