/* M0: what the memory card slots show when a card is taken out, put in or changed, and how much the polling costs.
 *
 * Both slots are polled with a chosen method at a chosen rate, once per frame the pad is polled too (as the apps do). Everything is logged on
 * the TTY (printf) and shown on the screen: raw presence flips, the debounced state, the bytes the card answered, the fingerprint (CRC-32 of
 * frames 0..15) when a card appears or on demand, and whether the content changed without the card ever disappearing (an emulator that
 * switches card images). The counters start again at every change of the rate or the method, so each setting has its own numbers.
 *
 *   L1 / R1  poll rate: off, every frame, 2, 5, 15, 30, 60 frames      L2 / R2  poll method: 81 | 81 52 00 00 | 81 53 + 8 | read frame 0
 *   CROSS    timing of all methods on the cards present (and of a pad poll)       SQUARE  fingerprint now (and compare with the last)
 *   TRIANGLE dump frames 0..2 of the cards present on the TTY                      SELECT  auto fingerprint every 5 s on/off      START  reset counters
 *
 * No card is ever written. Run it as the boot program (the card image of the probe) with a card in the other slot. */
#include <stdio.h>
#include <string.h>
#include <psxgpu.h>
#include <hwregs_c.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "pad.h"
#include "mcard.h"
#include "timer.h"
#include "hash/crc32.h"

#define IRQ_CONTROLLER (1 << 7)
#define ACK_TIMEOUT 20000
#define RX_TIMEOUT 20000
#define NEV 16
#define NMETHOD 4
#define NRATE 7
#define FP_FRAMES 16
#define AUTO_FP_SECONDS 5

static const char *const METHOD[NMETHOD] = {"81", "81 52 00 00", "81 53 + 8", "read frame 0"};
static const int RATE[NRATE] = {0, 1, 2, 5, 15, 30, 60};

typedef struct {
	int      raw, state;                 /* last raw presence and the debounced state (-1 unknown, 0 absent, 1 present) */
	uint8_t  rx[10];
	int      rx_n;                       /* bytes the card answered in the last poll */
	int      last_rc;                    /* method 3: the code of mc_read */
	uint32_t polls, flips, partial, errs, fp_checks, fp_changes;
	uint32_t fp;
	int      fp_valid, hdr_ok, sum_bad, used, read_bad;
	const char *fmt;
} slot_t;

static slot_t S[2];
static char   ev_text[NEV][64];
static int    ev_n;
static int    hz, frame, rate_i = 4, method_i, auto_fp;
static pad_stats pad_base;

static RenderContext ctx;
static input_state   in;

static void delay(int n) { for (volatile int i = 0; i < n; i++) {} }

/* ---- the card, byte by byte ---- */

static int sio_byte(uint8_t tx, uint8_t *rx, int wait_ack)
{
	IRQ_STAT = (uint16_t) ~IRQ_CONTROLLER;
	SIO_CTRL(0) |= 0x10;
	SIO_DATA(0) = tx;
	for (int i = 0; !(SIO_STAT(0) & 2); i++)
		if (i > RX_TIMEOUT) return -1;
	*rx = SIO_DATA(0);
	if (wait_ack) {
		for (int i = 0; !(IRQ_STAT & IRQ_CONTROLLER); i++)
			if (i > ACK_TIMEOUT) return -2;
	}
	return 0;
}

/* Sends n bytes to the card in port p (0 = slot 1); every byte but the last waits for the /ACK of the card, the last one too if ack_last.
 * Returns how many bytes were exchanged completely; then the line is released, which ends the command wherever it is. */
static int raw(int p, const uint8_t *tx, int n, uint8_t *rx, int ack_last)
{
	uint16_t saved = IRQ_MASK;
	int i;

	IRQ_MASK = 0;
	SIO_CTRL(0) = (uint16_t) (0x1003 | (p ? 0x2000 : 0));
	delay(100);
	for (i = 0; i < n; i++)
		if (sio_byte(tx[i], &rx[i], i < n - 1 || ack_last)) break;
	SIO_CTRL(0) = 0;
	IRQ_MASK = saved;
	return i;
}

/* One poll with method m: returns the number of bytes that completed (0 = no card answered), *n the number it should be, rx the bytes. */
static int probe(int p, int m, uint8_t rx[10], int *n, int *rc)
{
	static const uint8_t t_id[10] = {0x81, 0x53, 0, 0, 0, 0, 0, 0, 0, 0};
	static const uint8_t t_hdr[4] = {0x81, 0x52, 0x00, 0x00};
	uint8_t frame_buf[MC_FRAME];

	memset(rx, 0, 10);
	*rc = 0;
	switch (m) {
	case 0: *n = 1; return raw(p, t_id, 1, rx, 1);
	case 1: *n = 4; return raw(p, t_hdr, 4, rx, 1);
	case 2: *n = 10; return raw(p, t_id, 10, rx, 0);
	default:
		*n = 1;
		*rc = mc_read(p, 0, frame_buf);
		return *rc == MC_NO_CARD ? 0 : 1;
	}
}

/* ---- the log ---- */

static void ev(const char *s)
{
	char t[64];
	sprintf(t, "%d.%02d %s", frame / hz, (frame % hz) * 100 / hz, s);
	strncpy(ev_text[ev_n % NEV], t, 63);
	ev_text[ev_n % NEV][63] = 0;
	ev_n++;
	printf("[card] %s\n", t);
}
#define EVF(...) do { char t_[64]; sprintf(t_, __VA_ARGS__); ev(t_); } while (0)

static const char *rc_name(int rc)
{
	return rc == MC_OK ? "ok" : rc == MC_NO_CARD ? "nocard" : rc == MC_BAD_ID ? "badid" : rc == MC_BAD_SUM ? "badsum" : "badaddr";
}

/* CRC-32 of frames 0..15 (header and directory) and what they say about the file system; announce: log the result */
static void fingerprint(int p, int announce)
{
	slot_t *s = &S[p];
	uint8_t buf[FP_FRAMES * MC_FRAME];
	uint32_t old = s->fp;
	int had = s->fp_valid;

	memset(buf, 0, sizeof buf);
	s->read_bad = 0;
	for (int i = 0; i < FP_FRAMES; i++)
		if (mc_read(p, i, buf + i * MC_FRAME)) s->read_bad++;
	s->fp = crc32(buf, sizeof buf);
	s->fp_valid = s->read_bad == 0;
	s->hdr_ok = buf[0] == 'M' && buf[1] == 'C';
	s->sum_bad = 0;
	s->used = 0;
	for (int i = 0; i < FP_FRAMES; i++) {
		uint8_t x = 0;
		for (int k = 0; k < MC_FRAME - 1; k++) x ^= buf[i * MC_FRAME + k];
		if (x != buf[i * MC_FRAME + MC_FRAME - 1]) s->sum_bad++;
		if (i > 0 && buf[i * MC_FRAME] == 0x51) s->used++;
	}
	s->fmt = s->read_bad ? "UNREAD" : (s->hdr_ok && !s->sum_bad ? "FS-OK" : "FS-ODD");
	s->fp_checks++;
	if (had && s->fp_valid && old != s->fp) {
		s->fp_changes++;
		EVF("S%d CONTENT CHANGED %08x -> %08x", p + 1, (unsigned) old, (unsigned) s->fp);
	} else if (announce) {
		EVF("S%d fp %08x %s hdr %d sumbad %d used %d bad %d", p + 1, (unsigned) s->fp, s->fmt, s->hdr_ok, s->sum_bad, s->used, s->read_bad);
	}
}

/* ---- polling of one slot ---- */

static void poll_slot(int p)
{
	slot_t *s = &S[p];
	uint8_t rx[10];
	int n, rc, ok = probe(p, method_i, rx, &n, &rc), pres = ok > 0, prev = s->raw;

	s->polls++;
	memcpy(s->rx, rx, sizeof rx);
	s->rx_n = ok;
	s->last_rc = rc;
	if (method_i == 3) {
		if (rc != MC_OK && rc != MC_NO_CARD) { s->errs++; EVF("S%d read frame 0: %s", p + 1, rc_name(rc)); }
	} else if (ok > 0 && ok < n) {
		s->partial++;
		if (s->partial <= 5 || (s->partial % 100) == 0) EVF("S%d partial %d/%d: %02x %02x %02x %02x", p + 1, ok, n, rx[0], rx[1], rx[2], rx[3]);
	}
	if (prev >= 0 && pres != prev) {
		s->flips++;
		EVF("S%d raw %s -> %s (%02x %02x %02x %02x)", p + 1, prev ? "present" : "absent", pres ? "present" : "absent", rx[0], rx[1], rx[2], rx[3]);
	}
	s->raw = pres;
	if (pres == prev && pres != s->state) {            /* two equal polls in a row: the state changed */
		s->state = pres;
		EVF("S%d %s", p + 1, pres ? "CARD IN" : "CARD OUT");
		if (pres) fingerprint(p, 1);
	}
}

/* ---- timing ---- */

static uint32_t us(uint32_t cycles) { return cycles * 10 / 339; }       /* 33.8688 cycles per microsecond; one run is far below 2^28 cycles */

static void bench(void)
{
	EVF("timing, 16 runs each");
	for (int p = 0; p < 2; p++) {
		if (S[p].state != 1) continue;
		for (int m = 0; m < NMETHOD; m++) {
			uint32_t sum = 0, mx = 0;
			int full = 0;
			for (int i = 0; i < 16; i++) {
				uint8_t rx[10];
				int n, rc;
				uint32_t t0 = ticks_cycles(), d;
				int ok = probe(p, m, rx, &n, &rc);
				d = ticks_cycles() - t0;
				sum += d;
				if (d > mx) mx = d;
				full += ok == n;
			}
			EVF("S%d %-12s avg %u max %u us  complete %d/16", p + 1, METHOD[m], (unsigned) us(sum / 16), (unsigned) us(mx), full);
		}
	}
	{
		pad_state ps;
		uint32_t sum = 0;
		int ok = 0;
		for (int i = 0; i < 16; i++) {
			uint32_t t0 = ticks_cycles();
			ok += pad_poll(&ps) == 0;
			sum += ticks_cycles() - t0;
		}
		EVF("pad poll avg %u us  answered %d/16", (unsigned) us(sum / 16), ok);
	}
}

static void dump(void)
{
	for (int p = 0; p < 2; p++) {
		if (S[p].state != 1) continue;
		for (int f = 0; f < 3; f++) {
			uint8_t b[MC_FRAME];
			int rc = mc_read(p, f, b);
			printf("[dump] slot %d frame %d: %s\n", p + 1, f, rc_name(rc));
			if (rc) continue;
			for (int i = 0; i < MC_FRAME; i += 16) {
				printf("[dump]  %02x:", i);
				for (int k = 0; k < 16; k++) printf(" %02x", b[i + k]);
				printf("\n");
			}
		}
	}
}

/* ---- counters, screen ---- */

static void reset_counters(void)
{
	for (int p = 0; p < 2; p++) {
		S[p].polls = S[p].flips = S[p].partial = S[p].errs = S[p].fp_checks = S[p].fp_changes = 0;
	}
	pad_base = *pad_get_stats();
}

static void stat_line(const char *why)
{
	const pad_stats *ps = pad_get_stats();

	printf("[stat] %s: rate %d frames, method %s, auto-fp %d | pad polls %u fail %u retries %u\n", why, RATE[rate_i], METHOD[method_i], auto_fp,
	       (unsigned) (ps->polls - pad_base.polls), (unsigned) (ps->fail - pad_base.fail), (unsigned) (ps->retries - pad_base.retries));
	for (int p = 0; p < 2; p++)
		printf("[stat]  slot %d: %s polls %u flips %u partial %u errs %u fp checks %u changes %u\n", p + 1, S[p].state == 1 ? "present" : "absent", (unsigned) S[p].polls,
		       (unsigned) S[p].flips, (unsigned) S[p].partial, (unsigned) S[p].errs, (unsigned) S[p].fp_checks, (unsigned) S[p].fp_changes);
}

/* Every glyph is a 20 byte sprite in the 8 KB primitive buffer of the frame (gpu.c does not check it in this build): about 390 glyphs fit, an
 * overrun garbles the whole picture. The screen is kept to GLYPH_BUDGET characters per frame; the rest of the detail is on the TTY. */
#define GLYPH_BUDGET 360
static int budget;

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
	char t[96];
	const pad_stats *ps = pad_get_stats();
	int row = 0, padfail = (int) (ps->fail - pad_base.fail);

	budget = GLYPH_BUDGET;
	sprintf(t, "PROBE M0  %d:%02d  f%d %s", frame / hz / 60, frame / hz % 60, frame, hz == 50 ? "PAL" : "NTSC");
	line(row++, t, 255, 255, 255);
	if (RATE[rate_i]) sprintf(t, "every %d fr, method %s", RATE[rate_i], METHOD[method_i]);
	else sprintf(t, "polling OFF, method %s", METHOD[method_i]);
	line(row++, t, 150, 200, 255);
	for (int p = 0; p < 2; p++) {
		slot_t *s = &S[p];
		sprintf(t, "S%d %s %08x %s u%d %02x %02x %02x %02x", p + 1, s->state == 1 ? "IN " : s->state == 0 ? "out" : "?  ", (unsigned) s->fp,
		        s->fp_valid ? s->fmt : "-", s->used, s->rx[0], s->rx[1], s->rx[2], s->rx[3]);
		line(row++, t, s->state == 1 ? 120 : 160, s->state == 1 ? 255 : 160, s->state == 1 ? 120 : 160);
		sprintf(t, " p%u fl%u pa%u er%u fc%u ch%u", (unsigned) s->polls, (unsigned) s->flips, (unsigned) s->partial, (unsigned) s->errs,
		        (unsigned) s->fp_checks, (unsigned) s->fp_changes);
		line(row++, t, 200, 200, 200);
	}
	sprintf(t, "pad p%u fail%u retry%u afp %s", (unsigned) (ps->polls - pad_base.polls), (unsigned) padfail, (unsigned) (ps->retries - pad_base.retries),
	        auto_fp ? "5s" : "off");
	line(row++, t, padfail ? 255 : 200, padfail ? 90 : 200, padfail ? 90 : 200);
	for (int i = 0; i < 2; i++) {
		int k = ev_n - 2 + i;
		line(row++, k >= 0 ? ev_text[k % NEV] : "", 255, 220, 120);
	}
	line(row++, ICO_L1 ICO_R1 "rate " ICO_L2 ICO_R2 "meth " ICO_CROSS "time " ICO_SQUARE "fp " ICO_TRIANGLE "dump", 150, 160, 200);
	line(row++, ICO_SELECT "auto-fp " ICO_START "reset", 150, 160, 200);
}

int main(void)
{
	int last = -1;

	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
	S[0].raw = S[0].state = S[1].raw = S[1].state = -1;
	S[0].fmt = S[1].fmt = "-";
	printf("psxx card probe (M0): %d Hz frame counter, results as [card], [stat], [dump] lines\n", hz);
	reset_counters();

	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		frame++;
		input_poll(&in, NULL);                 /* the pad is polled once per frame, as in the apps */
		pr = input_take_pressed(&in);

		if (pr & (PAD_L1 | PAD_R1 | PAD_L2 | PAD_R2 | PAD_START)) {
			stat_line("before the change");
			if (pr & PAD_R1) rate_i = (rate_i + 1) % NRATE;
			if (pr & PAD_L1) rate_i = (rate_i + NRATE - 1) % NRATE;
			if (pr & PAD_R2) method_i = (method_i + 1) % NMETHOD;
			if (pr & PAD_L2) method_i = (method_i + NMETHOD - 1) % NMETHOD;
			reset_counters();
			EVF("rate %d frames, method %s", RATE[rate_i], METHOD[method_i]);
		}
		if (pr & PAD_SELECT) { auto_fp = !auto_fp; EVF("auto fingerprint %s", auto_fp ? "on (5 s)" : "off"); }
		if (pr & PAD_CROSS) bench();
		if (pr & PAD_SQUARE) for (int p = 0; p < 2; p++) if (S[p].state == 1) fingerprint(p, 1);
		if (pr & PAD_TRIANGLE) dump();

		if (RATE[rate_i] && frame % RATE[rate_i] == 0) {
			poll_slot(0);
			poll_slot(1);
		} else if (!RATE[rate_i] && (frame % (hz / 2)) == 0 && (S[0].state < 0 || S[1].state < 0)) {
			poll_slot(0);                      /* with the polling off the state is read once, so the display is not empty */
			poll_slot(1);
		}
		if (auto_fp && frame % (hz * AUTO_FP_SECONDS) == 0)
			for (int p = 0; p < 2; p++) if (S[p].state == 1) fingerprint(p, 0);
		if (frame % (hz * 10) == 0) stat_line("every 10 s");

		draw();
		gpu_present(&ctx);
	}
	return 0;
}
