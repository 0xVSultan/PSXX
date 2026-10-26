/* Test of the "hide wallet" mode (see hide.h): the console is a CD player until a gesture and a session PIN bring the "wallet" back.
 * The wallet here is a stand-in with a demo key in RAM, an entropy menu and the music line, to try the pieces on their own:
 *
 *  - set the session PIN (typed twice), then the hint about the gesture
 *  - wallet: hold L1+L2+R1+R2 for 1 s  -> the CD player (the music goes on in the background)
 *  - player: L1+L2+R1+R2 for 1 s, then within 1 s DOWN for 3 s, then the PIN -> the wallet; 5 wrong PINs wipe the demo key and lock
 *  - entropy menu: the CD seek sample needs the head, so the music is paused or switched off there first
 * Needs a disc with audio tracks (tools/gen_testdisc.py makes one). */
#include <stdio.h>
#include <string.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include "cdrom.h"
#include "hide.h"
#include "util.h"
#include "ui.h"

#define SW GPU_XRES
#define MARGIN 16

enum state { S_SET1, S_SET2, S_INFO, S_WALLET, S_ENTROPY, S_PLAYER, S_PIN, S_LOCKED };
enum music { M_OFF, M_PLAY, M_PAUSE };
enum act { A_NONE, A_PLAY_PAUSE, A_STOP, A_NEXT, A_PREV, A_SAMPLE, A_MUSIC_PAUSE, A_MUSIC_OFF };

static RenderContext ctx;
static input_state   in;
static hide_clock    clk;
static hide_gesture  gest;
static hide_pin      pin;
static hide_dial     dial;
static char          first[HIDE_PIN_LEN + 1];

static int           state = S_SET1;
static uint8_t       demo_key[16];

static cd_disc       disc;
static int           disc_ok, disc_rc = CD_NO_DISC, disc_tried;
static int           music = M_OFF, track = 1;
static uint32_t      resume_abs = 0xFFFFFFFFu;
static cd_audio_pos  pos;
static int           have_pos;

static int           act = A_NONE;
static const char   *busy;
static char          msg[64];
static int           msg_frames;
static cd_seek_result last_seek;
static int           have_seek, nsamples;

static void say(const char *m) { snprintf(msg, sizeof msg, "%s", m); msg_frames = 180; }
static void text(int x, int y, const char *s, int r, int g, int b) { font_draw(&ctx, 0, x, y, s, r, g, b); }
static void white(int x, int y, const char *s) { text(x, y, s, 255, 255, 255); }
static void dim(int x, int y, const char *s) { text(x, y, s, 150, 160, 200); }
static void ctext(int y, const char *s, int r, int g, int b) { text((SW - font_width(s)) / 2, y, s, r, g, b); }

static void bright(int y, uint8_t rgb[3], void *u) { (void) y; (void) u; rgb[0] = 255; rgb[1] = 255; rgb[2] = 255; }

/* ---- the drive ---- */
static unsigned track_start(int t)
{
	int i = t - disc.first;

	if (i < 0 || i >= disc.ntoc) return 0;
	return ((unsigned) disc.toc[i][0] * 60 + disc.toc[i][1]) * 75;
}

static unsigned track_len_sec(int t)
{
	unsigned a = track_start(t), b = t < disc.last ? track_start(t + 1) : disc.leadout;

	return a && b > a ? (b - a) / 75 : 0;
}

static int ensure_disc(void)
{
	if (disc_ok) return 1;
	disc_rc = cd_open(&disc);
	disc_tried = 1;
	if (disc_rc != CD_OK) {
		say(disc_rc == CD_NO_DISC ? "No disc in the drive" : disc_rc == CD_TIMEOUT ? "The drive did not answer" : "Drive error");
		return 0;
	}
	disc_ok = 1;
	cd_audio_init();
	track = disc.first;
	return 1;
}

static void refresh_pos(void)
{
	if (!disc_ok || music != M_PLAY) return;
	if (cd_audio_where(&pos) == CD_OK) {
		have_pos = 1;
		if (!pos.playing) music = M_OFF;                    /* the disc ended */
		else if (pos.track) track = pos.track;
	}
}

static void play_track(int t)
{
	if (t < disc.first) t = disc.first;
	if (t > disc.last) t = disc.last;
	if (cd_audio_play(t) == CD_OK) { music = M_PLAY; track = t; resume_abs = 0xFFFFFFFFu; have_pos = 0; }
	else say("Cannot play this track");
}

static void music_pause(void)
{
	cd_audio_pos p;

	if (music != M_PLAY) return;
	if (cd_audio_pause(&p) == CD_OK) {
		music = M_PAUSE;
		resume_abs = p.abs;
		pos = p;
		have_pos = 1;
	} else {
		say("Pause failed");
	}
}

static void music_resume(void)
{
	int rc = resume_abs != 0xFFFFFFFFu ? cd_audio_play_from(resume_abs) : cd_audio_play(track);

	if (rc == CD_OK) music = M_PLAY;
	else say("Cannot resume");
}

static void music_off(void)
{
	if (music == M_OFF) return;
	cd_audio_stop();
	music = M_OFF;
	resume_abs = 0xFFFFFFFFu;
	have_pos = 0;
}

static void do_act(int a)
{
	switch (a) {
	case A_PLAY_PAUSE:
		if (!ensure_disc()) break;
		if (music == M_PLAY) music_pause();
		else if (music == M_PAUSE) music_resume();
		else play_track(track);
		break;
	case A_STOP:
		music_off();
		track = disc_ok ? disc.first : 1;
		break;
	case A_NEXT:
		if (!ensure_disc()) break;
		if (track < disc.last) play_track(track + 1);
		break;
	case A_PREV:
		if (!ensure_disc()) break;
		if (music == M_PLAY && have_pos && (pos.rel_min > 0 || pos.rel_sec > 3)) play_track(track);       /* like a real player: back to the start first */
		else if (track > disc.first) play_track(track - 1);
		else play_track(track);
		break;
	case A_MUSIC_PAUSE:
		if (music == M_PLAY) music_pause();
		else if (music == M_PAUSE) music_resume();
		break;
	case A_MUSIC_OFF:
		music_off();
		break;
	case A_SAMPLE:
		if (!ensure_disc()) break;
		{
			uint32_t span = disc.leadout > 450 ? disc.leadout - 300 : 150;
			uint32_t target = 150 + ticks_cycles() % span;
			cd_seek_result r;
			int rc = cd_seek(target, &r);

			last_seek = r;
			have_seek = rc == CD_OK;
			nsamples++;
			if (rc != CD_OK) say("The seek failed");
			else if (music == M_PAUSE) say("Sample taken; the music resumes where it paused");
			else say("Sample taken");
		}
		break;
	}
}

/* ---- screens ---- */
static void time_str(char *out, size_t n, unsigned sec) { snprintf(out, n, "%02u:%02u", sec / 60, sec % 60); }

static void music_line(int y)
{
	char l[80];

	if (music == M_OFF) snprintf(l, sizeof l, "Music: off");
	else snprintf(l, sizeof l, "Music: %s  track %02d  %02u:%02u", music == M_PLAY ? "playing" : "paused", track, have_pos ? pos.rel_min : 0u, have_pos ? pos.rel_sec : 0u);
	text(MARGIN, y, l, music == M_PLAY ? 120 : 200, music == M_PLAY ? 255 : 200, music == M_PLAY ? 120 : 200);
}

static void draw_dial(int y)
{
	char c[2] = {0, 0}, s[2 * HIDE_PIN_LEN * 2 + 2];
	int o = 0;

	for (int i = 0; i < HIDE_PIN_LEN; i++) {
		c[0] = i < dial.n ? '*' : i == dial.n ? (char) ('0' + dial.cur) : '_';
		s[o++] = c[0];
		s[o++] = ' ';
	}
	s[o] = 0;
	font_draw_big(&ctx, 0, (SW - o * 40) / 2, y, s, 2, bright, NULL);
}

static void draw_set(int again)
{
	white(MARGIN, UI_TOP, again ? "Session PIN: type it again" : "Set the session PIN");
	dim(MARGIN, 34, again ? "The same 6 digits to confirm." : "6 digits, kept in RAM until the power goes off.");
	draw_dial(70);
	dim(MARGIN, 130, "Hide the wallet later: hold " ICO_L1 ICO_L2 ICO_R1 ICO_R2 " for 1 s");
	dim(MARGIN, 152, "(the screen turns into a CD player)");
	text(MARGIN, UI_HINT1, ICO_UPDOWN " digit   " ICO_CROSS " take   " ICO_CIRCLE " delete", 255, 255, 255);
}

static void draw_info(void)
{
	white(MARGIN, UI_TOP, "PIN is set");
	dim(MARGIN, 34, "Hide:  hold " ICO_L1 ICO_L2 ICO_R1 ICO_R2 " for 1 s. The CD player comes up;");
	dim(MARGIN, 54, "       the music can play on while the wallet is open.");
	dim(MARGIN, 84, "Back:  " ICO_L1 ICO_L2 ICO_R1 ICO_R2 " for 1 s, then within 1 s");
	dim(MARGIN, 104, "       hold " ICO_DOWN " for 3 s, then type the PIN.");
	dim(MARGIN, 134, "5 wrong PINs wipe the keys: the password is needed again.");
	text(MARGIN, UI_HINT2, ICO_CROSS " continue", 255, 255, 255);
}

static void draw_wallet(void)
{
	char l[48];

	white(MARGIN, UI_TOP, "Wallet (hide test)");
	snprintf(l, sizeof l, "Demo key: %02X%02X%02X%02X %02X%02X%02X%02X ...", demo_key[0], demo_key[1], demo_key[2], demo_key[3], demo_key[4], demo_key[5], demo_key[6], demo_key[7]);
	white(MARGIN, 40, l);
	music_line(70);
	dim(MARGIN, 100, "PIN tries used: ");
	snprintf(l, sizeof l, "%d of %d", pin.tries, HIDE_MAX_TRIES);
	white(MARGIN + 17 * font_cell_w(), 100, l);
	text(MARGIN, UI_HINT1, ICO_CROSS " entropy menu    hold " ICO_L1 ICO_L2 ICO_R1 ICO_R2 " 1 s: CD player", 255, 255, 255);
}

static void draw_entropy(void)
{
	char l[80];

	white(MARGIN, UI_TOP, "Entropy sources");
	dim(MARGIN, 34, "Joystick   on");
	dim(MARGIN, 54, "Coin       off");
	dim(MARGIN, 74, "Dice       off");
	white(MARGIN, 94, "CD seek timing");
	music_line(124);
	if (music != M_OFF) dim(MARGIN, 144, "A CD sample moves the head: pause or stop the music first.");
	if (have_seek) {
		unsigned us = last_seek.seek / (CD_TICKS_PER_MS / 1000);

		snprintf(l, sizeof l, "Sample %d: seek %u.%02u ms", nsamples, us / 1000, (us % 1000) / 10);
		white(MARGIN, 164, l);
	}
	text(MARGIN, UI_HINT1, ICO_CROSS " CD sample   " ICO_SQUARE " pause / resume music   " ICO_TRIANGLE " music off", 255, 255, 255);
	text(MARGIN, UI_HINT2, ICO_CIRCLE " back", 255, 255, 255);
}

static void draw_player(void)
{
	char l[48], t1[16], t2[16];

	white(MARGIN, UI_TOP, "CD PLAYER");
	if (!disc_ok) {
		ctext(70, disc_tried ? (disc_rc == CD_NO_DISC ? "NO DISC" : "DRIVE ERROR") : "STOP", 255, 255, 255);
		dim(MARGIN, 120, disc_tried ? "Insert an audio disc and close the lid." : "Press " ICO_CROSS " to read the disc.");
	} else {
		unsigned len = track_len_sec(track), el = have_pos && music != M_OFF ? (unsigned) pos.rel_min * 60 + pos.rel_sec : 0;

		snprintf(l, sizeof l, "TRACK %02d", track);
		font_draw_big(&ctx, 0, (SW - 8 * 40) / 2, 40, l, 2, bright, NULL);
		time_str(t1, sizeof t1, el);
		time_str(t2, sizeof t2, len);
		snprintf(l, sizeof l, "%s / %s", t1, t2);
		ctext(100, l, 255, 255, 255);
		gpu_draw_rect(&ctx, 8, 60, 134, 520, 6, 60, 60, 90);
		if (len && el <= len) gpu_draw_rect(&ctx, 7, 60, 134, (int) (520u * el / len), 6, 120, 200, 255);
		ctext(152, music == M_PLAY ? "PLAY" : music == M_PAUSE ? "PAUSE" : "STOP", 120, 220, 255);
	}
	text(MARGIN, UI_HINT1, ICO_CROSS " play / pause   " ICO_SQUARE " stop   " ICO_LEFT ICO_RIGHT " track", 255, 255, 255);
}

static void draw_pin(void)
{
	char l[48];

	white(MARGIN, UI_TOP, "CD PLAYER");
	dim(MARGIN, 34, "Code");
	draw_dial(70);
	if (pin.tries) {
		snprintf(l, sizeof l, "Wrong code. %d tries left.", hide_pin_tries_left(&pin));
		text(MARGIN, 130, l, 255, 120, 120);
	}
	text(MARGIN, UI_HINT1, ICO_UPDOWN " digit   " ICO_CROSS " take   " ICO_CIRCLE " delete / back", 255, 255, 255);
}

static void draw_locked(void)
{
	char l[48];

	white(MARGIN, UI_TOP, "Locked");
	text(MARGIN, 40, "Too many wrong PINs.", 255, 120, 120);
	dim(MARGIN, 64, "The keys were wiped from RAM; the password is needed again.");
	snprintf(l, sizeof l, "Demo key now: %02X%02X%02X%02X %02X%02X%02X%02X ...", demo_key[0], demo_key[1], demo_key[2], demo_key[3], demo_key[4], demo_key[5], demo_key[6], demo_key[7]);
	white(MARGIN, 100, l);
	text(MARGIN, UI_HINT2, ICO_START " start over (test)", 255, 255, 255);
}

/* ---- logic ---- */
static void to_state(int s)
{
	state = s;
	hide_gesture_init(&gest, s == S_PLAYER);        /* the chord alone hides the wallet; in the player the DOWN follow-up is needed */
	hide_dial_init(&dial);
}

static void fill_key(void)
{
	for (int i = 0; i < (int) sizeof demo_key; i++) demo_key[i] = (uint8_t) (0x5A ^ (i * 37));
}

int main(void)
{
	int last_frame = -1, nframe = 0;

	gpu_init(&ctx, 16, 16, 40);
	font_init(1);
	ticks_init();
	input_init(&in);
	hide_clock_init(&clk, ticks_cycles());
	hide_pin_clear(&pin);
	fill_key();
	to_state(S_SET1);

	for (;;) {
		input_poll(&in, NULL);
		uint32_t now = hide_clock_update(&clk, ticks_cycles());
		int f = VSync(-1);
		if (f == last_frame) continue;
		last_frame = f;
		nframe++;
		uint16_t pr = input_take_pressed(&in);

		if (state == S_WALLET || state == S_PLAYER) {
			int ev = hide_gesture_update(&gest, in.ps.buttons, now);
			if (state == S_WALLET && ev == HIDE_EV_CHORD) { to_state(S_PLAYER); hide_gesture_hold_off(&gest); pr = 0; }
			else if (state == S_PLAYER && ev == HIDE_EV_UNLOCK) { to_state(S_PIN); pr = 0; }
		}

		if (nframe % 20 == 0) refresh_pos();
		if (msg_frames > 0) msg_frames--;

		switch (state) {
		case S_SET1:
		case S_SET2: {
			int r = hide_dial_update(&dial, pr);
			if (r == HIDE_DIAL_DONE && state == S_SET1) {
				memcpy(first, dial.digits, sizeof first);
				to_state(S_SET2);
			} else if (r == HIDE_DIAL_DONE) {
				if (memcmp(first, dial.digits, HIDE_PIN_LEN) == 0) {
					hide_pin_set(&pin, dial.digits);
					to_state(S_INFO);
				} else {
					say("The two PINs differ. Start again.");
					to_state(S_SET1);
				}
				secure_zero(first, sizeof first);
			} else if (r == HIDE_DIAL_CANCEL && state == S_SET2) {
				secure_zero(first, sizeof first);
				to_state(S_SET1);
			}
			break;
		}
		case S_INFO:
			if (pr & PAD_CROSS) to_state(S_WALLET);
			break;
		case S_WALLET:
			if (pr & PAD_CROSS) to_state(S_ENTROPY);
			break;
		case S_ENTROPY:
			if (act == A_NONE) {
				if (pr & PAD_CIRCLE) to_state(S_WALLET);
				else if (pr & PAD_SQUARE) { if (music != M_OFF) { act = A_MUSIC_PAUSE; busy = "Working..."; } }
				else if (pr & PAD_TRIANGLE) { if (music != M_OFF) { act = A_MUSIC_OFF; busy = "Working..."; } }
				else if (pr & PAD_CROSS) {
					if (music == M_PLAY) say("Music is playing: pause or stop it first");
					else { act = A_SAMPLE; busy = disc_ok ? "Seeking..." : "Reading the disc..."; }
				}
			}
			break;
		case S_PLAYER:
			if (act == A_NONE) {
				if (pr & PAD_CROSS) { act = A_PLAY_PAUSE; busy = disc_ok ? "Working..." : "Reading the disc..."; }
				else if (pr & PAD_SQUARE) { act = A_STOP; busy = "Working..."; }
				else if (pr & PAD_RIGHT) { act = A_NEXT; busy = disc_ok ? "Working..." : "Reading the disc..."; }
				else if (pr & PAD_LEFT) { act = A_PREV; busy = disc_ok ? "Working..." : "Reading the disc..."; }
			}
			break;
		case S_PIN: {
			int r = hide_dial_update(&dial, pr);
			if (r == HIDE_DIAL_CANCEL) {
				to_state(S_PLAYER);
			} else if (r == HIDE_DIAL_DONE) {
				int c = hide_pin_check(&pin, dial.digits);
				if (c == HIDE_PIN_OK) {
					to_state(S_WALLET);
				} else if (c == HIDE_PIN_LOCKED) {
					secure_zero(demo_key, sizeof demo_key);
					music_off();
					to_state(S_LOCKED);
				} else {
					hide_dial_wipe(&dial);
					hide_dial_init(&dial);
				}
			}
			break;
		}
		case S_LOCKED:
			if (pr & PAD_START) {
				hide_pin_clear(&pin);
				fill_key();
				to_state(S_SET1);
			}
			break;
		}

		switch (state) {
		case S_SET1: draw_set(0); break;
		case S_SET2: draw_set(1); break;
		case S_INFO: draw_info(); break;
		case S_WALLET: draw_wallet(); break;
		case S_ENTROPY: draw_entropy(); break;
		case S_PLAYER: draw_player(); break;
		case S_PIN: draw_pin(); break;
		case S_LOCKED: draw_locked(); break;
		}
		if (act != A_NONE && busy) ctext(UI_HINT2 - 24, busy, 255, 220, 80);
		else if (msg_frames > 0) ctext(UI_HINT2 - 24, msg, 255, 220, 80);
		gpu_present(&ctx);

		if (act != A_NONE) {                      /* the drive works after the frame that says so has been shown */
			int a = act;
			act = A_NONE;
			busy = NULL;
			do_act(a);
			hide_clock_update(&clk, ticks_cycles());
			hide_gesture_init(&gest, state == S_PLAYER);
		}
	}
	return 0;
}
