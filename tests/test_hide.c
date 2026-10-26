/* Host test of the hide-wallet logic (hal/psx/hide.c): the gesture timing, the PIN and its lock, the dial, the millisecond clock. */
#include <stdio.h>
#include <string.h>
#include "hide.h"
#include "pad.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

#define CHORD (PAD_L1 | PAD_L2 | PAD_R1 | PAD_R2)

/* run the detector from t0 to t1 in 16 ms steps with the buttons `held`; returns the first event and its time in *at */
static int run(hide_gesture *g, uint16_t held, uint32_t t0, uint32_t t1, uint32_t *at)
{
	for (uint32_t t = t0; t <= t1; t += 16) {
		int e = hide_gesture_update(g, held, t);
		if (e) { if (at) *at = t; return e; }
	}
	return HIDE_EV_NONE;
}

static void test_chord(void)
{
	hide_gesture g;
	uint32_t at = 0;

	hide_gesture_init(&g, 0);
	CHECK(run(&g, CHORD, 0, 900, &at) == HIDE_EV_NONE);                     /* not yet */
	CHECK(run(&g, CHORD, 912, 1100, &at) == HIDE_EV_CHORD);
	CHECK(at >= 1000 && at < 1040);
	CHECK(run(&g, CHORD, 1120, 5000, NULL) == HIDE_EV_NONE);                /* once only while held */
	CHECK(run(&g, 0, 5008, 5200, NULL) == HIDE_EV_NONE);                    /* released: ready again */
	CHECK(run(&g, CHORD, 5300, 6400, NULL) == HIDE_EV_CHORD);

	hide_gesture_init(&g, 0);                                               /* three of the four buttons never count */
	CHECK(run(&g, PAD_L1 | PAD_L2 | PAD_R1, 0, 3000, NULL) == HIDE_EV_NONE);
	hide_gesture_init(&g, 0);                                               /* let go after 800 ms: starts over */
	CHECK(run(&g, CHORD, 0, 800, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, 0, 816, 900, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, CHORD, 916, 1700, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, CHORD, 1716, 2000, NULL) == HIDE_EV_CHORD);
}

static void test_unlock(void)
{
	hide_gesture g;
	uint32_t at = 0;

	/* chord 1 s, then DOWN pressed 100 ms later and held 3 s (chord released meanwhile) */
	hide_gesture_init(&g, 1);
	CHECK(run(&g, CHORD, 0, 1100, NULL) == HIDE_EV_NONE);                   /* the chord alone is not enough in the player */
	CHECK(hide_gesture_phase(&g) == 2);
	CHECK(run(&g, PAD_DOWN, 1116, 1400, NULL) == HIDE_EV_NONE);
	CHECK(hide_gesture_phase(&g) == 3);
	CHECK(run(&g, PAD_DOWN, 1416, 4000, NULL) == HIDE_EV_NONE);             /* not yet 3 s of DOWN */
	CHECK(run(&g, PAD_DOWN, 4016, 4600, &at) == HIDE_EV_UNLOCK);
	CHECK(at >= 4116 && at < 4140);                                         /* DOWN went down at 1116 */

	/* DOWN too late (the window is 1 s after the chord second) */
	hide_gesture_init(&g, 1);
	CHECK(run(&g, CHORD, 0, 1100, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, 0, 1116, 2300, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, PAD_DOWN, 2316, 6000, NULL) == HIDE_EV_NONE);             /* never fires: the sequence timed out */
	CHECK(hide_gesture_phase(&g) == 0);

	/* DOWN released early starts over */
	hide_gesture_init(&g, 1);
	CHECK(run(&g, CHORD, 0, 1100, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, PAD_DOWN, 1116, 3000, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, 0, 3016, 3100, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, PAD_DOWN, 3116, 7000, NULL) == HIDE_EV_NONE);

	/* DOWN held together with the chord from the start: it counts from the end of the chord second */
	hide_gesture_init(&g, 1);
	CHECK(run(&g, CHORD | PAD_DOWN, 0, 1100, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, CHORD | PAD_DOWN, 1116, 4300, &at) == HIDE_EV_UNLOCK);
	CHECK(at >= 4024 && at < 4060);

	/* a plain DOWN without the chord does nothing */
	hide_gesture_init(&g, 1);
	CHECK(run(&g, PAD_DOWN, 0, 10000, NULL) == HIDE_EV_NONE);

	/* hold-off after a switch: the chord still held does not start the next sequence */
	hide_gesture_init(&g, 1);
	hide_gesture_hold_off(&g);
	CHECK(run(&g, CHORD, 0, 5000, NULL) == HIDE_EV_NONE);
	CHECK(hide_gesture_phase(&g) == 0);
	CHECK(run(&g, 0, 5016, 5100, NULL) == HIDE_EV_NONE);
	CHECK(run(&g, CHORD, 5116, 6200, NULL) == HIDE_EV_NONE && hide_gesture_phase(&g) == 2);
}

static void test_pin(void)
{
	hide_pin p;

	hide_pin_clear(&p);
	CHECK(hide_pin_check(&p, "123456") == HIDE_PIN_NONE);
	CHECK(hide_pin_set(&p, "12345") == -1);
	CHECK(hide_pin_set(&p, "12345a") == -1);
	CHECK(hide_pin_set(&p, "1234567") == -1);
	CHECK(hide_pin_set(&p, "123456") == 0);
	CHECK(hide_pin_check(&p, "123456") == HIDE_PIN_OK);
	CHECK(hide_pin_check(&p, "123457") == HIDE_PIN_BAD && p.tries == 1);
	CHECK(hide_pin_tries_left(&p) == 4);
	CHECK(hide_pin_check(&p, "123456") == HIDE_PIN_OK && p.tries == 0);    /* a good one resets the counter */
	for (int i = 0; i < 4; i++) CHECK(hide_pin_check(&p, "000000") == HIDE_PIN_BAD);
	CHECK(hide_pin_tries_left(&p) == 1);
	CHECK(hide_pin_check(&p, "000000") == HIDE_PIN_LOCKED);                 /* the fifth wrong one */
	CHECK(hide_pin_check(&p, "123456") == HIDE_PIN_LOCKED);                 /* even the right one is refused now */
	CHECK(hide_pin_tries_left(&p) == 0);
	{
		uint8_t z[32] = {0};
		CHECK(memcmp(p.digest, z, 32) == 0);                                /* the digest is gone with the lock */
	}
	CHECK(hide_pin_set(&p, "654321") == 0 && p.locked == 0);                /* a new session */
	CHECK(hide_pin_check(&p, "654321") == HIDE_PIN_OK);
	CHECK(hide_pin_check(&p, "12") == HIDE_PIN_BAD);                        /* malformed input is a wrong try, not a crash */
}

static void test_dial(void)
{
	hide_dial d;

	hide_dial_init(&d);
	CHECK(hide_dial_update(&d, PAD_UP) == HIDE_DIAL_EDIT && d.cur == 1);
	CHECK(hide_dial_update(&d, PAD_DOWN) == HIDE_DIAL_EDIT && d.cur == 0);
	CHECK(hide_dial_update(&d, PAD_DOWN) == HIDE_DIAL_EDIT && d.cur == 9);  /* wraps */
	CHECK(hide_dial_update(&d, PAD_UP) == HIDE_DIAL_EDIT && d.cur == 0);
	CHECK(hide_dial_update(&d, PAD_UP) == HIDE_DIAL_EDIT);
	CHECK(hide_dial_update(&d, PAD_UP) == HIDE_DIAL_EDIT);
	CHECK(hide_dial_update(&d, PAD_CROSS) == HIDE_DIAL_EDIT && d.n == 1 && d.digits[0] == '2' && d.cur == 0);
	CHECK(hide_dial_update(&d, PAD_CIRCLE) == HIDE_DIAL_EDIT && d.n == 0);  /* delete */
	CHECK(hide_dial_update(&d, PAD_CIRCLE) == HIDE_DIAL_CANCEL);            /* empty: cancel */
	for (int i = 0; i < HIDE_PIN_LEN - 1; i++) CHECK(hide_dial_update(&d, PAD_CROSS) == HIDE_DIAL_EDIT);
	CHECK(hide_dial_update(&d, PAD_UP | PAD_CROSS) == HIDE_DIAL_DONE);      /* the digit changes first, then it is taken */
	CHECK(strcmp(d.digits, "000001") == 0);
	hide_dial_wipe(&d);
	CHECK(d.n == 0 && d.digits[0] == 0);
}

static void test_clock(void)
{
	hide_clock c;
	uint32_t cyc = 0xFFFFFF00u;                                             /* starts just before the wrap of the cycle counter */

	hide_clock_init(&c, cyc);
	for (int i = 0; i < 3000; i++) {
		cyc += 33869u / 2;                                                  /* half a millisecond a step */
		hide_clock_update(&c, cyc);
	}
	CHECK(c.ms >= 1498 && c.ms <= 1500);
}

int main(void)
{
	test_chord();
	test_unlock();
	test_pin();
	test_dial();
	test_clock();
	printf("hide: %d failure(s)\n", fails);
	return fails != 0;
}
