#pragma once
#include <stdint.h>

/* "Hide wallet" mode: the console looks like a CD player until a secret gesture and a session PIN bring the wallet back.
 * Only logic, no hardware, so it is tested on the host (tests/test_hide.c). The buttons are the PAD_* masks of pad.h.
 *
 *  - Gesture: L1+L2+R1+R2 held for 1 s. In the wallet that hides it (the CD player comes up). In the player the same chord has to be
 *    followed, within 1 s of the end of that second, by DOWN held for 3 s (also with the chord released); then the PIN is asked.
 *  - PIN: HIDE_PIN_LEN digits, set once per session (typed twice). 5 wrong tries lock it: the keys are wiped by the caller and the
 *    full password is needed again. The counter lives in RAM next to the keys; a power cycle needs the password anyway.
 *  - The time is a millisecond counter that the caller keeps (hide_clock). */

#define HIDE_PIN_LEN 6
#define HIDE_MAX_TRIES 5
#define HIDE_CHORD_MS 1000          /* L1+L2+R1+R2 held */
#define HIDE_WINDOW_MS 1000         /* DOWN has to be pressed within this time after the chord */
#define HIDE_DOWN_MS 3000           /* DOWN held */

/* A millisecond clock from a free running cycle counter (wrap-safe as long as it is called more often than the counter wraps). */
typedef struct { uint32_t last, ms, rest; } hide_clock;
void hide_clock_init(hide_clock *c, uint32_t cycles);
/* `cycles` is the counter now (33.8688 MHz); returns the milliseconds since the init. */
uint32_t hide_clock_update(hide_clock *c, uint32_t cycles);

enum { HIDE_EV_NONE = 0, HIDE_EV_CHORD = 1, HIDE_EV_UNLOCK = 2 };

typedef struct {
	uint8_t  phase;
	uint8_t  need_down;      /* 0: the chord alone fires HIDE_EV_CHORD; 1: chord, then DOWN fires HIDE_EV_UNLOCK */
	uint32_t t;              /* start time of the current phase */
} hide_gesture;

void hide_gesture_init(hide_gesture *g, int need_down);
/* Feed the buttons held now and the time. Returns HIDE_EV_*. After an event nothing fires again until the chord and DOWN are released. */
int hide_gesture_update(hide_gesture *g, uint16_t held, uint32_t now_ms);
/* Ignore the buttons until the chord and DOWN are let go (after a switch caused by the gesture itself). */
void hide_gesture_hold_off(hide_gesture *g);
/* Progress for a UI (the tests only): 0 idle, 1 chord being held, 2 armed (waiting for DOWN), 3 DOWN being held. */
int hide_gesture_phase(const hide_gesture *g);

/* ---- the session PIN ---- */
enum { HIDE_PIN_OK = 0, HIDE_PIN_BAD = 1, HIDE_PIN_LOCKED = 2, HIDE_PIN_NONE = 3 };

typedef struct {
	uint8_t  digest[32];     /* SHA-256 of a tag and the digits (not a protection against a RAM dump: it only keeps the digits off the screen and out of plain RAM) */
	uint8_t  is_set;
	uint8_t  tries;          /* wrong tries since the last good one */
	uint8_t  locked;
} hide_pin;

void hide_pin_clear(hide_pin *p);
/* digits: HIDE_PIN_LEN characters '0'..'9'. Returns 0, or -1 for a bad string. */
int hide_pin_set(hide_pin *p, const char *digits);
/* HIDE_PIN_OK (the counter is reset), HIDE_PIN_BAD (one more try used), HIDE_PIN_LOCKED (this was the last try, or it was locked before), HIDE_PIN_NONE (no PIN set). */
int hide_pin_check(hide_pin *p, const char *digits);
int hide_pin_tries_left(const hide_pin *p);

/* ---- typing a PIN with the pad: UP / DOWN change the digit, CROSS takes it, CIRCLE deletes the last one (or cancels when it is empty) ---- */
enum { HIDE_DIAL_EDIT = 0, HIDE_DIAL_DONE = 1, HIDE_DIAL_CANCEL = 2 };

typedef struct {
	char    digits[HIDE_PIN_LEN + 1];
	uint8_t n;               /* digits taken */
	uint8_t cur;             /* the digit being chosen, 0..9 */
} hide_dial;

void hide_dial_init(hide_dial *d);
/* `pressed`: the buttons newly pressed since the last call. Returns HIDE_DIAL_*; DONE when the last digit was taken. */
int hide_dial_update(hide_dial *d, uint16_t pressed);
/* Overwrite the digits (after use). */
void hide_dial_wipe(hide_dial *d);
