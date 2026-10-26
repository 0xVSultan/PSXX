#include "hide.h"
#include <string.h>
#include "pad.h"
#include "hash/sha256.h"
#include "util.h"

#define CYC_MS 33869u

void hide_clock_init(hide_clock *c, uint32_t cycles)
{
	c->last = cycles;
	c->ms = c->rest = 0;
}

uint32_t hide_clock_update(hide_clock *c, uint32_t cycles)
{
	uint32_t d = cycles - c->last;      /* wraps right */

	c->last = cycles;
	c->rest += d;
	c->ms += c->rest / CYC_MS;
	c->rest %= CYC_MS;
	return c->ms;
}

/* ---- gesture ---- */
enum { G_IDLE, G_CHORD, G_ARMED, G_DOWN, G_WAIT };

#define CHORD (PAD_L1 | PAD_L2 | PAD_R1 | PAD_R2)

void hide_gesture_init(hide_gesture *g, int need_down)
{
	g->phase = G_IDLE;
	g->need_down = need_down != 0;
	g->t = 0;
}

void hide_gesture_hold_off(hide_gesture *g) { g->phase = G_WAIT; }

int hide_gesture_phase(const hide_gesture *g)
{
	switch (g->phase) {
	case G_CHORD: return 1;
	case G_ARMED: return 2;
	case G_DOWN: return 3;
	default: return 0;
	}
}

int hide_gesture_update(hide_gesture *g, uint16_t held, uint32_t now)
{
	int chord = (held & CHORD) == CHORD;

	switch (g->phase) {
	case G_IDLE:
		if (chord) { g->phase = G_CHORD; g->t = now; }
		break;
	case G_CHORD:
		if (!chord) { g->phase = G_IDLE; break; }
		if (now - g->t >= HIDE_CHORD_MS) {
			if (!g->need_down) { g->phase = G_WAIT; return HIDE_EV_CHORD; }
			g->phase = G_ARMED;
			g->t = now;
		}
		break;
	case G_ARMED:
		if (held & PAD_DOWN) { g->phase = G_DOWN; g->t = now; break; }
		if (now - g->t > HIDE_WINDOW_MS) g->phase = G_WAIT;     /* too late: nothing until everything is let go */
		break;
	case G_DOWN:
		if (!(held & PAD_DOWN)) { g->phase = G_WAIT; break; }
		if (now - g->t >= HIDE_DOWN_MS) { g->phase = G_WAIT; return HIDE_EV_UNLOCK; }
		break;
	default:                                                     /* G_WAIT */
		if (!chord && !(held & PAD_DOWN)) g->phase = G_IDLE;
		break;
	}
	return HIDE_EV_NONE;
}

/* ---- PIN ---- */
static int digits_ok(const char *s)
{
	for (int i = 0; i < HIDE_PIN_LEN; i++)
		if (s[i] < '0' || s[i] > '9') return 0;
	return s[HIDE_PIN_LEN] == 0;
}

static void digest_of(const char *digits, uint8_t out[32])
{
	sha256_ctx c;

	sha256_init(&c);
	sha256_update(&c, (const uint8_t *) "psxx-hide-pin", 13);
	sha256_update(&c, (const uint8_t *) digits, HIDE_PIN_LEN);
	sha256_final(&c, out);
	secure_zero(&c, sizeof c);
}

void hide_pin_clear(hide_pin *p)
{
	secure_zero(p, sizeof *p);
}

int hide_pin_set(hide_pin *p, const char *digits)
{
	if (!digits_ok(digits)) return -1;
	digest_of(digits, p->digest);
	p->is_set = 1;
	p->tries = 0;
	p->locked = 0;
	return 0;
}

int hide_pin_tries_left(const hide_pin *p)
{
	return p->locked ? 0 : HIDE_MAX_TRIES - p->tries;
}

int hide_pin_check(hide_pin *p, const char *digits)
{
	uint8_t d[32];
	uint32_t diff = 0;

	if (!p->is_set) return HIDE_PIN_NONE;
	if (p->locked) return HIDE_PIN_LOCKED;
	p->tries++;                                  /* counted first, taken back on success */
	if (!digits_ok(digits)) memset(d, 0xFF, sizeof d);
	else digest_of(digits, d);
	for (int i = 0; i < 32; i++) diff |= (uint32_t) (d[i] ^ p->digest[i]);
	secure_zero(d, sizeof d);
	if (diff == 0) {
		p->tries = 0;
		return HIDE_PIN_OK;
	}
	if (p->tries >= HIDE_MAX_TRIES) {
		p->locked = 1;
		secure_zero(p->digest, sizeof p->digest);
		return HIDE_PIN_LOCKED;
	}
	return HIDE_PIN_BAD;
}

/* ---- dial ---- */
void hide_dial_init(hide_dial *d)
{
	memset(d, 0, sizeof *d);
}

void hide_dial_wipe(hide_dial *d)
{
	secure_zero(d, sizeof *d);
}

int hide_dial_update(hide_dial *d, uint16_t pressed)
{
	if (pressed & PAD_UP) d->cur = (uint8_t) (d->cur == 9 ? 0 : d->cur + 1);
	if (pressed & PAD_DOWN) d->cur = (uint8_t) (d->cur == 0 ? 9 : d->cur - 1);
	if (pressed & PAD_CIRCLE) {
		if (d->n == 0) return HIDE_DIAL_CANCEL;
		d->digits[--d->n] = 0;
		d->cur = 0;
		return HIDE_DIAL_EDIT;
	}
	if (pressed & PAD_CROSS) {
		d->digits[d->n++] = (char) ('0' + d->cur);
		d->digits[d->n] = 0;
		d->cur = 0;
		if (d->n == HIDE_PIN_LEN) return HIDE_DIAL_DONE;
	}
	return HIDE_DIAL_EDIT;
}
