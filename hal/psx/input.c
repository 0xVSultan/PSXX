#include "input.h"
#include "timer.h"
#include <psxgpu.h>

void input_init(input_state *in)
{
	in->ps.buttons = 0;
	in->ps.id = 0;
	for (int i = 0; i < 4; i++) in->ps.stick[i] = 0x80;
	in->prev = 0;
	in->pressed_acc = 0;
	in->have_prev = 0;
	in->last_ok_frame = -1000;
	in->last_sample = 0;
	in->extra = NULL;
	for (int i = 0; i < 4; i++) in->stick_cell[i] = 0x80;
	pad_init();
}

int input_poll(input_state *in, entropy_pool *pool)
{
	pad_state now;
	if (pad_poll(&now)) return 0;
	uint32_t t = ticks_cycles();             /* sampled right after the controller answered */

	in->ps = now;
	in->last_ok_frame = VSync(-1);
	if (!in->have_prev) {
		in->prev = now.buttons;              /* buttons already held at start are not events */
		in->have_prev = 1;
	}
	uint16_t changed = in->prev ^ now.buttons;
	uint16_t pressed = changed & now.buttons, released = changed & in->prev;
	in->pressed_acc |= pressed;
	for (int k = 0; k < 2; k++) {                           /* the pool of the caller, and the extra one (not twice when they are the same) */
		entropy_pool *p = k ? in->extra : pool;
		if (!p || (k && p == pool)) continue;
		if (pressed) {
			entropy_add_context(p, pressed);
			entropy_add_timing(p, ENTROPY_SRC_PAD_PRESS, t);
			in->last_sample = t;
		}
		if (released) {
			entropy_add_context(p, 0x10000u | released);
			entropy_add_timing(p, ENTROPY_SRC_PAD_RELEASE, t);
			in->last_sample = t;
		}
	}
	/* The analog sticks (a DualShock in analog mode; L3 and R3 are buttons above): a move of 16 steps or more from the last hashed position is an event, its timing goes through
	 * the same estimator as the buttons' (a regular sweep earns nothing, an irregular hand does) and the raw positions, noise included, are hashed along. */
	if (now.id == 0x73 || now.id == 0x53) {
		int moved = 0;

		for (int i = 0; i < 4; i++) {
			int d = (int) now.stick[i] - (int) in->stick_cell[i];
			if (d >= 16 || d <= -16) moved = 1;               /* 16 steps away from the last hashed position: not the noise around the centre */
		}
		if (moved) {
			uint32_t pos = (uint32_t) now.stick[0] | (uint32_t) now.stick[1] << 8 | (uint32_t) now.stick[2] << 16 | (uint32_t) now.stick[3] << 24;

			for (int k = 0; k < 2; k++) {
				entropy_pool *p = k ? in->extra : pool;
				if (!p || (k && p == pool)) continue;
				entropy_add_context(p, pos);
				entropy_add_timing(p, ENTROPY_SRC_PAD_STICK, t);
				in->last_sample = t;
			}
			for (int i = 0; i < 4; i++) in->stick_cell[i] = now.stick[i];
		}
	}
	in->prev = now.buttons;
	return 1;
}

uint16_t input_take_pressed(input_state *in)
{
	uint16_t p = in->pressed_acc;
	in->pressed_acc = 0;
	return p;
}

int input_present(const input_state *in)
{
	return VSync(-1) - in->last_ok_frame < 6;   /* a single failed poll must not flash "none" */
}
