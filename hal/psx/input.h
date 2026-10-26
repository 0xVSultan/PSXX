#pragma once
#include <stdint.h>
#include "pad.h"
#include "entropy.h"

/* Controller input for the apps: polls the pad, tracks button edges for menu navigation and (optionally) feeds
 * every press/release into the entropy pool with a root counter time stamp taken right after the pad answered. */

typedef struct {
	pad_state ps;            /* last good pad state */
	uint16_t  prev;          /* buttons at the previous successful poll */
	uint16_t  pressed_acc;   /* buttons newly pressed since input_take_pressed() */
	int       have_prev;
	int       last_ok_frame; /* VSync counter at the last successful poll */
	uint8_t   stick_cell[4]; /* the analog sticks at the last hashed move */
	uint32_t  last_sample;   /* last time stamp fed to the pool */
	entropy_pool *extra;     /* a second pool that gets every event too (the background pool of the generator), or NULL */
} input_state;

void input_init(input_state *in);
/* One poll. If `pool` is not NULL, press and release events are added to it (and to in->extra, if that is set and a different pool). Returns 1 if the pad answered. */
int input_poll(input_state *in, entropy_pool *pool);
/* Buttons newly pressed since the last call (edges are accumulated between UI updates), then cleared. */
uint16_t input_take_pressed(input_state *in);
/* 1 unless the pad has not answered for several frames. */
int input_present(const input_state *in);
