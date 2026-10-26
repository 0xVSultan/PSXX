#pragma once
#include <stdint.h>

/* Polled controller access on SIO0 / port 1, no interrupts and no SDK pad library (works when booted from a
 * FreePSXBoot card, where the kernel's interrupt handling is not the SDK's). One poll takes about 0.3-0.6 ms. */

enum {
	PAD_SELECT = 1 << 0,  PAD_L3 = 1 << 1,  PAD_R3 = 1 << 2,  PAD_START = 1 << 3,
	PAD_UP = 1 << 4,      PAD_RIGHT = 1 << 5, PAD_DOWN = 1 << 6, PAD_LEFT = 1 << 7,
	PAD_L2 = 1 << 8,      PAD_R2 = 1 << 9,  PAD_L1 = 1 << 10,  PAD_R1 = 1 << 11,
	PAD_TRIANGLE = 1 << 12, PAD_CIRCLE = 1 << 13, PAD_CROSS = 1 << 14, PAD_SQUARE = 1 << 15
};

typedef struct {
	uint16_t buttons;   /* bit set = pressed (see PAD_*) */
	uint8_t  id;        /* 0x41 digital, 0x73 analog (DualShock), 0x53 analog joystick */
	uint8_t  stick[4];  /* right X, right Y, left X, left Y (0x80 = centre) when the pad is analog, else 0x80 */
} pad_state;

/* Diagnostics: how many polls worked and why the last failing one failed. */
typedef struct {
	uint32_t polls, ok, fail, retries;   /* retries: polls that needed a second attempt */
	uint8_t  err;       /* 1 = RX timeout, 2 = /ACK timeout, 3 = bad header */
	uint8_t  err_byte;  /* index of the byte in the 9 byte frame where it happened */
	uint8_t  err_id, err_hdr;   /* bytes 1 and 2 received in the failing poll */
} pad_stats;
const pad_stats *pad_get_stats(void);

void pad_init(void);
/* Returns 0 and fills `s` when a pad answered, -1 when nothing is connected. */
int pad_poll(pad_state *s);
