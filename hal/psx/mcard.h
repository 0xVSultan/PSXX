#pragma once
#include <stdint.h>

/* Polled memory card access on SIO0, no BIOS card functions and no interrupts (like pad.c). A card holds 1024 frames
 * of 128 bytes; block n (1..15) of the file system is frames 64 * n .. 64 * n + 63, frames 1..15 are the directory. */

#define MC_FRAME 128

enum { MC_OK = 0, MC_NO_CARD = -1, MC_BAD_ID = -2, MC_BAD_SUM = -3, MC_BAD_ADDR = -4 };

/* port 0 = slot 1, port 1 = slot 2. Return MC_OK or a negative MC_* code. */
int mc_read(int port, int frame, uint8_t out[MC_FRAME]);
int mc_write(int port, int frame, const uint8_t in[MC_FRAME]);
/* 1 if a card answers in the slot (one byte exchanged, no frame read), else 0. */
int mc_present(int port);
