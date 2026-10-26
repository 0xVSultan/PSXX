#pragma once
#include <stdint.h>

/* Free running time base from root counter 2 (system clock / 8), extended to 32 bits in software. */

void ticks_init(void);

/* CPU clock cycles (33.8688 MHz) since ticks_init(), modulo 2^32 (wraps after ~127 s; use wrap-safe differences).
 * Resolution is 8 cycles. Must be called at least every ~15 ms, otherwise a 16 bit wrap of the hardware counter is missed. */
uint32_t ticks_cycles(void);
