#include "timer.h"
#include <hwregs_c.h>

#define TIMER 2

static uint16_t last;
static uint32_t total;          /* in units of 8 CPU cycles */

void ticks_init(void)
{
	TIMER_CTRL(TIMER) = 0x0200;  /* free run, clock source = system clock / 8 (bit 9 on timer 2) */
	TIMER_VALUE(TIMER) = 0;
	last = 0;
	total = 0;
}

uint32_t ticks_cycles(void)
{
	uint16_t cur = (uint16_t) TIMER_VALUE(TIMER);
	total += (uint16_t) (cur - last);
	last = cur;
	return total * 8;
}
