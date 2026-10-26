#include "pad.h"
#include <hwregs_c.h>

#define IRQ_CONTROLLER (1 << 7)     /* I_STAT bit raised by the /ACK pulse of the device */
#define ACK_TIMEOUT 10000
#define RX_TIMEOUT 10000

static void delay(int n) { for (volatile int i = 0; i < n; i++) {} }

void pad_init(void)
{
	SIO_CTRL(0) = 0x40;          /* reset */
	delay(10);
	SIO_BAUD(0) = 0x88;
	SIO_MODE(0) = 0x0D;          /* 8 bit, x1 */
	SIO_CTRL(0) = 0;
}

/* Send one byte, return the byte received at the same time. wait_ack: wait for the device's /ACK afterwards
 * (every byte but the last). Returns 0, 1 on an RX timeout, 2 on an /ACK timeout. */
static int xfer(uint8_t tx, uint8_t *rx, int wait_ack)
{
	IRQ_STAT = (uint16_t) ~IRQ_CONTROLLER;
	SIO_CTRL(0) |= 0x10;                       /* acknowledge the SIO interrupt flag */
	SIO_DATA(0) = tx;
	for (int i = 0; !(SIO_STAT(0) & 2); i++)   /* RX FIFO not empty */
		if (i > RX_TIMEOUT) return 1;
	*rx = SIO_DATA(0);
	if (wait_ack) {
		for (int i = 0; !(IRQ_STAT & IRQ_CONTROLLER); i++)
			if (i > ACK_TIMEOUT) return 2;
	}
	return 0;
}

static pad_stats stats;

const pad_stats *pad_get_stats(void) { return &stats; }

/* One attempt at a full poll. Returns 0 on success; otherwise 1 (RX timeout), 2 (/ACK timeout) or 3 (bad header),
 * and records where it went wrong in `stats`. */
static int poll_once(pad_state *s)
{
	static const uint8_t tx[9] = {0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t rx[9] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x80, 0x80, 0x80};
	int n = 9, err = 0, i;

	SIO_CTRL(0) = 0x1003;                      /* select port 1, enable TX and RX */
	delay(100);
	for (i = 0; i < n; i++) {
		err = xfer(tx[i], &rx[i], i != n - 1);
		if (err) break;
		if (i == 1) {                          /* rx[1] = pad ID; low nibble = number of 16 bit words that follow */
			int words = rx[1] & 0x0F;
			n = 3 + 2 * (words ? words : 16);
			if (n > 9) n = 9;
		}
	}
	SIO_CTRL(0) = 0;                           /* deselect */

	if (!err && rx[2] != 0x5A) err = 3;
	if (err) {
		stats.err = (uint8_t) err;
		stats.err_byte = (uint8_t) i;
		stats.err_id = rx[1];
		stats.err_hdr = rx[2];
		return err;
	}
	s->id = rx[1];
	s->buttons = (uint16_t) ~(rx[3] | (rx[4] << 8));
	for (int k = 0; k < 4; k++) s->stick[k] = rx[5 + k];
	return 0;
}

/* A DualShock starts in digital mode (id 0x41: no sticks, no L3 / R3) until the Analog button is pressed; DuckStation too. The program asks for the analog mode itself, with three
 * frames of nine bytes: the configuration mode, the mode analog (1) locked (3), and out of the configuration mode. The answers are not looked at (a digital pad does not know the
 * commands: the frame ends at the first byte it does not /ACK). */
static void set_analog(void)
{
	static const uint8_t cmd[3][9] = {{0x01, 0x43, 0x00, 0x01}, {0x01, 0x44, 0x00, 0x01, 0x03}, {0x01, 0x43, 0x00, 0x00, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A}};
	uint8_t rx;

	for (int c = 0; c < 3; c++) {
		SIO_CTRL(0) = 0x1003;
		delay(100);
		for (int i = 0; i < 9; i++)
			if (xfer(cmd[c][i], &rx, i != 8)) break;
		SIO_CTRL(0) = 0;
		delay(300);
	}
}

int pad_poll(pad_state *s)
{
	/* Defer all interrupts for the duration of the transfer (~0.5 ms): a vertical blank handler touching SIO0 in the
	 * middle of it breaks the exchange. The IRQ_STAT flags stay set, so the interrupt is delivered right afterwards. */
	uint16_t saved_mask = IRQ_MASK;
	IRQ_MASK = 0;

	stats.polls++;
	int r = poll_once(s);
	if (r) {                                   /* one immediate retry before reporting a failure */
		stats.retries++;
		r = poll_once(s);
	}
	if (r) stats.fail++; else stats.ok++;
	{                                          /* a pad that answers as a digital one is asked for the analog mode (a real digital pad does not know the command) */
		static uint8_t digital_polls;

		if (r || s->id != 0x41) digital_polls = 0;
		else if (++digital_polls == 30) set_analog();
	}

	IRQ_MASK = saved_mask;
	return r ? -1 : 0;
}
