#include "mcard.h"
#include <hwregs_c.h>

#define IRQ_CONTROLLER (1 << 7)
#define ACK_TIMEOUT 20000
#define RX_TIMEOUT 20000

static void delay(int n) { for (volatile int i = 0; i < n; i++) {} }

static int xfer(uint8_t tx, uint8_t *rx, int wait_ack)
{
	IRQ_STAT = (uint16_t) ~IRQ_CONTROLLER;
	SIO_CTRL(0) |= 0x10;
	SIO_DATA(0) = tx;
	for (int i = 0; !(SIO_STAT(0) & 2); i++)
		if (i > RX_TIMEOUT) return MC_NO_CARD;
	*rx = SIO_DATA(0);
	if (wait_ack) {
		for (int i = 0; !(IRQ_STAT & IRQ_CONTROLLER); i++)
			if (i > ACK_TIMEOUT) return MC_NO_CARD;
	}
	return MC_OK;
}

/* One transaction: 81h, command (R/W), 00h 00h, address, then 128 data bytes with checksum and end bytes. */
static int transaction(int port, int frame, int write, const uint8_t *in, uint8_t *out)
{
	uint8_t msb = (uint8_t) (frame >> 8), lsb = (uint8_t) frame, rx = 0, sum = (uint8_t) (msb ^ lsb);
	int r;

	if (frame < 0 || frame > 1023) return MC_BAD_ADDR;
	SIO_CTRL(0) = (uint16_t) (0x1003 | (port ? 0x2000 : 0));
	delay(100);

#define TX(b, ack) do { r = xfer((b), &rx, (ack)); if (r) goto done; } while (0)
	TX(0x81, 1);
	TX(write ? 0x57 : 0x52, 1);
	TX(0x00, 1);
	if (rx != 0x5A) { r = MC_BAD_ID; goto done; }                       /* card ID 1 */
	TX(0x00, 1);
	if (rx != 0x5D) { r = MC_BAD_ID; goto done; }                       /* card ID 2 */
	TX(msb, 1);
	TX(lsb, 1);
	if (write) {
		for (int i = 0; i < MC_FRAME; i++) { sum ^= in[i]; TX(in[i], 1); }
		TX(sum, 1);
		TX(0x00, 1);                                                    /* ack 1 (5Ch) */
		TX(0x00, 1);                                                    /* ack 2 (5Dh) */
		TX(0x00, 0);                                                    /* end byte: 47h = good */
		r = rx == 0x47 ? MC_OK : (rx == 0x4E ? MC_BAD_SUM : MC_BAD_ADDR);
	} else {
		TX(0x00, 1);                                                    /* 5Ch */
		TX(0x00, 1);                                                    /* 5Dh */
		TX(0x00, 1);                                                    /* confirmed address MSB */
		if (rx != msb) { r = MC_BAD_ADDR; goto done; }
		TX(0x00, 1);                                                    /* confirmed address LSB */
		for (int i = 0; i < MC_FRAME; i++) { TX(0x00, 1); out[i] = rx; sum ^= rx; }
		TX(0x00, 1);                                                    /* checksum */
		if (rx != sum) { r = MC_BAD_SUM; goto done; }
		TX(0x00, 0);                                                    /* end byte */
		r = rx == 0x47 ? MC_OK : MC_BAD_ADDR;
	}
#undef TX
done:
	SIO_CTRL(0) = 0;
	return r;
}

static int run(int port, int frame, int write, const uint8_t *in, uint8_t *out)
{
	uint16_t saved = IRQ_MASK;
	int r;

	IRQ_MASK = 0;                          /* a vertical blank handler must not touch SIO0 in the middle of a transfer */
	r = transaction(port, frame, write, in, out);
	IRQ_MASK = saved;
	return r;
}

int mc_read(int port, int frame, uint8_t out[MC_FRAME]) { return run(port, frame, 0, 0, out); }
int mc_write(int port, int frame, const uint8_t in[MC_FRAME]) { return run(port, frame, 1, in, 0); }

/* Is there a card? The shortest exchange: select the slot, send 81h, see whether the card answers with its /ACK (about 0.12 ms; M0 measured it in no$psx and DuckStation). */
int mc_present(int port)
{
	uint16_t saved = IRQ_MASK;
	uint8_t rx = 0;
	int r;

	IRQ_MASK = 0;
	SIO_CTRL(0) = (uint16_t) (0x1003 | (port ? 0x2000 : 0));
	delay(100);
	r = xfer(0x81, &rx, 1);
	SIO_CTRL(0) = 0;
	IRQ_MASK = saved;
	return r == MC_OK;
}
