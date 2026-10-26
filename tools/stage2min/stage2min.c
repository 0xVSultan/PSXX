/* The second stage of the boot card, in its smallest form (psx-x).
 *
 * FreePSXBoot's exploit (stage 1, frames 0..63 of the card) reads this stage into 0x8000D000 and runs it; it reads the program from the card with its own SIO0 code (the BIOS' card
 * routines are not used: they are what hangs on the BIOS 1.0 and 4.x) and starts it from a breakpoint on the copy of the shell (reboot.s), once the kernel is up. It is the stage2
 * of FreePSXBoot (builder/stage2/stage2.c) without the display set-up and progress bar, without the search for a header frame (the builder patches the frame numbers into `cfg`),
 * and with a polled card transfer of the same shape as hal/psx/mcard.c. 1760 bytes (14 frames) become about 600 (5 frames), and the frame of the header is gone.
 *
 * Layout of the binary (tools/stage2min/build.py): the code from 0x8000D000, `cfg` as its last 28 bytes. tools/stage2min/ is not part of FreePSXBoot; the builder takes the binary with -minload. */
#include <stdint.h>

/* the registers by their KSEG1 addresses (the same hardware as 0x1F80xxxx, and an address that an emulator test without the PSX memory map can run) */
#define R8(a) (*(volatile uint8_t *) (a))
#define R16(a) (*(volatile uint16_t *) (a))
#define R32(a) (*(volatile uint32_t *) (a))
#define SIO_DATA R8(0xBF801040)
#define SIO_STAT R16(0xBF801044)
#define SIO_MODE R16(0xBF801048)
#define SIO_CTRL R16(0xBF80104A)
#define SIO_BAUD R16(0xBF80104E)
#define I_STAT R32(0xBF801070)
#define I_MASK R32(0xBF801074)

#ifdef SLOT2
#define SIO_SELECT 0x3003
#else
#define SIO_SELECT 0x1003
#endif

/* patched by the builder (builder.cc, minload) */
struct cfg { uint32_t pc, gp, sp; uint8_t *tload; uint32_t frames, first, reboot; };
struct cfg cfg __attribute__((section(".cfg"), used)) = {0};   /* at its place above the reboot (stage2min.ld) it is only read by the handler; patched in the card image */
extern const struct cfg cfg_lma;                               /* where the loaded copy of it is: this is what main reads */
#define CFG (&cfg_lma)
extern __attribute__((noreturn)) void reboothook(const struct cfg *);

static __attribute__((noinline)) void delay(int n)
{
	__asm__ volatile(".set noreorder\n1:\taddiu %0, %0, -1\n\tbgtz %0, 1b\n\tnop\n.set reorder" : "+r"(n));
}

#ifdef DBG
/* diagnostic build (build.py --dbg): the screen is filled with a colour at each step of the run, the last colour seen is where it stopped:
 * red = started, orange = SIO0 reset, yellow = first frame read, green = every frame read (the reboot follows), blue = the breakpoint fired and the handler runs (reboot.s),
 * magenta = the card did not answer */
#define GP0 R32(0xBF801810)
#define GP1 R32(0xBF801814)
static void mark(uint32_t rgb)
{
	while (!(GP1 & 0x04000000)) {}
	GP0 = 0x02000000 | rgb;
	GP0 = 0;
	GP0 = (240u << 16) | 320;
}
#define MARK(c) mark(c)
#else
#define MARK(c) ((void) 0)
#endif

/* one byte to the card and the byte it answers with; the acknowledge (DSR interrupt flag) follows every byte but the last of a transaction */
static uint8_t xfer(uint8_t t, int ack)
{
	uint8_t r;

	I_STAT = ~0x80u;
	SIO_CTRL |= 0x10;
	SIO_DATA = t;
#ifdef DBG
	for (int n = 0; !(SIO_STAT & 2); n++) if (n > 2000000) { MARK(0xFF00FF); for (;;) {} }
	r = SIO_DATA;
	if (ack) for (int n = 0; !(I_STAT & 0x80); n++) if (n > 2000000) { MARK(0xFF00FF); for (;;) {} }
#else
	while (!(SIO_STAT & 2)) {}
	r = SIO_DATA;
	if (ack) while (!(I_STAT & 0x80)) {}
#endif
	return r;
}

static void read_frame(uint32_t frame, uint8_t *buf)
{
	SIO_CTRL = SIO_SELECT;
	delay(100);
	for (int i = 0; i < 140; i++) {
		/* 81h 52h 00h 00h, the frame number, 00h 00h 00h 00h (5Ch 5Dh and the frame number again), 128 bytes, checksum, end byte */
		uint8_t r = xfer(i == 0 ? 0x81 : i == 1 ? 0x52 : i == 4 ? frame >> 8 : i == 5 ? frame : 0, i < 139);
		if (i >= 10 && i < 138) *buf++ = r;
	}
	SIO_CTRL = 0;
}

__attribute__((noreturn, section(".text.main"))) void main(void)
{
	uint8_t *p = CFG->tload;

	__asm__ volatile("mtc0 $0, $12");                                              /* no interrupts, no exceptions */
	I_MASK = 0;
	MARK(0x0000FF);
	SIO_CTRL = 0x40; SIO_BAUD = 0x88; SIO_MODE = 13; SIO_CTRL = 0; delay(10);      /* the stage 1 may have stopped in the middle of a transaction: reset SIO0 */
	SIO_CTRL = 2; delay(10);
	SIO_CTRL = 0x2002; delay(10);
	SIO_CTRL = 0;
	MARK(0x0080FF);
	for (uint32_t f = 0; f < CFG->frames; f++, p += 128) { read_frame(CFG->first + f, p); if (!f) MARK(0x00FFFF); }
	MARK(0x00FF00);
	reboothook(&cfg_lma);
}
