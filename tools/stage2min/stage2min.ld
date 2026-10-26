OUTPUT_ARCH(mips)
ENTRY(_start)
SECTIONS
{
	. = 0x8000d000;
	.text : { *(.text.start) *(.text.main) *(.text .text.*) }
	.rodata : { *(.rodata .rodata.*) }
	. = ALIGN(4);
	__handler_lma = .;
	/* The part that must live through the reboot of the BIOS - the handler of the breakpoint and the data it jumps with - runs at 0x8000d610, where the original stage2 keeps
	 * its own handler: the reboot overwrites the lower part of this area (the handler stayed at 0x8000d254 in the first version, and the CPU ran into the data after it).
	 * The binary holds it right after the rodata (the load address); reboothook copies it up. `cfg` is its last 28 bytes: the builder patches the last 28 bytes of the binary. */
	.handler 0x8000d610 : AT(__handler_lma) { __handler_start = .; *(.handler_text) *(.cfg) __handler_end = .; }
	cfg_lma = __handler_lma + (cfg - __handler_start);
	/DISCARD/ : { *(.comment) *(.gnu.attributes) *(.reginfo) *(.MIPS.abiflags) *(.pdr) *(.mdebug*) }
}
