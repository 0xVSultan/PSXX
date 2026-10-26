/* diagnostic layouts (build.py --layout orig|inplace): the reboot code at the address of the original (0x8000d568), no copying */
OUTPUT_ARCH(mips)
ENTRY(_start)
SECTIONS
{
	. = 0x8000d000;
	.text : { *(.text.start) *(.text.main) *(.text .text.*) }
	.rodata : { *(.rodata .rodata.*) }
	. = 0x8000d568;
	.reboot : { KEEP(*reboot*.o(.text .text.reboot .handler_text)) KEEP(*reboothook*.o(.text)) . = ALIGN(4); *(.cfg) }
	cfg_lma = cfg;
	/DISCARD/ : { *(.comment) *(.gnu.attributes) *(.reginfo) *(.MIPS.abiflags) *(.pdr) *(.mdebug*) }
}
