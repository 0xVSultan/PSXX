.section .text.start
.global _start
.set noreorder
_start:
	lui $sp, 0x8000
	ori $sp, $sp, 0xdef0
	j main
	nop
