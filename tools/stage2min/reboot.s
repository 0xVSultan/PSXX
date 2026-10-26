# The part of FreePSXBoot's reboothook.s that is needed for slot 1 (psx-x): a breakpoint on the access to 0x80030000 (the copy of the shell, when the kernel is set up), a handler
# copied to the debug vector 0x80000040, and a reboot of the BIOS. The handler removes the breakpoint and jumps to the program (cfg.pc, gp, sp). The address of the reboot entry of
# the BIOS is cfg.reboot (0xbfc00398 up to BIOS 2.0, 0xbfc003a8 from 2.1: the builder knows).
.section .text.reboot
.global reboothook
.set noreorder
.set noat

.macro cop0_nop
.ifdef NOPS
	nop
.endif
.endm

reboothook:
.ifndef CONSTREBOOT
	# the entry of the BIOS reboot, loaded early: a load is not seen by the next instruction (load delay slot of the R3000)
	la $t6, cfg_lma
	lw $t6, 24($t6)
.endif
.ifndef INPLACE
	# the handler and cfg go to their place above the part of the memory that the reboot overwrites (stage2min.ld)
	la $t0, __handler_lma
	la $t1, __handler_start
	la $t2, __handler_end
1:	lw $t3, 0($t0)
	addiu $t0, $t0, 4
	addiu $t1, $t1, 4
	bne $t1, $t2, 1b
	sw $t3, -4($t1)
.endif
.ifdef ORIGP
	# as the original: pc, gp and sp are saved at 0x8000dff0, which the kernel never writes
	la $a0, cfg
	li $t0, 0x8000dff0
	lw $t1, 0($a0)
	lw $t2, 4($a0)
	lw $t3, 8($a0)
	sw $t1, 0($t0)
	sw $t2, 4($t0)
	sw $t3, 8($t0)
.endif
	li $a0, 0x80030000
	mtc0 $a0, $5				# BPC: breakpoint on data access
	cop0_nop
	li $t0, 0xFFFFFFFF
	mtc0 $t0, $9				# BDAM
	cop0_nop
	mtc0 $a0, $3				# BPC: breakpoint on execution
	cop0_nop
	mtc0 $t0, $11				# BPCM
	cop0_nop
	li $t1, 0xEB800000
	mtc0 $t1, $7				# DCIC
	la $t0, copHook
	li $t5, 0x80000040
	lw $t1, 0x0($t0)
	lw $t2, 0x4($t0)
	lw $t3, 0x8($t0)
	lw $t4, 0xC($t0)
	sw $t1, 0x0($t5)
	sw $t2, 0x4($t5)
	sw $t3, 0x8($t5)
	sw $t4, 0xC($t5)
.ifdef CONSTREBOOT
	la $t6, 0xbfc003a8
.endif
	jalr $t6
	nop

copHook:
	la $k0, cophandler
	jr $k0
	nop

.ifndef LOWH
.section .handler_text
.endif
cophandler:
	mtc0 $0, $5
	mtc0 $0, $9
	mtc0 $0, $3
	mtc0 $0, $11
	mtc0 $0, $7
.ifdef DBG
	# diagnostic build: blue screen = the breakpoint fired and the handler runs
	lui $t0, 0xbf80
	li $t1, 0x02FF0000
	sw $t1, 0x1810($t0)
	sw $0, 0x1810($t0)
	li $t1, (240 << 16) | 320
	sw $t1, 0x1810($t0)
.endif
.ifdef UNIROM
	# as the original handler: the tags that FreePSXBoot leaves for Unirom (0xbe48, 0xbe4c)
	li $t0, 0xbe48
	lui $t1, 0xf12e
	ori $t1, $t1, 0xe175
	sw $t1, 0($t0)
	lui $t1, 0xec5b
	ori $t1, $t1, 0x71
	sw $t1, 4($t0)
.endif
.ifdef PAD8
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
.endif
.ifdef ORIGP
	li $t0, 0x8000dff0
.else
	la $t0, cfg
.endif
	lw $t1, 0($t0)
	lw $gp, 4($t0)
	lw $sp, 8($t0)
	jr $t1
	rfe
