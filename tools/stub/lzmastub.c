/* Self-extracting stub for packed PS-X EXEs (tools/packexe.py).
 *
 * The packed EXE is loaded high in RAM as [compressed LZMA stream][this stub]. The packer links this file right
 * after the stream and defines the symbols below with --defsym:
 *   STUB_SRC    first byte of the compressed stream
 *   STUB_DST    where the original image has to be unpacked (its original load address)
 *   STUB_SIZE   size of the original image in bytes
 *   STUB_ENTRY  the original entry point
 *   STUB_PROBS  scratch memory for the decoder (LZMA_PROBS 16 bit entries), unused RAM
 * Decompression runs out of place: the stream and the scratch memory lie above the destination range, which the packer
 * has checked. Neither is needed after the jump.
 *
 * No libc, no interrupts needed.
 */
#include <stdint.h>

/* With -DSTUB_PROFILE the stub measures how long the unpacking takes (root counter 2, system clock / 8, read once per decoded symbol: well
 * within its 15 ms wrap) and leaves the result at 0x801FC000 for the program: magic "STUB", the unpacking time in units of 8 CPU cycles, the
 * size of the unpacked image, the size of the packed stream. */
#ifdef STUB_PROFILE
#define STUB_RESULT ((volatile uint32_t *) 0x801FC000u)
static uint16_t t_last;
static uint32_t t_total;
static inline void stub_tick(void)
{
    uint16_t c = *(volatile uint16_t *) 0x1F801120u;
    t_total += (uint16_t) (c - t_last);
    t_last = c;
}
#define LZMA_TICK() stub_tick()
#endif
#ifndef STUB_EXT_DEC
#include "lzma_unpack.h"
#endif

extern const uint8_t STUB_SRC[];
extern uint8_t STUB_DST[];
extern const char STUB_SIZE[];
extern uint16_t STUB_PROBS[];
extern void STUB_ENTRY(void);

#ifdef STUB_EXT_DEC
/* the decoder image, carried in the stub (tools/packexe.py: the file STUB_DEC_BIN) */
__asm__(".section .text.stubdec,\"ax\"\n"
        ".balign 4\n"
        ".globl stub_dec\n"
        "stub_dec:\n"
        ".incbin \"" STUB_DEC_BIN "\"\n"
        ".balign 4\n"
        ".globl stub_dec_end\n"
        "stub_dec_end:\n"
        ".previous\n");
extern const uint8_t stub_dec[], stub_dec_end[];
#endif

/* the code just written must not be fetched from the instruction cache: BIOS FlushCache() = A0 function 0x44 */
static inline void flush_cache(void)
{
    register unsigned fn __asm__("$9") = 0x44;
    __asm__ volatile(
        "jal 0xa0\n\t"
        "nop\n\t"
        : "+r"(fn)
        :
        : "memory", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "$31");
}

__attribute__((noreturn, section(".text.stubmain"), used))
void stub_main(void)
{
#ifdef STUB_PROFILE
    *(volatile uint16_t *) 0x1F801124u = 0x0200;            /* free running, system clock / 8 */
    *(volatile uint16_t *) 0x1F801120u = 0;
    t_last = 0;
    t_total = 0;
#endif
#ifdef STUB_EXT_DEC
    /* the decoder of the program (lzdec.c, linked at STUB_DEC_AT) goes into its pocket and does the work; the main card calls it afterwards (core/pkg/ovl.c, PSXX_EXT_DEC) */
    {
        const uint32_t *s = (const uint32_t *) stub_dec;
        volatile uint32_t *d = (volatile uint32_t *) STUB_DEC_AT;

        for (; s < (const uint32_t *) stub_dec_end; s++) *d++ = *s;
        *(volatile uint32_t *) STUB_DEC_TAG = STUB_DEC_MAGIC;
        flush_cache();
        ((int (*)(const uint8_t *, uint8_t *, uint32_t, uint16_t *, unsigned, const uint8_t *, uint32_t)) STUB_DEC_AT)(STUB_SRC, STUB_DST, (uint32_t) (uintptr_t) STUB_SIZE, STUB_PROBS, STUB_PROPS, 0, 0);
    }
#else
    lzma_unpack(STUB_SRC, STUB_DST, (uint32_t) (uintptr_t) STUB_SIZE, STUB_PROBS);
#endif
#ifdef STUB_PROFILE
    stub_tick();
    STUB_RESULT[1] = t_total;
    STUB_RESULT[2] = (uint32_t) (uintptr_t) STUB_SIZE;
    STUB_RESULT[3] = (uint32_t) (uintptr_t) stub_main - (uint32_t) (uintptr_t) STUB_SRC;
    STUB_RESULT[0] = 0x42555453u;                           /* "STUB" */
#endif
    flush_cache();
    STUB_ENTRY();
    for (;;) {}
}
