/* Self-extracting stub for packed PS-X EXEs (tools/packexe.py).
 *
 * The packed EXE is loaded as [compressed LZ4 block][this stub]. The packer links this file at the address right
 * after the block and defines the symbols below with --defsym:
 *   STUB_SRC    first byte of the compressed block
 *   STUB_END    one past its last byte
 *   STUB_DST    where the original image has to be unpacked (its original load address)
 *   STUB_ENTRY  the original entry point
 * The block sits at the very end of the destination range, so decompression runs in place; the packer has checked
 * the margin. The stub itself lies behind the destination range (in what becomes the program's BSS) and is not
 * needed after the jump.
 *
 * No libc, no stack use beyond the compiler's frame, no interrupts needed.
 */
#include <stdint.h>
#include "lz4_unpack.h"

extern const uint8_t STUB_SRC[], STUB_END[];
extern uint8_t STUB_DST[];
extern void STUB_ENTRY(void);

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
    lz4_unpack_unchecked(STUB_SRC, STUB_END, STUB_DST);
    flush_cache();
    STUB_ENTRY();
    for (;;) {}
}
