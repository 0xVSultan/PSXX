/* The LZMA decoder with the properties byte and the preset dictionary (lzma_unpack.h with LZMA_DICT), as one piece of position dependent code with its entry at the first byte: it is linked
 * at MM_DEC_LO (hal/psx/memmap.h) by tools/packexe.py and carried by the unpacking stub, which copies it there. No data, no calls out: the image is only the .text. */
#define LZMA_DICT
#include "lzma_unpack.h"

__attribute__((section(".text.startup")))
int lz_decode(const uint8_t *src, uint8_t *dst, uint32_t dst_size, uint16_t *probs, unsigned props, const uint8_t *dict, uint32_t dict_len)
{
    return lzma_unpack(src, dst, dst_size, probs, props, dict, dict_len);
}
