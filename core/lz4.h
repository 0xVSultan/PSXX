#pragma once
#include <stddef.h>
#include <stdint.h>

/* LZ4 block format decompression with full bounds checking (for data we do not fully control).
 * Returns the number of bytes written to dst, or -1 if the stream is malformed or does not fit in dstcap. */
int lz4_decompress(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstcap);
