#include "hash/crc32.h"
/* Bitwise (no table): smaller than a 1 KB table and only used on small buffers. */
uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t c = 0xFFFFFFFFu;
    while (len--) {
        c ^= *data++;
        for (int i = 0; i < 8; i++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}
