#include "coin/base58.h"
#include "hash/sha256.h"
#include <string.h>

static const char ALPHA[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int base58_encode(const uint8_t *in, size_t len, char *out, size_t outcap)
{
    uint8_t buf[128];
    size_t zeros = 0, n, i, j;
    if (len > sizeof buf) return -1;
    while (zeros < len && in[zeros] == 0) zeros++;
    memcpy(buf, in, len);
    /* repeated division of the big-endian number by 58 */
    char tmp[200];
    size_t t = 0, start = zeros;
    while (start < len) {
        uint32_t rem = 0;
        for (i = start; i < len; i++) {
            uint32_t v = (rem << 8) | buf[i];
            buf[i] = (uint8_t)(v / 58);
            rem = v % 58;
        }
        if (t >= sizeof tmp) return -1;
        tmp[t++] = ALPHA[rem];
        while (start < len && buf[start] == 0) start++;
    }
    n = zeros + t;
    if (n + 1 > outcap) return -1;
    for (i = 0; i < zeros; i++) out[i] = '1';
    for (j = 0; j < t; j++) out[zeros + j] = tmp[t - 1 - j];
    out[n] = 0;
    return (int)n;
}

int base58check_encode(const uint8_t *payload, size_t len, char *out, size_t outcap)
{
    uint8_t buf[100], h1[32], h2[32];
    if (len > 96) return -1;
    memcpy(buf, payload, len);
    sha256(payload, len, h1);
    sha256(h1, 32, h2);
    memcpy(buf + len, h2, 4);
    return base58_encode(buf, len + 4, out, outcap);
}

static const uint8_t XMR_BLOCK_CHARS[9] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

int base58_monero_encode(const uint8_t *in, size_t len, char *out, size_t outcap)
{
    size_t o = 0;
    for (size_t pos = 0; pos < len; pos += 8) {
        size_t bl = (len - pos < 8) ? len - pos : 8;
        size_t nch = XMR_BLOCK_CHARS[bl];
        uint64_t num = 0;
        if (o + nch + 1 > outcap) return -1;
        for (size_t i = 0; i < bl; i++) num = (num << 8) | in[pos + i];
        for (size_t i = nch; i-- > 0; ) {
            out[o + i] = ALPHA[num % 58];
            num /= 58;
        }
        o += nch;
    }
    out[o] = 0;
    return (int)o;
}
