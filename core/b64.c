#include "b64.h"

static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t o = 0;

    if (cap < 4 * ((n + 2) / 3) + 1) return -1;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = A[v >> 18];
        out[o++] = A[(v >> 12) & 63];
        out[o++] = i + 1 < n ? A[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? A[v & 63] : '=';
    }
    out[o] = 0;
    return (int)o;
}

int b64_decode(const char *in, uint8_t *out, size_t cap)
{
    uint32_t acc = 0;
    int bits = 0, pad = 0;
    size_t o = 0;

    for (; *in; in++) {
        int v;
        char c = *in;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') { pad++; continue; }
        if (pad) return -1;                                  /* data after the padding */
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }
    if (pad > 2 || (bits == 6) || (acc != 0)) return -1;     /* leftover bits must be zero, 1 char tail is invalid */
    return (int)o;
}
