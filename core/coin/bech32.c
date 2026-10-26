#include "coin/bech32.h"
#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod_step(uint32_t chk, uint8_t v)
{
    static const uint32_t G[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= G[i];
    return chk;
}

int bech32_encode(char *out, size_t outcap, const char *hrp, const uint8_t *data5, size_t n5, int m)
{
    size_t hl = strlen(hrp), o = 0;
    uint32_t chk = 1;
    if (hl + 1 + n5 + 6 + 1 > outcap) return -1;
    for (size_t i = 0; i < hl; i++) chk = polymod_step(chk, (uint8_t)(hrp[i] >> 5));
    chk = polymod_step(chk, 0);
    for (size_t i = 0; i < hl; i++) chk = polymod_step(chk, (uint8_t)(hrp[i] & 31));
    for (size_t i = 0; i < n5; i++) chk = polymod_step(chk, data5[i]);
    for (int i = 0; i < 6; i++) chk = polymod_step(chk, 0);
    chk ^= m ? 0x2bc830a3u : 1u;
    memcpy(out, hrp, hl); o = hl;
    out[o++] = '1';
    for (size_t i = 0; i < n5; i++) out[o++] = CHARSET[data5[i]];
    for (int i = 0; i < 6; i++) out[o++] = CHARSET[(chk >> (5 * (5 - i))) & 31];
    out[o] = 0;
    return (int)o;
}

int bech32_convert_bits(uint8_t *out, size_t outcap, const uint8_t *in, size_t inlen, int frombits, int tobits, int pad)
{
    uint32_t acc = 0, maxv = (1u << tobits) - 1;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (o >= outcap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
        acc &= (1u << bits) - 1;      /* keep only the pending bits */
    }
    if (pad) {
        if (bits) {
            if (o >= outcap) return -1;
            out[o++] = (uint8_t)((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return -1;
    }
    return (int)o;
}

int segwit_addr_encode(char *out, size_t outcap, const char *hrp, int witver, const uint8_t *prog, size_t proglen)
{
    uint8_t d[1 + 65];
    int n;
    if (witver < 0 || witver > 16 || proglen < 2 || proglen > 40) return -1;
    d[0] = (uint8_t)witver;
    n = bech32_convert_bits(d + 1, sizeof d - 1, prog, proglen, 8, 5, 1);
    if (n < 0) return -1;
    return bech32_encode(out, outcap, hrp, d, (size_t)n + 1, witver == 0 ? 0 : 1);
}
