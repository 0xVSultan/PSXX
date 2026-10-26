#include "sign/nip19.h"
#include <string.h>
#include "coin/bech32.h"

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod_step(uint32_t chk, uint32_t v)
{
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    return chk;
}

#define N19_MAX 400                                   /* characters of a string; an nprofile with a few relays is about 250 */

static int hrp_type(const char *h, size_t n)
{
    static const struct { const char *name; int type; } T[] = {
        {"npub", N19_NPUB}, {"nsec", N19_NSEC}, {"note", N19_NOTE}, {"nprofile", N19_NPROFILE}, {"nevent", N19_NEVENT}, {"naddr", N19_NADDR}, {"nrelay", N19_NRELAY}};
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        size_t k = 0;
        if (strlen(T[i].name) != n) continue;
        while (k < n && T[i].name[k] == (h[k] | 32)) k++;                     /* the prefix in either case */
        if (k == n) return T[i].type;
    }
    return 0;
}

int nip19_decode(nip19 *r, const char *s)
{
    uint8_t d5[N19_MAX], raw[N19_MAX * 5 / 8 + 2];
    size_t n = strlen(s), sep = 0, nd, o = 0;
    int lower = 0, upper = 0, type;
    uint32_t chk = 1;
    uint32_t acc = 0;
    int bits = 0, special = 0;

    memset(r, 0, sizeof *r);
    if (n < 8 || n > N19_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'a' && c <= 'z') lower = 1;
        else if (c >= 'A' && c <= 'Z') upper = 1;
        if (c == '1') sep = i;
    }
    if ((lower && upper) || sep < 1 || n - sep < 7) return -1;
    type = hrp_type(s, sep);
    if (!type) return -1;
    for (size_t i = 0; i < sep; i++) chk = polymod_step(chk, (uint32_t) (s[i] | 32) >> 5);
    chk = polymod_step(chk, 0);
    for (size_t i = 0; i < sep; i++) chk = polymod_step(chk, (uint32_t) (s[i] | 32) & 31);
    nd = n - sep - 1;
    for (size_t i = 0; i < nd; i++) {
        const char *p = memchr(CHARSET, s[sep + 1 + i] | 32, 32);
        if (!p) return -1;
        d5[i] = (uint8_t) (p - CHARSET);
        chk = polymod_step(chk, d5[i]);
    }
    if (chk != 1) return -1;
    nd -= 6;                                                          /* the checksum */
    for (size_t i = 0; i < nd; i++) {                                 /* 5 bits to 8, no padding bits left */
        acc = (acc << 5) | d5[i];
        bits += 5;
        if (bits >= 8) { bits -= 8; raw[o++] = (uint8_t) (acc >> bits); acc &= (1u << bits) - 1; }
    }
    if (bits >= 5 || acc) return -1;
    r->type = type;
    if (type == N19_NPUB || type == N19_NSEC || type == N19_NOTE) {
        if (o != 32) return -1;
        memcpy(r->id, raw, 32);
        return type;
    }
    for (size_t i = 0; i < o;) {                                      /* the type-length-value list */
        unsigned t, l;
        if (i + 2 > o) return -1;
        t = raw[i]; l = raw[i + 1]; i += 2;
        if (i + l > o) return -1;
        if (t == 0) {
            if (type == N19_NADDR) { if (l >= sizeof r->d) return -1; memcpy(r->d, raw + i, l); r->d[l] = 0; }
            else { if (l != 32) return -1; memcpy(r->id, raw + i, 32); }
            special = 1;
        } else if (t == 1) {
            if (!r->relay[0] && l < sizeof r->relay) { memcpy(r->relay, raw + i, l); r->relay[l] = 0; }
            r->nrelays++;
        } else if (t == 2) {
            if (l != 32) return -1;
            memcpy(r->author, raw + i, 32);
            r->have_author = 1;
        } else if (t == 3) {
            if (l != 4) return -1;
            r->kind = (uint32_t) raw[i] << 24 | (uint32_t) raw[i + 1] << 16 | (uint32_t) raw[i + 2] << 8 | raw[i + 3];
            r->have_kind = 1;
        }
        i += l;
    }
    if (!special) return -1;                                          /* the entry 0 (the key, id or identifier) is required */
    return type;
}

int nip19_encode32(char *out, size_t cap, const char *hrp, const uint8_t v[32])
{
    uint8_t d5[56];
    int n = bech32_convert_bits(d5, sizeof d5, v, 32, 8, 5, 1);
    return n < 0 ? -1 : bech32_encode(out, cap, hrp, d5, (size_t) n, 0);
}
