#include "coin/xmr_seed.h"
#include "coin/words.h"
#include "coin/xmr_words.h"
#include "hash/crc32.h"
#include "util.h"
#include <string.h>

#define N XMR_NWORDS
#define PREFIX 3

/* The list is decoded once (words.c). */

int xmr_word(unsigned idx, char out[13])
{
    const words_list *l = words_get(WORDS_XMR);
    size_t n;
    if (!l || idx >= N) return -1;
    n = (size_t) (l->off[idx + 1] - l->off[idx]) - 1;
    memcpy(out, l->text + l->off[idx], n);
    out[n] = 0;
    return (int) n;
}

/* index of the word whose first `len` (>= PREFIX) letters are s (a full word matches too), or -1 */
static int find(const char *s, size_t len)
{
    const words_list *l = words_get(WORDS_XMR);
    if (!l || len < PREFIX || len > 12) return -1;
    for (int i = 0; i < N; i++) {
        const char *w = l->text + l->off[i];
        size_t wl = (size_t) (l->off[i + 1] - l->off[i]) - 1;
        if (!memcmp(w, s, PREFIX) && (wl == len ? !memcmp(w, s, len) : (wl > len && !memcmp(w, s, len)))) return i;
    }
    return -1;
}

int xmr_word_find(const char *s, size_t len) { return find(s, len); }

/* checksum word index: CRC-32 over the first 3 letters of each of the 24 words, modulo 24 */
static unsigned checksum_index(const uint16_t idx[24])
{
    uint8_t buf[24 * PREFIX];
    char w[13];
    for (int i = 0; i < 24; i++) {
        xmr_word(idx[i], w);
        memcpy(buf + i * PREFIX, w, PREFIX);
    }
    return crc32(buf, sizeof buf) % 24;
}

int xmr_complete(const char *pre, size_t len, int from, char out[][13], int max)
{
    const words_list *l = words_get(WORDS_XMR);
    int total = 0;
    if (!l || len == 0 || len > 12) return 0;
    for (int i = 0; i < N; i++) {
        const char *w = l->text + l->off[i];
        size_t wl = (size_t) (l->off[i + 1] - l->off[i]) - 1;
        if (wl < len || memcmp(w, pre, len)) continue;
        if (total >= from && total - from < max) memcpy(out[total - from], w, wl + 1);
        total++;
    }
    return total;
}

int xmr_seed_encode(const uint8_t key[32], char *out, size_t cap)
{
    uint16_t idx[XMR_SEED_WORDS];
    size_t o = 0;

    for (int i = 0; i < 8; i++) {
        uint32_t val = (uint32_t)key[4*i] | (uint32_t)key[4*i+1] << 8 | (uint32_t)key[4*i+2] << 16 | (uint32_t)key[4*i+3] << 24;
        uint32_t w1 = val % N;
        uint32_t w2 = ((val / N) + w1) % N;
        uint32_t w3 = (((val / N) / N) + w2) % N;
        idx[3*i] = (uint16_t)w1; idx[3*i+1] = (uint16_t)w2; idx[3*i+2] = (uint16_t)w3;
    }
    idx[24] = idx[checksum_index(idx)];

    for (int i = 0; i < XMR_SEED_WORDS; i++) {
        char w[13];
        int l = xmr_word(idx[i], w);
        if (o + (size_t)l + 1 + (i + 1 < XMR_SEED_WORDS ? 1 : 0) > cap) return -1;
        memcpy(out + o, w, (size_t)l);
        o += (size_t)l;
        if (i + 1 < XMR_SEED_WORDS) out[o++] = ' ';
    }
    out[o] = 0;
    secure_zero(idx, sizeof idx);
    return (int)o;
}

int xmr_seed_decode(const char *m, uint8_t key[32])
{
    uint16_t idx[XMR_SEED_WORDS];
    int n = 0;

    while (*m) {
        while (*m == ' ') m++;
        if (!*m) break;
        const char *e = m;
        while (*e && *e != ' ') e++;
        int i = find(m, (size_t)(e - m));
        if (i < 0 || n >= XMR_SEED_WORDS) return -1;
        idx[n++] = (uint16_t)i;
        m = e;
    }
    if (n != XMR_SEED_WORDS) return -1;
    if (idx[24] != idx[checksum_index(idx)]) return -1;

    for (int i = 0; i < 8; i++) {
        uint64_t w1 = idx[3*i], w2 = idx[3*i+1], w3 = idx[3*i+2];
        uint64_t val = w1 + (uint64_t)N * ((N - w1 + w2) % N) + (uint64_t)N * N * ((N - w2 + w3) % N);
        if (val > 0xFFFFFFFFull) { secure_zero(idx, sizeof idx); return -1; }
        key[4*i] = (uint8_t)val; key[4*i+1] = (uint8_t)(val >> 8); key[4*i+2] = (uint8_t)(val >> 16); key[4*i+3] = (uint8_t)(val >> 24);
    }
    secure_zero(idx, sizeof idx);
    return 0;
}
