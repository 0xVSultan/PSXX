#include "pwtools.h"
#include <string.h>
#include "blob.h"
#include "coin/bip39.h"
#include "hash/sha256.h"

void pw_seed_make(uint8_t seed[32], const uint8_t salt[32], const uint8_t *secret, size_t slen, int what, int type)
{
    uint8_t info[11 + 2] = {'p', 's', 'x', '-', 'p', 'w', '-', 's', 'e', 'e', 'd', 0, 0};

    info[11] = (uint8_t) what;
    info[12] = (uint8_t) type;
    hkdf_sha256(salt, 32, secret, slen, info, sizeof info, seed, 32);
}

/* log2(n) * 16 for n >= 1 (the mantissa interpolated linearly: at most 0.09 bit too low) */
static int log2x16(unsigned n)
{
    int e = 0;
    unsigned m = n;

    while (m > 1) { m >>= 1; e++; }
    return e * 16 + (int) ((n << 4) >> e) - 16;
}

static int all_bip39_words(const char *pw, int *distinct)
{
    int idxs[PW_MAX], n = 0, count = 0;
    const char *p = pw;

    while (*p) {
        char tok[BIP39_MAX_WORD + 2], w[BIP39_MAX_WORD + 1];
        int l = 0, idx, dup = 0;

        while (*p && !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) p++;     /* separators: anything that is not a letter */
        if (!*p) break;
        while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) {
            if (l < BIP39_MAX_WORD + 1) tok[l] = (*p >= 'A' && *p <= 'Z') ? (char) (*p + 32) : *p;
            l++;
            p++;
        }
        if (l > BIP39_MAX_WORD) return 0;
        tok[l] = 0;
        idx = bip39_find(tok, (size_t) l);
        if (idx < 0 || bip39_word((unsigned) idx, w) <= 0 || strcmp(w, tok) != 0) return 0;
        for (int i = 0; i < n; i++) if (idxs[i] == idx) dup = 1;
        if (!dup && n < PW_MAX) idxs[n++] = idx;
        count++;
    }
    *distinct = n;
    return count >= 3;
}

int pw_entropy_bits(const char *pw)
{
    unsigned pool = 0, units = 0;
    int distinct, lower = 0, upper = 0, digit = 0, sym = 0, other = 0, prev = -1;
    uint8_t seen[32];

    if (!*pw) return 0;
    if (all_bip39_words(pw, &distinct)) return 11 * distinct;
    memset(seen, 0, sizeof seen);
    for (const uint8_t *p = (const uint8_t *) pw; *p; p++) {
        int c = *p, fresh;

        if ((c & 0xC0) == 0x80) continue;                           /* the rest of a multi byte character */
        if (c >= 'a' && c <= 'z') lower = 1;
        else if (c >= 'A' && c <= 'Z') upper = 1;
        else if (c >= '0' && c <= '9') digit = 1;
        else if (c < 0x80) sym = 1;
        else other = 1;
        fresh = !(seen[(c & 0x7F) >> 3 | (c >> 7) << 4] & (1 << (c & 7)));     /* the first byte tells the characters apart well enough */
        seen[(c & 0x7F) >> 3 | (c >> 7) << 4] |= (uint8_t) (1 << (c & 7));
        if (prev >= 0 && (c == prev || c == prev + 1 || c == prev - 1)) units += 1;   /* the same character again or a step of a sequence: cheap */
        else units += fresh ? 4 : 3;                                                  /* a character seen before, not next to itself: a little less (random passwords have some) */
        prev = c;
    }
    pool = (lower ? 26u : 0) + (upper ? 26u : 0) + (digit ? 10u : 0) + (sym ? 33u : 0) + (other ? 64u : 0);
    return (int) ((unsigned) log2x16(pool) * units / 64);          /* units are quarter characters, log2 is in sixteenths */
}

/* ---- random passwords: a stream of bytes from SHA-256(domain, seed, counter, block) ---- */

typedef struct { const uint8_t *seed; uint32_t counter, block; uint8_t buf[32]; int pos; } rng;

static uint8_t rng_byte(rng *r)
{
    if (r->pos >= 32) {
        sha256_ctx c;
        uint8_t be[8];

        for (int i = 0; i < 4; i++) { be[i] = (uint8_t) (r->counter >> (24 - 8 * i)); be[4 + i] = (uint8_t) (r->block >> (24 - 8 * i)); }
        sha256_init(&c);
        sha256_update(&c, (const uint8_t *) "psx-pwgen", 9);
        sha256_update(&c, r->seed, 32);
        sha256_update(&c, be, 8);
        sha256_final(&c, r->buf);
        memset(&c, 0, sizeof c);
        r->block++;
        r->pos = 0;
    }
    return r->buf[r->pos++];
}

int pw_generate(int kind, const uint8_t seed[32], uint32_t counter, char *out, size_t cap)
{
    static const char ALPHA[] = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";     /* 25 + 24 + 8 = 57 */
    rng r;

    r.seed = seed; r.counter = counter; r.block = 0; r.pos = 32;
    if (kind == PW_WORDS) {
        size_t o = 0;

        for (int i = 0; i < PW_WORDS_COUNT; i++) {
            char w[BIP39_MAX_WORD + 1];
            unsigned idx = ((unsigned) rng_byte(&r) << 8 | rng_byte(&r)) & 0x7FF;       /* 2048 words: 11 bits, no bias */
            int l = bip39_word(idx, w);

            if (l <= 0 || o + (size_t) l + 2 > cap) return -1;
            memcpy(out + o, w, (size_t) l);
            o += (size_t) l;
            out[o++] = i + 1 < PW_WORDS_COUNT ? ' ' : 0;
        }
        memset(&r, 0, sizeof r);
        return 11 * PW_WORDS_COUNT;
    }
    if (cap < PW_CHARS_LEN + 1) return -1;
    for (;;) {
        int lo = 0, up = 0, di = 0;

        for (int i = 0; i < PW_CHARS_LEN; i++) {
            uint8_t b;
            char c;

            do b = rng_byte(&r); while (b >= 228);                                   /* 57 * 4: every character is equally likely */
            c = ALPHA[b % 57];
            out[i] = c;
            if (c >= 'a' && c <= 'z') lo = 1; else if (c >= 'A' && c <= 'Z') up = 1; else di = 1;
        }
        if (lo && up && di) break;                                                  /* like the browsers: all three kinds, else draw again */
    }
    out[PW_CHARS_LEN] = 0;
    memset(&r, 0, sizeof r);
    return 87;                                                                      /* 15 * log2(57) = 87.5, a little less by the rule above */
}
