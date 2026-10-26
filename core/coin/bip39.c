#include "coin/bip39.h"
#include "coin/words.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "util.h"
#include <string.h>

/* The list is decoded once (words.c): a word is text[off[i]], and the list is sorted. */

int bip39_word(unsigned idx, char out[BIP39_MAX_WORD + 1])
{
    const words_list *l = words_get(WORDS_BIP39);
    size_t n;
    if (!l || idx >= (unsigned) l->n) return -1;
    n = (size_t) (l->off[idx + 1] - l->off[idx]) - 1;                      /* without the 0 */
    memcpy(out, l->text + l->off[idx], n);
    out[n] = 0;
    return (int) n;
}

int bip39_find(const char *s, size_t len)
{
    const words_list *l = words_get(WORDS_BIP39);
    if (!l || len == 0 || len > BIP39_MAX_WORD) return -1;
    for (int i = 0; i < l->n; i++) {
        const char *w = l->text + l->off[i];
        size_t wl = (size_t) (l->off[i + 1] - l->off[i]) - 1;
        /* no strncmp: the one in the PSn00bSDK libc treats the end of the shorter string as a match ("tennis" found "ten") */
        if (len >= 4 ? (wl >= len && !memcmp(w, s, len)) : (wl == len && !memcmp(w, s, len))) return i;
    }
    return -1;
}

int bip39_complete(const char *pre, size_t len, int from, char out[][BIP39_MAX_WORD + 1], int max)
{
    const words_list *l = words_get(WORDS_BIP39);
    int total = 0;
    if (!l || len == 0 || len > BIP39_MAX_WORD) return 0;
    for (int i = 0; i < l->n; i++) {
        const char *w = l->text + l->off[i];
        size_t wl = (size_t) (l->off[i + 1] - l->off[i]) - 1;
        if (wl < len || memcmp(w, pre, len)) continue;
        if (total >= from && total - from < max) memcpy(out[total - from], w, wl + 1);
        total++;
    }
    return total;
}

/* Bit helpers: bit i of the message, MSB first. */
static unsigned get_bit(const uint8_t *b, unsigned i) { return (b[i >> 3] >> (7 - (i & 7))) & 1; }

int bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t len, char *out, size_t cap)
{
    uint8_t bits[33], h[32];
    if (len < 16 || len > 32 || (len & 3)) return -1;
    memcpy(bits, entropy, len);
    sha256(entropy, len, h);
    bits[len] = h[0];                                  /* checksum is the first len/4 bits of the hash */
    unsigned nwords = (unsigned)(len * 8 + len / 4) / 11, o = 0;
    for (unsigned w = 0; w < nwords; w++) {
        unsigned idx = 0;
        for (unsigned b = 0; b < 11; b++) idx = (idx << 1) | get_bit(bits, w * 11 + b);
        char word[BIP39_MAX_WORD + 1];
        int n = bip39_word(idx, word);
        if (o + (unsigned)n + 1 + (w + 1 < nwords ? 1 : 0) > cap) { secure_zero(bits, sizeof bits); return -1; }
        memcpy(out + o, word, (size_t)n);
        o += (unsigned)n;
        if (w + 1 < nwords) out[o++] = ' ';
    }
    out[o] = 0;
    secure_zero(bits, sizeof bits);
    return (int)o;
}

int bip39_mnemonic_to_entropy(const char *m, uint8_t entropy[32])
{
    uint8_t bits[33] = {0}, h[32];
    unsigned nbits = 0, nwords = 0;
    while (*m) {
        while (*m == ' ') m++;
        if (!*m) break;
        const char *e = m;
        while (*e && *e != ' ') e++;
        int idx = bip39_find(m, (size_t)(e - m));
        /* the words must be given in full, not as 4 letter prefixes */
        char full[BIP39_MAX_WORD + 1];
        if (idx < 0 || nwords >= 24 || bip39_word((unsigned)idx, full) != (int)(e - m) || memcmp(full, m, (size_t)(e - m))) {
            secure_zero(bits, sizeof bits);
            return -1;
        }
        for (int b = 10; b >= 0; b--, nbits++)
            if ((idx >> b) & 1) bits[nbits >> 3] |= (uint8_t)(0x80 >> (nbits & 7));
        nwords++;
        m = e;
    }
    if (nwords < 12 || nwords > 24 || nwords % 3) { secure_zero(bits, sizeof bits); return -1; }
    unsigned entlen = nwords * 4 / 3;                  /* ENT = 32/3 bits per word */
    unsigned cs = nwords / 3;                          /* checksum bits */
    sha256(bits, entlen, h);
    int ok = ((h[0] ^ bits[entlen]) >> (8 - cs)) == 0;
    if (ok) memcpy(entropy, bits, entlen);
    secure_zero(bits, sizeof bits);
    return ok ? (int)entlen : -1;
}

void bip39_seed(const char *mnemonic, const char *passphrase, uint8_t seed[64])
{
    uint8_t salt[8 + 128];
    size_t pl = strlen(passphrase);
    if (pl > 128) pl = 128;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, passphrase, pl);
    pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic), salt, 8 + pl, 2048, seed, 64);
    secure_zero(salt, sizeof salt);
}
