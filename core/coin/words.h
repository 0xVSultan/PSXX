#pragma once
#include <stddef.h>
#include <stdint.h>

/* The English word lists of BIP39 and Monero, decoded from their arithmetic coded blobs (bip39_words.h, xmr_words.h; tools/gen_words_ac.py, decoder core/wordlist/wl.c) into RAM
 * once: the words as UTF-8 text, each followed by a 0 byte, and the offset of every word. A word's position is its index. The decoding needs a work area of about 50 KB for a moment
 * and keeps about 40 KB. On the console the default work area is the overlay region (0x801B4000..), which is free until an overlay is loaded: so the lists have to be decoded
 * (words_prepare) before one is, and the generator does that when the signer is chosen. */
enum { WORDS_BIP39 = 0, WORDS_XMR = 1 };

typedef struct {
    const char     *text;
    const uint16_t *off;      /* off[i] is where word i starts in text; off[n] is the length of text */
    int             n;
} words_list;

/* Decodes both lists with the given work area (4 byte aligned, words_work_size() bytes at least). Returns 0, or -1. */
int words_init(void *work, size_t worksize);
size_t words_work_size(void);
/* Decodes them now with the default work area if that has not happened yet. Returns 0 when the lists are ready. */
int words_prepare(void);
/* The list, or NULL if it cannot be had. */
const words_list *words_get(int which);
