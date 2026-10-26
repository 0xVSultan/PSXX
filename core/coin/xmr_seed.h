#pragma once
#include <stddef.h>
#include <stdint.h>

/* Monero legacy 25 word mnemonic (Electrum style, English list of 1626 words).
 * 32 key bytes -> 24 words (3 words per 4 bytes) + 1 checksum word chosen by CRC-32 of the 3 letter word prefixes. */

#define XMR_SEED_WORDS 25
#define XMR_MAX_MNEMONIC (XMR_SEED_WORDS * 13)      /* words up to 12 letters + separator, incl. NUL */

/* Word `idx` (0..1625) -> out (NUL terminated, up to 13 bytes). Returns its length, or -1. */
int xmr_word(unsigned idx, char out[13]);

/* Index of a word given by its first `len` (>= 3) letters or in full, or -1. */
int xmr_word_find(const char *s, size_t len);

/* key (32 bytes, usually sc_reduce32'd) -> 25 words separated by single spaces. Returns the length, or -1. */
int xmr_seed_encode(const uint8_t key[32], char *out, size_t cap);
/* 25 words (full words or 3+ letter prefixes) -> key. Verifies word count, words and checksum. Returns 0 or -1. */
int xmr_seed_decode(const char *mnemonic, uint8_t key[32]);

/* The words that start with the `len` letters of `pre` (word completion while typing): the matches from the `from`-th on (at most `max`)
 * go to out; returns the number of matches in all. */
int xmr_complete(const char *pre, size_t len, int from, char out[][13], int max);
