#pragma once
/* Typing the words of a mnemonic in another language: the keys the typed letters are matched against, the search, and the BIP39 checks that go with
 * a list of word indexes. The screens (hal/psx/lang_ui.c) only draw and move a cursor; what a keystroke means is decided here, so that it can be tested on the host.
 *
 * A word is found by a prefix of its key; the key depends on the script of the keyboard it is typed on:
 *   LANGIN_LATIN   the letters without accents, lower case (Spanish, French, Italian, Czech, Portuguese: the first letters of a word, as BIP39 says)
 *   LANGIN_KANA    the first six kana of the word as they are (the keyboard has the voiced and semi-voiced ones, so the text is composed)
 *   LANGIN_HANGUL  the first twelve jamo of the word as codes 1..51 (the compatibility jamo U+3131..3163 in order), the way the keyboard types them: a trail consonant and the lead
 *                  of the next syllable are the same key, so a word is found by its letters without the syllable breaks */
#include <stddef.h>
#include <stdint.h>
#include "coin/words.h"

enum { LANGIN_LATIN = 0, LANGIN_KANA = 1, LANGIN_HANGUL = 2 };
enum { LANGIN_KEYMAX = 18 };                      /* bytes of a key at most */

/* The key of a word (UTF-8, composed). Returns its length (without the 0 that ends it), the key is zero padded up to cap bytes, cap >= LANGIN_KEYMAX + 1. */
int langin_key(int mode, const char *word, uint8_t *out, int cap);
/* The compatibility jamo with code `code` (1..51) as UTF-8 in out (4 bytes); the code of a jamo cell. */
int langin_jamo_utf8(int code, char out[4]);

/* How many of the n keys (each `stride` bytes) begin with the tl typed bytes; the numbers of those from number `from` on go to out (at most max). */
int langin_find(const uint8_t *keys, int stride, int n, const uint8_t *typed, int tl, int from, int max, uint16_t *out);

/* The entropy of a mnemonic of n word indexes (12, 15, 18, 21, 24), the checksum checked: returns its length in bytes (16 .. 32), or -1 if the checksum does not fit. */
int langin_bip39_entropy(const uint16_t *idx, int n, uint8_t ent[32]);
/* The mnemonic as the sentence that goes into the seed: the words in NFKD with a space between them. Returns the length, or -1. */
int langin_sentence(const words_list *wl, const uint16_t *idx, int n, char *out, size_t cap);
