#pragma once
#include <stddef.h>
#include <stdint.h>

/* BIP39, English wordlist (front coded, 8.3 KB). Mnemonics are words separated by single spaces.
 * Passphrases are used as raw bytes: correct for ASCII; other characters would need NFKD normalisation first. */

#define BIP39_MAX_WORD 8
#define BIP39_MAX_MNEMONIC (24 * (BIP39_MAX_WORD + 1))   /* incl. NUL */

/* Word `idx` (0..2047) written to out (NUL terminated, at most 9 bytes). Returns its length, or -1. */
int bip39_word(unsigned idx, char out[BIP39_MAX_WORD + 1]);
/* Index of a word given by its first `len` letters (len >= 4 may be a prefix, as BIP39 words are unique in 4 letters;
 * shorter input must be the full word). Returns the index or -1. */
int bip39_find(const char *s, size_t len);
/* The words that start with pre[0..len) (lower case), in list order. Returns how many there are in all; out[0..] gets the
 * ones from number `from` on, at most `max` of them. */
int bip39_complete(const char *pre, size_t len, int from, char out[][BIP39_MAX_WORD + 1], int max);

/* Entropy of 16, 20, 24, 28 or 32 bytes -> 12..24 words. Returns the string length or -1. */
int bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t len, char *out, size_t cap);
/* Mnemonic -> entropy, verifying the word count, every word and the checksum. Returns the entropy length, or -1. */
int bip39_mnemonic_to_entropy(const char *mnemonic, uint8_t entropy[32]);
/* seed = PBKDF2-HMAC-SHA512("mnemonic" + passphrase, mnemonic, 2048 iterations). Takes ~4 s on a PlayStation. */
void bip39_seed(const char *mnemonic, const char *passphrase, uint8_t seed[64]);
