#pragma once
/* Passwords for the encrypted texts and key files: a rough estimate of the entropy of a typed password (to warn about weak ones), and two kinds of random passwords:
 * 15 characters in the style of the browsers' suggestions, and 8 random words of the BIP39 list (Diceware with that list: 11 bits a word).
 *
 * The estimate is an upper bound for a password made by a person (dictionary words, names and dates are far weaker than their length suggests); it is only there to catch the
 * obviously short and uniform ones. A password that is a series of BIP39 words (three or more, different) counts 11 bits a word. */
#include <stddef.h>
#include <stdint.h>

#define PW_MAX 96                         /* the longest password the keyboards accept */
#define PW_WEAK_BITS 64                   /* below this a typed password is warned about */
#define PW_STRONG_BITS 80

enum { PW_CHARS = 0, PW_WORDS = 1 };

#define PW_CHARS_LEN 15
#define PW_WORDS_COUNT 8

/* The seed of the random passwords: HKDF-SHA256 with the digest of the background pool (everything the buttons did while the program ran, entropy_digest) as the salt and
 * the secret (the key's entropy, or the extracted entropy of a text) as the input, `what` and `type` as the info. The salt only adds: the seed is never less unpredictable than the
 * secret, and with enough unpredictable button timing in the salt it no longer follows from the secret alone (a password that cannot be recomputed from the words). */
enum { PW_SEED_TEXT = 1, PW_SEED_KEY = 2 };
void pw_seed_make(uint8_t seed[32], const uint8_t salt[32], const uint8_t *secret, size_t slen, int what, int type);

/* Estimated entropy in whole bits (0 for an empty password). */
int pw_entropy_bits(const char *pw);

/* A random password from `seed` and `counter` (the same inputs give the same password: the caller takes the seed from secret entropy and counts up for another one).
 * PW_CHARS: 15 characters out of 57 (letters and digits without l, I, O, 0, 1), at least one lower case letter, one capital and one digit, about 87 bits.
 * PW_WORDS: 8 words of the BIP39 list separated by spaces, 88 bits. Returns the entropy in bits, or -1 if `cap` is too small (96 bytes are enough for both). */
int pw_generate(int kind, const uint8_t seed[32], uint32_t counter, char *out, size_t cap);
