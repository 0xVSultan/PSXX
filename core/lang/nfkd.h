#pragma once
/* NFKD of the text of a mnemonic. A BIP39 mnemonic in another language than English goes into the seed as the NFKD form of its sentence, and the word lists in RAM are in the
 * composed form (NFC), which is what the screen draws. This covers what the lists use: Hangul syllables (by formula), U+3000 (to a space), and the characters of nfkd_tab.h
 * (tools/gen_nfkd.py: the accented Latin letters, the voiced kana). Everything else is copied as it is. */
#include <stddef.h>

/* UTF-8 in, UTF-8 out (NUL terminated). Returns the length, or (size_t) -1 if cap is too small or the text is not UTF-8. in and out must not overlap. */
size_t lang_nfkd(const char *in, char *out, size_t cap);
