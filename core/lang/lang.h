#pragma once
/* The language card: the index of the languages, the glyph sets (hanzi, hangul, kana) and the
 * Chinese word lists, which are stored as mappings onto the hanzi set. The word lists of the other languages are blobs of core/wordlist/wl.c. Everything here works on the
 * unpacked bytes of a group; the groups themselves are read by core/pkg (ovl_unpack_group). Nothing in here allocates: the callers give the buffers. */
#include <stddef.h>
#include <stdint.h>

enum {
    LANG_ID_INDEX = 0x0001,
    LANG_ID_HANZI = 0x0101, LANG_ID_HANGUL = 0x0102, LANG_ID_KANA = 0x0103,
    LANG_ID_BIP39 = 0x0200, LANG_ID_XMR = 0x0300,                       /* + the language id: word list blobs */
    LANG_ID_ZH_SIMPLIFIED = 0x0400, LANG_ID_ZH_TRADITIONAL = 0x0401, LANG_ID_ZH_XMR = 0x0402,
    LANG_ID_XSUB = 0x0500,                                              /* + the language id: the Monero list is a subset of the BIP39 list of the language (one bit of a mask per BIP39 word) */
    LANG_ID_UI = 0x0600                                                 /* + the language id: the table of the UI texts of the language for the range of the main card (hal/psx/ui_text.h, tools/ui_ids.py pack);
                                                                           + 0x100 the table for the signer, + 0x200 for the language module */
};

enum { LANG_BIP39 = 1, LANG_XMR = 2, LANG_ONE_CHAR = 4 };               /* flags of a language: which lists it has, a word is one character (Chinese) */
enum { LANG_GLYPH_HANZI = 1, LANG_GLYPH_HANGUL = 2, LANG_GLYPH_KANA = 4 };
enum { LANG_MAX = 16 };

typedef struct {
    uint8_t  id, flags, glyphs;         /* glyphs: LANG_GLYPH_* of the sets the words need */
    uint8_t  xmr_prefix;                /* characters of a word that the Monero checksum covers: 1 (Chinese), 3 or 4; 0: no Monero list */
    uint16_t bip_group, xmr_group;      /* group ids of the lists, 0 if the language has none */
    uint8_t  separator;                 /* 0: a space between words, 1: U+3000 (Japanese) */
    uint16_t ui_group;                  /* the group of the dictionary of the UI texts in this language, 0 if the language has none */
    char     name[17];
} lang_info;

/* the index group (0x0001) -> the languages; returns their number, or -1 */
int lang_index(const uint8_t *raw, size_t len, lang_info *out, int max);

typedef struct {
    uint8_t        w, h, fmt;
    uint16_t       n;
    const uint8_t *bits;                /* the bitmaps, in the order of the code points */
    uint16_t      *cps;                 /* the code points, ascending: n entries the caller provides */
} glyphset;

/* How many code points a glyph group holds (to size the buffer for glyphset_open), or 0 if it is not one. */
unsigned glyphset_count(const uint8_t *raw, size_t len);
/* Opens a glyph group (the unpacked bytes stay in use); cps has glyphset_count() entries. Returns 0, or -1. */
int glyphset_open(glyphset *g, const uint8_t *raw, size_t len, uint16_t *cps);
/* the index of a code point, or -1 */
int glyphset_find(const glyphset *g, unsigned cp);
/* the rows of glyph `idx`: h rows, bit 15 the leftmost pixel */
void glyphset_rows(const glyphset *g, int idx, uint16_t rows[18]);

/* The three Chinese lists as text in the form of core/coin/words.h (UTF-8, each word followed by a 0 byte, off[i] where word i starts, off[n] the length). Return the number of
 * words, or -1 (bad data, a buffer too small). The traditional and the Monero list are made from the simplified one. The groups are coded with the range coder of the word
 * lists (core/wordlist/wl.h wl_rc; tools/data_pack.py describes them). */
/* sel: 2048 entries of scratch (the glyphs of the list, put in the order of the words) */
int lang_zh_simplified(const glyphset *hanzi, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap, uint16_t *sel);
/* work: scratch of hanzi->n entries and hanzi->n bits (the glyphs the simplified list does not use) */
int lang_zh_traditional(const glyphset *hanzi, const char *stext, const uint16_t *soff, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap,
                        uint16_t *work);
int lang_zh_monero(const char *stext, const uint16_t *soff, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap);

/* The Monero list of a language whose Monero words are all words of its BIP39 list, in the same order (Japanese, Spanish): `map` has one bit per word of the BIP39 list (text stext,
 * offsets soff, sn words), set for the words the Monero list keeps (the group holds it coded: wl_mask_decode). lang_xmr_subset_size is the number of text bytes the subset needs (0 if the mask is too short or empty);
 * lang_xmr_subset writes the list in the form of core/coin/words.h and returns the number of words, or -1 (bad data, a buffer too small). */
size_t lang_xmr_subset_size(const uint16_t *soff, int sn, const uint8_t *map, size_t len);
int lang_xmr_subset(const char *stext, const uint16_t *soff, int sn, const uint8_t *map, size_t len, char *out, size_t cap, uint16_t *off, size_t offcap);

/* ---- mnemonics in any list ---- */
#include "coin/words.h"
/* BIP39 (entropy of 16, 20, 24, 28 or 32 bytes): the indexes of the words, the checksum included. Returns the number of words (12..24), or -1. */
int lang_bip39_indexes(const uint8_t *entropy, size_t len, uint16_t idx[24]);
/* Monero's legacy seed: 24 words for the 32 bytes of the key (three for every four bytes, in a list of n words), then the checksum word: the CRC-32 of the first `prefix` characters
 * of the 24 words, modulo 24, picks the word to repeat. 25 indexes. Returns 25, or -1. */
int lang_xmr_indexes(const words_list *wl, int prefix, const uint8_t key[32], uint16_t idx[25]);
/* The reverse: the key of 25 word indexes, the checksum word checked. 0, or -1 (an index outside the list, not an encoding of 32 bytes, a wrong checksum word). */
int lang_xmr_decode(const words_list *wl, int prefix, const uint16_t idx[25], uint8_t key[32]);
/* The words of a mnemonic as text, with a space between them (separator 0) or U+3000 (1). Returns the length, or -1 if cap is too small. */
int lang_join(const words_list *wl, const uint16_t *idx, int n, int separator, char *out, size_t cap);
