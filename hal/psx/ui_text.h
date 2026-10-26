#pragma once
#include <stddef.h>
#include <stdint.h>

/* The texts of the screens by identifier. The program has no text in its code: a screen asks T(TXT_BACK) for the text of the current language.
 *
 * An identifier is  range << 12 | number.  A range belongs to a part of the program that has its own texts (and is loaded with it):
 *     UI_R_A  the main card (always in RAM), UI_R_B  the signer, UI_R_L  the language module.
 * A range has a table per language: English is built into the card that carries the range, every other language (Hungarian too: tools/strings/ui_15_<range>.txt) comes from the data card as UI_LANG_EXT, one blob per range; UI_LANG_HU is only used by the host programs (UI_WITH_HU).
 * A text that a table does not have (an empty text) is shown in English, the English table is complete.
 *
 * A table ("UD2"):  "UD2\0", u32 tab_id, u16 n, u16 0, u16 anchor[(n + 7) / 8], then the texts in the order of the numbers, each ended by a 0 byte. anchor[k] is the offset (from the
 * start of the texts) of text 8 * k; a lookup steps over at most 7 texts. tab_id identifies the list of the texts of the range (tools/ui_ids.py: a hash of their names, in order): a table
 * made for another list is refused, so that a card of another release shows English instead of wrong texts.
 *
 * No RAM beyond a few pointers: the tables are used where they are (in the image of the card, or in the buffer that the data card was read into). */

#define UI_R_A 0
#define UI_R_B 1
#define UI_R_L 2
#define UI_RANGES 3

enum { UI_LANG_EN = 0, UI_LANG_HU = 1, UI_LANG_EXT = 2, UI_NLANG = 3 };

#define UI_ID(range, number) ((uint16_t) ((range) << 12 | (number)))
#define UI_RANGE_OF(id) ((unsigned) (id) >> 12)
#define UI_NUMBER_OF(id) ((unsigned) (id) & 0xFFFu)

/* Make a table known: range, language, the blob, the number of texts and the tab_id the range has (generated: ui_ids.h). Returns 0, or -1 when the blob is not a table of that range
 * (nothing changes then). A table can be replaced; NULL takes it away. The English table of a range is the one that must be there. */
int ui_table_set(int range, int lang, const uint8_t *blob, uint32_t len, uint32_t tab_id, unsigned n);
/* A range goes away with its module: its English and Hungarian tables (they are in the image of the module). The table of the language of the data card is not touched: it lives in
 * the memory of the language module (ui_ext_clear). */
void ui_range_clear(int range);
/* The language of the screens: UI_LANG_EN, UI_LANG_HU or UI_LANG_EXT. Returns 0, or -1 for a number that is not a language (nothing changes). Takes effect at the next drawing. */
int ui_lang_set(int lang);
/* The language of the data card goes away (its module is wiped, or it is switched off): the tables of UI_LANG_EXT of every range are taken away and, if that was the language of
 * the screens, English comes back. */
void ui_ext_clear(void);
/* Does the main card have the texts of this language (a table in the range of the main card)? English always. */
int ui_lang_have(int lang);
/* The next language that is there (English, Hungarian, the language of the data card, English ...), set; returns it. Takes effect at the next drawing. */
int ui_lang_cycle(void);
int ui_lang_get(void);
/* The text; "" for an identifier of a range that is not loaded, and never NULL. */
const char *ui_text(uint16_t id);
/* The text of English, whatever the language is (for a log, a file name). */
const char *ui_text_en(uint16_t id);

#define T(id) ui_text(id)
/* The text for a count: one form for 1 and another for the rest, each a complete text with the %d in it (English "1 input", "2 inputs"; a language that does not
 * change the word has the same text twice). n is evaluated twice. */
#define TN(n, one, many) ui_text((n) == 1 ? (one) : (many))
