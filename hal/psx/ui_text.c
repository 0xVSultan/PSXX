#include "ui_text.h"
#include <string.h>

typedef struct {
	const uint8_t *blob;
	const uint8_t *anchor;
	const uint8_t *text;
	unsigned       n;
} table;

static table tab[UI_RANGES][UI_NLANG];
static int   cur_lang = UI_LANG_EN;

static uint32_t le32(const uint8_t *p) { return p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24); }
static unsigned le16(const uint8_t *p) { return (unsigned) (p[0] | p[1] << 8); }

int ui_table_set(int range, int lang, const uint8_t *blob, uint32_t len, uint32_t tab_id, unsigned n)
{
	table t;
	uint32_t head, tl, at = 0;

	if (range < 0 || range >= UI_RANGES || lang < 0 || lang >= UI_NLANG) return -1;
	if (!blob) {
		memset(&tab[range][lang], 0, sizeof(table));
		return 0;
	}
	if (len < 12 || memcmp(blob, "UD2", 4) || le32(blob + 4) != tab_id || le16(blob + 8) != n || le16(blob + 10) != 0 || n == 0) return -1;
	head = 12 + 2 * ((n + 7) / 8);
	if (head >= len || blob[len - 1]) return -1;                              /* the last text is ended */
	t.blob = blob;
	t.anchor = blob + 12;
	t.text = blob + head;
	t.n = n;
	tl = len - head;
	for (unsigned i = 0; i < n; i++) {                                        /* n texts, the anchors where they say */
		if (at >= tl) return -1;
		if (!(i & 7) && le16(t.anchor + 2 * (i >> 3)) != at) return -1;
		while (at < tl && t.text[at]) at++;
		if (at >= tl) return -1;
		at++;
	}
	if (at != tl) return -1;                                                  /* nothing after the last text */
	tab[range][lang] = t;
	return 0;
}

void ui_range_clear(int range)
{
	if (range >= 0 && range < UI_RANGES) memset(tab[range], 0, UI_LANG_EXT * sizeof(table));
}

int ui_lang_set(int lang)
{
	if (lang < 0 || lang >= UI_NLANG) return -1;
	cur_lang = lang;
	return 0;
}

int ui_lang_get(void) { return cur_lang; }

void ui_ext_clear(void)
{
	for (int r = 0; r < UI_RANGES; r++) memset(&tab[r][UI_LANG_EXT], 0, sizeof(table));
	if (cur_lang == UI_LANG_EXT) cur_lang = UI_LANG_EN;
}

int ui_lang_have(int lang)
{
	if (lang == UI_LANG_EN) return 1;
	return lang > 0 && lang < UI_NLANG && tab[UI_R_A][lang].blob != NULL;
}

int ui_lang_cycle(void)
{
	for (int k = 1; k <= UI_NLANG; k++) {
		int l = (cur_lang + k) % UI_NLANG;

		if (ui_lang_have(l)) { cur_lang = l; break; }
	}
	return cur_lang;
}

static const char *lookup(const table *t, unsigned num)
{
	const char *p;

	if (!t->blob || num >= t->n) return NULL;
	p = (const char *) t->text + le16(t->anchor + 2 * (num >> 3));
	for (unsigned k = num & 7; k; k--) p += strlen(p) + 1;
	return p;
}

const char *ui_text_en(uint16_t id)
{
	unsigned r = UI_RANGE_OF(id);
	const char *s = r < UI_RANGES ? lookup(&tab[r][UI_LANG_EN], UI_NUMBER_OF(id)) : NULL;

	return s ? s : "";
}

const char *ui_text(uint16_t id)
{
	unsigned r = UI_RANGE_OF(id);
	const char *s;

	if (r >= UI_RANGES) return "";
	if (cur_lang != UI_LANG_EN) {
		s = lookup(&tab[r][cur_lang], UI_NUMBER_OF(id));
		if (s && *s) return s;                                                /* a text this language does not have is English */
	}
	return ui_text_en(id);
}
