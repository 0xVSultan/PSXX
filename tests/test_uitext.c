/* The text tables by identifier (hal/psx/ui_text.c) against tests/uitext_vectors.txt (tools/gen_uitext_vectors.py, with the packer of tools/ui_ids.py): the texts of an accepted table
 * are found by their number, a language that lacks a text (or a table) shows English, an identifier that is not there gives "" (never NULL), a table can be replaced and a range
 * taken away, and a table of another list of texts or a damaged one is refused and changes nothing. Usage: test_uitext <uitext_vectors.txt> */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../hal/psx/ui_text.h"

static int unhex(const char *s, uint8_t *out, size_t max)
{
	size_t n = 0;

	while (isxdigit((unsigned char) s[0]) && isxdigit((unsigned char) s[1])) {
		char t[3] = {s[0], s[1], 0};
		if (n >= max) return -1;
		out[n++] = (uint8_t) strtoul(t, NULL, 16);
		s += 2;
	}
	return (int) n;
}

static int total, bad;
#define CHECK(c, ...) do { total++; if (!(c)) { bad++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(int argc, char **argv)
{
	FILE *f = fopen(argc > 1 ? argv[1] : "tests/uitext_vectors.txt", "r");
	static char line[1 << 16];
	static uint8_t blob[1 << 15];
	static uint8_t keep[8][3][1 << 13];       /* the blobs stay where they are: the tables are used in place */
	int nline = 0;

	if (!f) { printf("cannot read the vectors\n"); return 2; }
	CHECK(ui_lang_get() == UI_LANG_EN, "the language starts as English");
	CHECK(ui_lang_set(7) == -1 && ui_lang_set(-1) == -1 && ui_lang_get() == UI_LANG_EN, "a number that is not a language is refused");
	CHECK(ui_text(UI_ID(0, 0)) != NULL && ui_text(UI_ID(0, 0))[0] == 0, "no table: the empty text, not NULL");
	while (fgets(line, sizeof line, f)) {
		unsigned r, l, n, tid, id;
		char hex[1 << 15];
		char *p = line;

		nline++;
		if (line[0] == '#' || line[0] == '\n') continue;
		line[strcspn(line, "\r\n")] = 0;
		if (sscanf(p, "tab %u %u %x %u %32767s", &r, &l, &tid, &n, hex) == 5 || sscanf(p, "bad %u %u %x %u %32767s", &r, &l, &tid, &n, hex) == 5) {
			int len = unhex(hex, blob, sizeof blob), rc;
			int is_tab = !strncmp(p, "tab", 3);
			uint8_t *dst = (is_tab && r < 8 && l < 3 && len >= 0 && (size_t) len <= sizeof keep[0][0]) ? keep[r][l] : blob;

			if (dst != blob) memcpy(dst, blob, (size_t) len);
			if (is_tab && dst != blob) {                                 /* a good table replaces the old one: the old blob may be overwritten only after that */
				rc = ui_table_set((int) r, (int) l, dst, (uint32_t) len, tid, n);
				CHECK(rc == 0, "line %d: a good table is accepted (range %u, language %u)", nline, r, l);
			} else {
				rc = ui_table_set((int) r, (int) l, blob, (uint32_t) len, tid, n);
				CHECK(rc == -1, "line %d: a bad table is refused (range %u, language %u, %d bytes)", nline, r, l, len);
			}
		} else if (sscanf(p, "lang %u", &l) == 1) {
			CHECK(ui_lang_set((int) l) == 0 && ui_lang_get() == (int) l, "line %d: the language is set", nline);
		} else if (!strncmp(p, "clear ", 6)) {
			ui_range_clear(atoi(p + 6));
		} else if (!strncmp(p, "have ", 5)) {
			int lg = atoi(p + 5), want = atoi(strchr(p + 5, ' ') + 1);
			CHECK(ui_lang_have(lg) == want, "line %d: ui_lang_have(%d) = %d (wanted %d)", nline, lg, ui_lang_have(lg), want);
		} else if (!strncmp(p, "cycle ", 6)) {
			int want = atoi(p + 6), got = ui_lang_cycle();
			CHECK(got == want && ui_lang_get() == want, "line %d: the next language is %d (wanted %d)", nline, got, want);
		} else if (!strncmp(p, "getlang ", 8)) {
			CHECK(ui_lang_get() == atoi(p + 8), "line %d: the language is %d (wanted %d)", nline, ui_lang_get(), atoi(p + 8));
		} else if (!strcmp(p, "extclear")) {
			ui_ext_clear();
		} else if (!strncmp(p, "text ", 5) || !strncmp(p, "en ", 3)) {
			int en = p[0] == 'e';
			const char *q = p + (en ? 3 : 5), *sp = strchr(q, ' ');
			uint8_t want[512];
			int wl;
			const char *got;

			id = (unsigned) strtoul(q, NULL, 10);
			wl = sp ? unhex(sp + 1, want, sizeof want - 1) : 0;
			if (wl < 0) wl = 0;
			want[wl] = 0;
			got = en ? ui_text_en((uint16_t) id) : ui_text((uint16_t) id);
			CHECK(got != NULL && !strcmp(got, (const char *) want), "line %d: %s(0x%04x) = \"%s\" (wanted \"%s\")", nline, en ? "en" : "text", id, got ? got : "(null)", (const char *) want);
		} else {
			printf("line %d: not understood: %s\n", nline, line);
			return 2;
		}
	}
	fclose(f);
	printf("uitext: %d checks, %d failures\n", total, bad);
	return bad != 0;
}
