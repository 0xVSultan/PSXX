#include "keyboard.h"
#include <stdio.h>
#include "ui.h"
#include <string.h>
#include <psxgpu.h>
#include "font.h"
#include "kb_variants.h"
#include "pad.h"
#include "util.h"

/* Keys are laid out on a grid of half units (28 pixels): 20 half units = 560 pixels per row, centred.
 * Vertical layout (240 lines, within the safe area of ui.h): title 7 (the note to its right), text field 28..50 (one line of the text), counters 50..68,
 * the strip of variants 69..95, keys 97..201, hints Y_HINT (206..228). */
#define HALF 28
#define KEY_H 20
#define ROW_PITCH 21
#define ROWS 5
#define MAXKEYS 12
#define Y_TITLE 7
#define Y_FIELD 28
#define Y_CNT 50
#define Y_BAR 69
#define Y_KEYS 97
#define Y_HINT UI_HINT2
#define BAR_ITEM 30                     /* an entry of the strip: 28 pixels and a gap */
#define BAR_CELL_H 22
#define BAR_H 26                        /* the strip: the selected entry fills it, the others are a little lower */
#define BAR_SEL_W 48                    /* the selected entry, drawn twice as wide, at the centre of the screen (above the keys 5 and 6) */
#define MAX_VARIANTS 32
#define SUG_ITEM 86                     /* width of a suggested word: 8 letters + margin */

enum { K_CHAR, K_SHIFT, K_BKSP, K_LAYER, K_SPACE, K_OK, K_CURL, K_CURR, K_CURU, K_CURD, K_ENTER, K_TAB, K_INS };

typedef struct {
	char lab[8];
	char ch;
	uint8_t kind, pos, w;       /* position and width in half units */
} kkey;

static const char *const ROW1[3] = {"qwertyuiop", "QWERTYUIOP", "!\"#$%&'()*"};
static const char *const ROW2[3] = {"asdfghjkl", "ASDFGHJKL", "+-/:;<=>?@"};
static const char *const ROW3[3] = {"zxcvbnm", "ZXCVBNM", "[\\]^_`{|}~"};

static void add(kkey *keys, int *n, const char *lab, int ch, int kind, int pos, int w)
{
	kkey *k = &keys[(*n)++];
	strncpy(k->lab, lab, sizeof k->lab - 1);
	k->lab[sizeof k->lab - 1] = 0;
	k->ch = (char) ch;
	k->kind = (uint8_t) kind;
	k->pos = (uint8_t) pos;
	k->w = (uint8_t) w;
}

static void add_chars(kkey *keys, int *n, const char *s, int pos)
{
	for (; *s; s++, pos += 2) {
		char l[2] = {*s, 0};
		add(keys, n, l, *s, K_CHAR, pos, 2);
	}
}

/* the keys of a row in the current layer; returns how many */
static int kb_rows(const kb_state *k) { return k->hex ? 4 : k->suggest ? 3 : ROWS; }

static int row_keys(const kb_state *k, int row, kkey *keys)
{
	int n = 0, layer = k->sym ? 2 : k->shift ? 1 : 0;

	if (k->hex) {                                   /* hex keypad (1) or derivation path keypad (2): 4 x 4 keys, Del and OK at the right */
		static const char *const HEX[4] = {"0123", "4567", "89ab", "cdef"};
		static const char *const PATH[4] = {"0123", "4567", "89'/", "mh  "};
		const char *rowkeys = k->hex == 2 ? PATH[row] : HEX[row];
		for (int i = 0; i < 4; i++) {
			char l[2] = {rowkeys[i], 0};
			if (rowkeys[i] != ' ') add(keys, &n, l, rowkeys[i], K_CHAR, i * 4, 4);
		}
		if (row == 0) add(keys, &n, T(TXT_DEL), 0, K_BKSP, 16, 4);
		if (row == 3) add(keys, &n, "OK", 0, K_OK, 16, 4);
		return n;
	}

	if (k->suggest) {                               /* word mode: the letters, OK at the left and Del at the right of the last row */
		if (row < 2) add_chars(keys, &n, row ? ROW2[0] : ROW1[0], row);
		else {
			add(keys, &n, "OK", 0, K_OK, 0, 3);
			add_chars(keys, &n, ROW3[0], 3);
			add(keys, &n, T(TXT_DEL), 0, K_BKSP, 17, 3);
		}
		return n;
	}

	switch (row) {
	case 0: add_chars(keys, &n, "1234567890", 0); break;
	case 1: add_chars(keys, &n, ROW1[layer], 0); break;
	case 2: add_chars(keys, &n, ROW2[layer], layer == 2 ? 0 : 1); break;
	case 3:
		if (layer == 2) { add_chars(keys, &n, ROW3[2], 0); break; }
		add(keys, &n, k->shift == 2 ? T(TXT_SHIFT) : T(TXT_SHIFT_2), 0, K_SHIFT, 0, 3);
		add_chars(keys, &n, ROW3[layer], 3);
		add(keys, &n, T(TXT_INS), 0, K_INS, 17, 3);           /* insert / overwrite */
		break;
	default:
		add(keys, &n, k->sym ? "abc" : "?123", 0, K_LAYER, 0, 3);
		add(keys, &n, ",", ',', K_CHAR, 3, 2);
		add(keys, &n, T(TXT_TAB), 0, K_TAB, 5, 2);
		add(keys, &n, "", 0, K_CURL, 7, 2);                   /* the text cursor: a triangle is drawn on each of the four keys (Square types a space) */
		add(keys, &n, "", 0, K_CURU, 9, 2);                   /* one line up / down */
		add(keys, &n, "", 0, K_CURD, 11, 2);
		add(keys, &n, "", 0, K_CURR, 13, 2);
		add(keys, &n, ".", '.', K_CHAR, 15, 2);
		add(keys, &n, T(TXT_ENTER), 0, K_ENTER, 17, 3);       /* a new line */
		break;
	}
	return n;
}

static int center(const kkey *k) { return k->pos * 2 + k->w; }

/* the entries of the variants row for a key: the key itself, then its variants (code points) */
static int variants_of(const kb_state *k, const kkey *key, int cps[MAX_VARIANTS])
{
	int n = 0;
	if (key->kind != K_CHAR) return 0;
	cps[n++] = (unsigned char) key->ch;
	if (!k->accents) return n;
	for (unsigned i = 0; i < KB_NVARIANTS; i++) {
		if (KB_VARIANTS[i].base != key->ch) continue;
		const char *s = KB_VARIANTS[i].chars;
		int cp;
		while ((cp = font_utf8_next(&s)) != 0 && n < MAX_VARIANTS) cps[n++] = cp;
	}
	return n;
}

static void clamp_cursor(kb_state *k)
{
	kkey keys[MAXKEYS];
	int n = row_keys(k, k->row, keys);
	if (k->idx >= n) k->idx = n - 1;
	if (k->idx < 0) k->idx = 0;
}

void kb_init(kb_state *k, const char *title, const char *initial, int mask, int accents)
{
	memset(k, 0, sizeof *k);
	k->title = title;
	k->mask = mask;
	k->accents = accents;
	k->row = 1;
	k->limit = KB_DEFAULT_LIMIT;
	k->type_frame = VSync(-1) - 1000;
	if (initial) {
		strncpy(k->text, initial, KB_MAX);
		k->len = (int) strlen(k->text);
		k->cur = k->len;
	}
}

void kb_wipe(kb_state *k) { secure_zero(k, sizeof *k); }

void kb_set(kb_state *k, int limit, int hex)
{
	k->limit = limit > KB_MAX ? KB_MAX : limit;
	k->hex = hex;
	k->accents = hex ? 0 : k->accents;
	k->row = hex ? 0 : 1;
	k->idx = 0;
}

static void move_vertical(kb_state *k, int dir)
{
	kkey cur[MAXKEYS], nxt[MAXKEYS];
	int n = row_keys(k, k->row, cur);
	int c = center(&cur[k->idx < n ? k->idx : 0]);
	int rows = kb_rows(k), row = (k->row + dir + rows) % rows, best = 0, bestd = 1 << 30;
	int m = row_keys(k, row, nxt);

	for (int i = 0; i < m; i++) {
		int d = center(&nxt[i]) - c;
		if (d < 0) d = -d;
		if (d < bestd) { bestd = d; best = i; }
	}
	k->row = row;
	k->idx = best;
}

static void clear_marks(kb_state *k)
{
	k->nb = 0;
	k->marking = 0;
	k->confirm = 0;
}

static int next_off(const kb_state *k, int o);

static void type(kb_state *k, int cp)
{
	char enc[4];
	int n = font_utf8_encode(enc, cp), old = 0;
	if (k->ovr && cp != '\n' && k->cur < k->len && k->text[k->cur] != '\n') old = next_off(k, k->cur) - k->cur;      /* overwrite: the character under the cursor goes */
	if (k->len - old + n > k->limit) return;
	if (old) {
		memmove(k->text + k->cur, k->text + k->cur + old, (size_t) (k->len - k->cur - old + 1));
		k->len -= old;
	}
	memmove(k->text + k->cur + n, k->text + k->cur, (size_t) (k->len - k->cur + 1));
	memcpy(k->text + k->cur, enc, (size_t) n);
	k->len += n;
	k->cur += n;
	clear_marks(k);
	if (k->shift == 1) k->shift = 0;    /* one-shot shift applies to one character, the lock stays */
	k->type_frame = VSync(-1);
}

/* byte offset of the character before / after the one at `o` */
static int prev_off(const kb_state *k, int o)
{
	do o--; while (o > 0 && ((unsigned char) k->text[o] & 0xC0) == 0x80);
	return o;
}

static int next_off(const kb_state *k, int o)
{
	do o++; while (o < k->len && ((unsigned char) k->text[o] & 0xC0) == 0x80);
	return o;
}

/* remove the character before the cursor (all of its UTF-8 bytes) */
static void backspace(kb_state *k)
{
	int p;
	if (k->cur <= 0) return;
	p = prev_off(k, k->cur);
	memmove(k->text + p, k->text + k->cur, (size_t) (k->len - k->cur + 1));
	k->len -= k->cur - p;
	k->cur = p;
	clear_marks(k);
	k->type_frame = VSync(-1) - 1000;   /* nothing new to show */
}

/* ---- word completion ---- */

void kb_set_suggest(kb_state *k, kb_suggest_fn fn)
{
	k->suggest = fn;
	k->sug_total = k->sug_sel = k->sug_from = 0;
	k->sug_pre[0] = 0;
}

/* the lower case letters before the cursor back to the last space; returns their number, 0 if there is something else */
static int sug_prefix(const kb_state *k, char pre[KB_SUGLEN])
{
	int n = 0, o = k->cur;
	while (o > 0 && k->text[o - 1] != ' ') o--;
	for (; o < k->cur; o++) {
		char c = k->text[o];
		if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
		if (c < 'a' || c > 'z' || n >= KB_SUGLEN - 1) return 0;
		pre[n++] = c;
	}
	pre[n] = 0;
	return n;
}

static void sug_fetch(kb_state *k, int n)
{
	k->sug_total = n ? k->suggest(k->sug_pre, n, k->sug_from, k->sug, KB_SUG) : 0;
}

/* after the text or the highlight changed; `moved` = the highlight was stepped */
static void sug_refresh(kb_state *k, int moved)
{
	char pre[KB_SUGLEN];
	int n;

	if (!k->suggest || k->hex) return;
	n = sug_prefix(k, pre);
	if (strcmp(pre, k->sug_pre) || (!n && k->sug_total)) {
		strcpy(k->sug_pre, pre);
		k->sug_sel = k->sug_from = 0;
		sug_fetch(k, n);
	} else if (moved) {
		if (k->sug_sel < k->sug_from) k->sug_from = k->sug_sel;
		if (k->sug_sel >= k->sug_from + KB_SUG) k->sug_from = k->sug_sel - KB_SUG + 1;
		sug_fetch(k, n);
	}
}

/* replace the typed letters by the highlighted word and a space */
static void sug_accept(kb_state *k)
{
	char w[KB_SUGLEN];
	int n = (int) strlen(k->sug_pre);

	strcpy(w, k->sug[k->sug_sel - k->sug_from]);
	while (n-- > 0) backspace(k);
	for (const char *p = w; *p; p++) type(k, (unsigned char) *p);
	type(k, ' ');
}

/* characters per line of the text field / the full view */
static int line_chars(void) { return (GPU_XRES - 44) / font_cell_w(); }
/* the characters after which a line is broken: the width of the field, or no limit (L1 in the full view) */
/* a keypad (hex, path) has one long line in its field */
static int no_wrap(const kb_state *k) { return k->nowrap || (k->hex && !k->full); }
static int wrap_chars(const kb_state *k) { return no_wrap(k) ? 0x7fffffff : line_chars(); }
/* the first column shown of a line without wrapping: the cursor stays in view */
static int hscroll(const kb_state *k, int col) { int w = line_chars(); return no_wrap(k) && col >= w ? col - w + 1 : 0; }

/* character index of the byte offset / byte offset of a character index (clamped to the text) */
static int char_of(const char *t, int o)
{
	int c = 0;
	for (int i = 0; i < o; i++) if (((unsigned char) t[i] & 0xC0) != 0x80) c++;
	return c;
}

static int off_of(const char *t, int c)
{
	int o = 0;
	while (t[o] && c > 0) { do o++; while (t[o] && ((unsigned char) t[o] & 0xC0) == 0x80); c--; }
	return o;
}

/* The text is shown in lines of at most `maxc` characters: a line ends at a new line character (Enter) or where it is full. line_end() takes the line that starts at byte
 * offset o: *end is where its characters end, the return value is where the next line starts (a new line character belongs to the line it ends), -1 if it is the last line.
 * A text that ends with a full line or with a new line has an empty last line, where the cursor goes after it. */
static int line_end(const kb_state *k, int o, int maxc, int *end)
{
	int c = 0, p = o;
	while (p < k->len && k->text[p] != '\n' && c < maxc) { p = next_off(k, p); c++; }
	*end = p;
	if (p < k->len && k->text[p] == '\n') return p + 1;
	return c == maxc ? p : -1;
}

/* the line of the text cursor: where it starts and ends, the start of the line before and after it (-1: none), its number (from 0) */
static void cursor_line(const kb_state *k, int maxc, int *prev, int *start, int *end, int *next, int *no)
{
	int o = 0, p = -1, n = 0, e, nx;
	for (;;) {
		nx = line_end(k, o, maxc, &e);
		if (nx < 0 || nx > k->cur) break;
		p = o; o = nx; n++;
	}
	if (prev) *prev = p;
	if (start) *start = o;
	if (end) *end = e;
	if (next) *next = nx;
	if (no) *no = n;
}

static int line_count(const kb_state *k, int maxc)
{
	int o = 0, n = 1, e;
	while ((o = line_end(k, o, maxc, &e)) >= 0) n++;
	return n;
}

/* the text cursor one line up (dir -1) or down (+1), in the same column or at the end of a shorter line */
static void cursor_vertical(kb_state *k, int dir)
{
	int maxc = wrap_chars(k), prev, st, en, nx, col = 0, p, t, lim;

	cursor_line(k, maxc, &prev, &st, &en, &nx, NULL);
	for (p = st; p < k->cur; p = next_off(k, p)) col++;
	if (dir < 0) {
		if (prev < 0) return;
		t = prev;
		lim = st - (k->text[st - 1] == '\n' ? 1 : 0);
	} else {
		if (nx < 0) return;
		t = nx;
		line_end(k, nx, maxc, &lim);
	}
	for (p = t; col > 0 && p < lim; p = next_off(k, p)) col--;
	k->cur = p;
}

/* ---- marking, clipboard ---- */

static char clip[KB_CLIP][KB_MAX + 1];       /* newest first */
static uint8_t clip_secret[KB_CLIP];         /* copied from a masked field: shown as stars */

void kb_clip_wipe(void)
{
	secure_zero(clip, sizeof clip);
	secure_zero(clip_secret, sizeof clip_secret);
}

static void say(kb_state *k, const char *m)
{
	k->msg = m;
	k->msg_until = VSync(-1) + 90;
}

/* block i (0 .. nb - 1 finished, nb the one being marked) as the byte range [a, b); the character under the cursor counts */
static int block_range(const kb_state *k, int i, int *a, int *b)
{
	int lo, hi;
	if (i < k->nb) { lo = k->ba[i]; hi = k->bb[i]; }
	else if (i == k->nb && k->marking) {
		lo = k->mark_from < k->cur ? k->mark_from : k->cur;
		hi = k->mark_from < k->cur ? k->cur : k->mark_from;
	} else return 0;
	*a = lo;
	*b = hi < k->len ? next_off(k, hi) : k->len;
	return *b > *a;
}

static int block_count(const kb_state *k) { return k->nb + (k->marking ? 1 : 0); }

static int is_marked(const kb_state *k, int o)
{
	for (int i = 0; i < block_count(k); i++) {
		int a, b;
		if (block_range(k, i, &a, &b) && o >= a && o < b) return 1;
	}
	return 0;
}

#define SEP '\001'                 /* between separate blocks in a clipboard entry: pasted as a space or as nothing */
static int clip_join_space = 1;     /* paste: 1 = a single space between separate blocks, 0 = nothing */

/* the marked bytes in text order into out; separate blocks are told apart by SEP. Returns the length. */
static int marked_bytes(const kb_state *k, char *out)
{
	int n = 0, gap = 0;
	for (int o = 0; o < k->len; o++) {
		if (!is_marked(k, o)) { gap = n > 0; continue; }
		if (gap) { out[n++] = SEP; gap = 0; }
		out[n++] = k->text[o];
	}
	out[n] = 0;
	return n;
}

static int marked_count(const kb_state *k)
{
	int n = 0;
	for (int o = 0; o < k->len; o++) n += is_marked(k, o);
	return n;
}

static void delete_marked(kb_state *k)
{
	int w = 0, first = -1;
	for (int o = 0; o < k->len; o++) {
		if (is_marked(k, o)) { if (first < 0) first = o; continue; }
		k->text[w++] = k->text[o];
	}
	k->text[w] = 0;
	k->len = w;
	k->cur = first < 0 ? k->cur : first;
	if (k->cur > k->len) k->cur = k->len;
	while (k->cur > 0 && k->cur < k->len && ((unsigned char) k->text[k->cur] & 0xC0) == 0x80) k->cur--;
	clear_marks(k);
}

/* the marked text (all of the text if nothing is marked) becomes the newest clipboard entry */
static void copy_to_clip(kb_state *k)
{
	static char tmp[KB_MAX + 1];
	int n;
	if (block_count(k)) n = marked_bytes(k, tmp);
	else { memcpy(tmp, k->text, (size_t) k->len + 1); n = k->len; }
	if (n == 0) { say(k, T(TXT_NOTHING_TO_COPY)); return; }
	memmove(clip[1], clip[0], sizeof clip - sizeof clip[0]);
	memmove(clip_secret + 1, clip_secret, KB_CLIP - 1);
	memcpy(clip[0], tmp, (size_t) n + 1);
	clip_secret[0] = (uint8_t) k->mask;
	secure_zero(tmp, sizeof tmp);
	clear_marks(k);
	say(k, T(TXT_COPIED));
}

static void paste_clip(kb_state *k, int idx)
{
	const char *p = clip[idx];
	int cp;
	while ((cp = font_utf8_next(&p)) != 0) {
		if (cp == SEP) { if (clip_join_space) type(k, ' '); cp = 0; }
		if (cp == 0) continue;
		if (!k->multiline && (cp == '\n' || cp == '\t')) continue;   /* a text of one line */
		if (k->hex == 1) {                              /* only hex digits go into the hex keypad */
			if (cp >= 'A' && cp <= 'F') cp += 'a' - 'A';
			if (!((cp >= '0' && cp <= '9') || (cp >= 'a' && cp <= 'f'))) continue;
		} else if (k->hex == 2) {                       /* a path: digits, ' h H / m */
			if (cp == 'H') cp = 'h';
			if (cp == 'M') cp = 'm';
			if (!((cp >= '0' && cp <= '9') || cp == 39 || cp == 'h' || cp == '/' || cp == 'm')) continue;
		}
		type(k, cp);
	}
}

static void clip_remove(int idx)
{
	memmove(clip[idx], clip[idx + 1], (size_t) (KB_CLIP - 1 - idx) * sizeof clip[0]);
	memmove(clip_secret + idx, clip_secret + idx + 1, (size_t) (KB_CLIP - 1 - idx));
	secure_zero(clip[KB_CLIP - 1], sizeof clip[0]);
	clip_secret[KB_CLIP - 1] = 0;
}

/* the buttons in the full view (L2 + R2) */
static void full_update(kb_state *k, uint16_t pr)
{
	if (k->clip_view) {
		if ((pr & PAD_UP) && k->clip_sel > 0) k->clip_sel--;
		if ((pr & PAD_DOWN) && k->clip_sel < KB_CLIP - 1) k->clip_sel++;
		if (pr & PAD_SQUARE) clip_join_space = !clip_join_space;
		if ((pr & PAD_CIRCLE) && clip[k->clip_sel][0]) {
			if (!k->confirm) k->confirm = 1;
			else { clip_remove(k->clip_sel); k->confirm = 0; }
		}
		if ((pr & PAD_CROSS) && clip[k->clip_sel][0]) { paste_clip(k, k->clip_sel); k->clip_view = 0; k->rep_btn = 0; }
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) { k->clip_view = 0; k->rep_btn = 0; }
		return;
	}
	if (pr & PAD_SELECT) { k->clip_view = 1; k->clip_sel = 0; k->rep_btn = 0; return; }
	if (pr & PAD_START) copy_to_clip(k);
	if (pr & PAD_L1) k->nowrap = !k->nowrap;                    /* break the lines at the width of the field, or only at Enter */
	if (pr & PAD_CROSS) {                                       /* mark: start a block / end it */
		if (!k->marking) { k->marking = 1; k->mark_from = k->cur; }
		else if (k->nb < KB_BLOCKS) {
			k->ba[k->nb] = k->mark_from < k->cur ? k->mark_from : k->cur;
			k->bb[k->nb] = k->mark_from < k->cur ? k->cur : k->mark_from;
			k->nb++;
			k->marking = 0;
		} else say(k, T(TXT_TOO_MANY_BLOCKS));
	}
	if (pr & PAD_TRIANGLE) {                                    /* unmark: the open block, else the last one */
		if (k->marking) k->marking = 0;
		else if (k->nb) k->nb--;
	}
	if (pr & PAD_CIRCLE) {
		if (block_count(k) == 0) backspace(k);
		else if (!k->confirm) k->confirm = 1;
		else delete_marked(k);
	}
	if ((pr & PAD_LEFT) && k->cur > 0) k->cur = prev_off(k, k->cur);
	if ((pr & PAD_RIGHT) && k->cur < k->len) k->cur = next_off(k, k->cur);
	if (pr & PAD_UP) cursor_vertical(k, -1);
	if (pr & PAD_DOWN) cursor_vertical(k, 1);
}

/* Holding a button repeats it: directions always, O / Square / X in the key view (X only on a key that types or moves),
 * L1 / R1 through the variants row */
#define REPEAT_DELAY 22                 /* frames before it starts */
#define REPEAT_RATE 3                   /* frames between repeats */

static uint16_t kb_repeat(kb_state *k, uint16_t pr)
{
	uint16_t m = PAD_UP | PAD_DOWN | PAD_LEFT | PAD_RIGHT;

	if (k->clip_view) m = PAD_UP | PAD_DOWN;
	else if (!k->full) {
		kkey keys[MAXKEYS];
		int n, kind;
		clamp_cursor(k);
		n = row_keys(k, k->row, keys);
		kind = keys[k->idx < n ? k->idx : 0].kind;
		m |= PAD_CIRCLE | (k->hex ? 0 : PAD_SQUARE);
		if (k->accents || k->suggest) m |= PAD_L1 | PAD_R1;           /* the row of variants moves like the keys */
		if (kind == K_CHAR || kind == K_SPACE || kind == K_BKSP || kind == K_CURL || kind == K_CURR || kind == K_CURU || kind == K_CURD) m |= PAD_CROSS;
	}
	if (k->rep_btn && (!(k->held & k->rep_btn) || !(k->rep_btn & m))) k->rep_btn = 0;
	if (pr & m) {                                       /* a new press: it is the one that repeats */
		for (uint16_t b = 1; b; b = (uint16_t) (b << 1))
			if (pr & m & b) { k->rep_btn = b; k->rep_cnt = 0; }
		return pr;
	}
	if (k->rep_btn && ++k->rep_cnt >= REPEAT_DELAY && (k->rep_cnt - REPEAT_DELAY) % REPEAT_RATE == 0) pr |= k->rep_btn;
	return pr;
}

int kb_update(kb_state *k, uint16_t pr)
{
	kkey keys[MAXKEYS];
	int n, moved = 0;

	pr = kb_repeat(k, pr);
	if (k->confirm && (pr & ~PAD_CIRCLE)) {         /* a question is open: O says yes, any other button only takes it back */
		k->confirm = 0;
		k->rep_btn = 0;                             /* and if it stays held it does not start repeating its normal function */
		return KB_EDITING;
	}
	if ((pr & (PAD_L2 | PAD_R2)) && (k->held & (PAD_L2 | PAD_R2)) == (PAD_L2 | PAD_R2)) {
		k->full = !k->full;                                   /* L2 + R2: switch the full text view */
		k->clip_view = 0;
		k->confirm = 0;
		k->rep_btn = 0;                                       /* a held button does not carry its function into the other view */
		if (!(pr & PAD_L2)) k->reveal = !k->reveal;           /* L2 came first and has already toggled the stars */
		return KB_EDITING;
	}
	if (pr & PAD_L2) k->reveal = !k->reveal;
	if (k->full) { full_update(k, pr); return KB_EDITING; }
	if (pr & PAD_SELECT) return KB_CANCEL;
	if (pr & PAD_START) return KB_DONE;
	if (pr & PAD_CIRCLE) backspace(k);
	if ((pr & PAD_SQUARE) && !k->hex) {
		if (k->suggest && k->sug_total == 1) sug_accept(k);         /* the only word left: complete it */
		else if (!k->suggest) type(k, ' ');
	}
	if ((pr & PAD_TRIANGLE) && !k->hex) {
		if (k->suggest) { if (k->sug_total > 0) sug_accept(k); }
		else if (k->sym) k->ovr = !k->ovr;                          /* the symbols layer has no shift */
		else { k->shift = (k->shift + 1) % 3; k->var = 0; }
	}
	if ((pr & (PAD_L1 | PAD_R1)) && k->suggest && k->sug_total > 1) {
		if (pr & PAD_R1) k->sug_sel = (k->sug_sel + 1) % k->sug_total;
		if (pr & PAD_L1) k->sug_sel = (k->sug_sel + k->sug_total - 1) % k->sug_total;
		sug_refresh(k, 1);
	}

	clamp_cursor(k);
	n = row_keys(k, k->row, keys);
	if (pr & PAD_LEFT)  { k->idx = (k->idx + n - 1) % n; moved = 1; }
	if (pr & PAD_RIGHT) { k->idx = (k->idx + 1) % n; moved = 1; }
	if (pr & PAD_UP)    { move_vertical(k, -1); moved = 1; }
	if (pr & PAD_DOWN)  { move_vertical(k, 1); moved = 1; }
	if (moved) k->var = 0;

	if ((pr & (PAD_L1 | PAD_R1)) && !k->hex && !k->suggest) {
		int cps[MAX_VARIANTS], m = 0;
		n = row_keys(k, k->row, keys);
		if (k->accents) m = variants_of(k, &keys[k->idx], cps);
		if (m > 1) {                                                /* the strip is there: L1 / R1 step through it */
			if (pr & PAD_R1) k->var = (k->var + 1) % m;
			if (pr & PAD_L1) k->var = (k->var + m - 1) % m;
		} else if ((pr & PAD_L1) && (k->rep_btn != PAD_L1 || k->rep_cnt == 0))
			k->nowrap = !k->nowrap;                                  /* no strip: L1 switches the wrapping of the lines (once, not repeating) */
	}

	if (pr & PAD_CROSS) {
		clamp_cursor(k);
		n = row_keys(k, k->row, keys);
		const kkey *key = &keys[k->idx];
		switch (key->kind) {
		case K_CHAR: {
			int cps[MAX_VARIANTS], m = variants_of(k, key, cps);
			type(k, cps[k->var < m ? k->var : 0]);
			break;
		}
		case K_SPACE: type(k, ' '); break;
		case K_CURL:  if (k->cur > 0) k->cur = prev_off(k, k->cur); break;
		case K_CURR:  if (k->cur < k->len) k->cur = next_off(k, k->cur); break;
		case K_CURU:  cursor_vertical(k, -1); break;
		case K_CURD:  cursor_vertical(k, 1); break;
		case K_ENTER: case K_TAB: if (k->multiline) type(k, key->kind == K_ENTER ? '\n' : '\t'); break;
		case K_INS:   k->ovr = !k->ovr; break;
		case K_SHIFT: k->shift = (k->shift + 1) % 3; break;
		case K_BKSP:  backspace(k); break;
		case K_LAYER: k->sym = !k->sym; k->shift = 0; break;
		case K_OK:    return KB_DONE;
		}
		k->var = 0;
		clamp_cursor(k);
	}
	sug_refresh(k, 0);
	return KB_EDITING;
}

/* ---- drawing ---- */

/* a key cap with chamfered corners (one pixel): two overlapping rectangles */
static void cap(RenderContext *ctx, int x, int y, int w, int h, int r, int g, int b)
{
	gpu_draw_rect(ctx, 5, x + 1, y, w - 2, h, r, g, b);
	gpu_draw_rect(ctx, 5, x, y + 1, w, h - 2, r, g, b);
}

static void dark(int y, uint8_t rgb[3], void *user) { (void) y; (void) user; rgb[0] = rgb[1] = rgb[2] = 20; }

/* The strip of variants: [L1] entries [R1]. The selected entry (twice as wide, the glyph twice as wide) stays at the centre of the screen, above the keys 5 and 6, and the
 * strip moves under it; the entries that do not fit between the two button icons are not drawn. */
static void draw_variants(RenderContext *ctx, const kb_state *k, const kkey *key)
{
	int cps[MAX_VARIANTS], m = variants_of(k, key, cps);
	int xmin, xmax, sx = (GPU_XRES - BAR_SEL_W) / 2;

	if (!k->accents || m < 2) return;
	font_draw(ctx, 0, 16, Y_BAR + (BAR_H - font_cell_h()) / 2, ICO_L1, 150, 160, 200);
	font_draw(ctx, 0, GPU_XRES - 16 - font_width(ICO_R1), Y_BAR + (BAR_H - font_cell_h()) / 2, ICO_R1, 150, 160, 200);
	xmin = 16 + font_width(ICO_L1) + 8;
	xmax = GPU_XRES - 16 - font_width(ICO_R1) - 8;
	for (int i = 0; i < m; i++) {
		char l[4];
		int d = i - k->var, x = d == 0 ? sx : d < 0 ? sx + d * BAR_ITEM : sx + BAR_SEL_W + (d - 1) * BAR_ITEM;
		int w = d == 0 ? BAR_SEL_W : BAR_ITEM - 2;
		if (d && x < xmin) continue;
		if (x + w > xmax) continue;
		l[font_utf8_encode(l, cps[i])] = 0;
		if (d == 0) {
			cap(ctx, x, Y_BAR, w, BAR_H, 255, 210, 60);
			font_draw_big(ctx, 0, x + (w - 2 * font_cell_w()) / 2, Y_BAR + (BAR_H - font_cell_h()) / 2, l, 1, dark, 0);
		} else {
			cap(ctx, x, Y_BAR + (BAR_H - BAR_CELL_H) / 2, w, BAR_CELL_H, 40, 46, 84);
			font_draw(ctx, 0, x + (w - font_cell_w()) / 2, Y_BAR + (BAR_H - font_cell_h()) / 2, l, 255, 255, 255);
		}
	}
}

/* draw the characters c0 .. c1 - 1 of a UTF-8 text at (x, y); a tab shows as >, other control characters as spaces */
static void draw_span(RenderContext *ctx, int x, int y, const char *t, int c0, int c1)
{
	static char buf[4 * 80 + 4];
	int o0 = off_of(t, c0), n = off_of(t, c1) - o0;
	if (n <= 0) return;
	if (n > (int) sizeof buf - 1) n = (int) sizeof buf - 1;
	memcpy(buf, t + o0, (size_t) n);
	buf[n] = 0;
	for (int i = 0; i < n; i++)
		if ((unsigned char) buf[i] < 32) buf[i] = buf[i] == '\t' ? '>' : ' ';
	font_draw(ctx, 0, x, y, buf, 255, 255, 255);
}

/* the characters of the text, line n of m, the column of the cursor of the most a line holds, the bytes that can still be typed */
static void draw_counters(RenderContext *ctx, const kb_state *k, int y)
{
	int wc = wrap_chars(k), no, cs, ce;
	char st[100];
	int chars = char_of(k->text, k->len), col, most;

	cursor_line(k, wc, NULL, &cs, &ce, NULL, &no);
	col = char_of(k->text, k->cur) - char_of(k->text, cs);
	most = k->nowrap ? char_of(k->text, ce) - char_of(k->text, cs) : line_chars();
	sprintf(st, T(TXT_CHARS_N_LINE_N_OF_N_COLUMN_N_OF_N_REMAINING_N), chars, no + 1, line_count(k, wc), col, most, k->limit - k->len);
	font_draw(ctx, 0, 16, y, st, 150, 160, 200);
	font_draw(ctx, 0, GPU_XRES - 16 - font_width(T(TXT_WRAP)), y, T(TXT_WRAP), k->nowrap ? 90 : 255, k->nowrap ? 96 : 220, k->nowrap ? 130 : 80);   /* lit while lines are broken at the width of the field */
}

/* the text cursor: an underline, a block when typing overwrites; y is the bottom of the line */
static void cursor_rect(RenderContext *ctx, const kb_state *k, int x, int y)
{
	int h = k->ovr ? 8 : 2;
	gpu_draw_rect(ctx, 0, x, y - h, font_cell_w(), h, 255, 220, 80);
}

/* the triangle of a cursor key, centred on (cx, cy): up / down 18 wide and 9 high, left / right 9 wide on the screen (the pixels are twice as tall as wide), 18 pixels and 9 rows too */
static void arrow(RenderContext *ctx, int cx, int cy, int kind, int c)
{
	for (int r = 0; r < 9; r++) {
		int hor = kind == K_CURL || kind == K_CURR, d = r < 4 ? 4 - r : r - 4;
		int w = hor ? 2 * (9 - 2 * d) : 2 + 2 * (kind == K_CURU ? r : 8 - r);
		gpu_draw_rect(ctx, 3, !hor ? cx - w / 2 : kind == K_CURR ? cx - 9 : cx + 9 - w, cy - 4 + r, w, 1, c, c, c);
	}
}

void kb_draw(RenderContext *ctx, const kb_state *k)
{
	kkey keys[MAXKEYS];
	const int x0 = (GPU_XRES - 20 * HALF) / 2;
	static char shown[KB_MAX + 4];
	int fw = font_cell_w();
	const int maxc = line_chars();                  /* characters that fit the text field */
	const int wc = wrap_chars(k);                   /* where a line is broken */

	/* title; at the right the note (a size, an error) or the visibility hint of a masked text; between them the key of the full view, when there is room for it */
	{
		static const char EYES[] = ICO_L2 "+" ICO_R2 ICO_EYES;
		const char *right = k->mask ? (k->reveal ? T(TXT_HINT_HIDE_2) : T(TXT_HINT_SHOW)) : k->note && k->note[0] ? k->note : "";
		int rx = GPU_XRES - 16 - font_width(right), ex = 16 + font_width(k->title) + 16;

		font_draw(ctx, 0, 16, Y_TITLE, k->title, 255, 255, 255);
		if (ex + font_width(EYES) + 16 <= rx) font_draw(ctx, 0, ex, Y_TITLE, EYES, 150, 160, 200);
		if (k->mask) font_draw(ctx, 0, rx, Y_TITLE, right, 150, 160, 200);
		else if (right[0]) {
			int w = k->warn == 2 ? 255 : k->warn == 1 ? 255 : 150, g = k->warn == 2 ? 100 : k->warn == 1 ? 190 : 160;
			int b = k->warn ? 80 : 200;
			font_draw(ctx, 0, rx, Y_TITLE, right, w, g, b);
		}
	}

	/* the text as shown: stars for a masked text (the character typed last stays visible for a moment) */
	int cc = char_of(k->text, k->cur), total;
	if (k->mask && !k->reveal) {
		const char *p = k->text;
		int i = 0, cp, o = 0;
		while ((cp = font_utf8_next(&p)) != 0) {
			if (i == cc - 1 && VSync(-1) - k->type_frame < 60) o += font_utf8_encode(shown + o, cp);
			else shown[o++] = '*';
			i++;
		}
		shown[o] = 0;
	} else {
		strcpy(shown, k->text);
	}
	total = font_utf8_len(shown);

	if (k->full) {
		/* the whole text over several lines, the cursor line kept in view */
		const int lines = 6, pitch = 20;
		char st[48];
		gpu_draw_rect(ctx, 8, 14, Y_FIELD, GPU_XRES - 28, lines * pitch + 6, 200, 200, 200);
		gpu_draw_rect(ctx, 7, 16, Y_FIELD + 2, GPU_XRES - 32, lines * pitch + 2, 8, 8, 24);
		if (k->clip_view) {
			/* the clipboard: newest entry first, 6 lines visible around the one under the cursor */
			int top = k->clip_sel - 2;
			if (top > KB_CLIP - lines) top = KB_CLIP - lines;
			if (top < 0) top = 0;
			for (int l = 0; l < lines && top + l < KB_CLIP; l++) {
				int e = top + l, y = Y_FIELD + 4 + l * pitch, o = 0, cp;
				const char *p = clip[e];
				char line[230];
				if (e == k->clip_sel) gpu_draw_rect(ctx, 6, 18, y - 1, GPU_XRES - 36, pitch - 1, 50, 90, 200);
				o += sprintf(line, "%2d ", e + 1);
				if (!clip[e][0]) { strcpy(line + o, "-"); }
				else {
					int n = 0, mk = clip_secret[e] && !k->reveal;
					while ((cp = font_utf8_next(&p)) != 0 && n < 52) {
						if (mk) line[o++] = '*';
						else if (cp == SEP) line[o++] = '|';
						else if (cp < 32) line[o++] = ' ';
						else o += font_utf8_encode(line + o, cp);
						n++;
					}
					if (cp) { line[o++] = '.'; line[o++] = '.'; }
					line[o] = 0;
				}
				font_draw(ctx, 0, 20, y, line, 255, 255, 255);
			}
			if (k->confirm) {
				font_draw(ctx, 0, 16, Y_FIELD + lines * pitch + 6, T(TXT_DELETE_THIS_CLIPBOARD_ENTRY), 255, 190, 80);
				font_draw(ctx, 0, 16, UI_HINT1, T(TXT_HINT_YES_DELETE_SELECTED), 255, 190, 80);
			} else {
				font_draw(ctx, 0, 16, Y_FIELD + lines * pitch + 6, clip_join_space ? T(TXT_CLIPBOARD_BLOCKS_JOINED_BY_A)
				                                                                     : T(TXT_CLIPBOARD_BLOCKS_JOINED), 255, 220, 80);
				font_draw(ctx, 0, 16, Y_HINT, T(TXT_HINT_PASTE_DELETE_JOIN), 150, 160, 200);                  /* both hints fit on one line */
				font_draw(ctx, 0, 16 + font_width(T(TXT_HINT_PASTE_DELETE_JOIN)) + 30, Y_HINT, T(TXT_HINT_BACK_2), 150, 160, 200);
			}
			return;
		}
		{
			int cl, cs, nl = line_count(k, wc), top, lo = 0, e, hx;
			cursor_line(k, wc, NULL, &cs, NULL, NULL, &cl);
			hx = hscroll(k, cc - char_of(k->text, cs));
			top = cl - 2;
			if (top > nl - lines) top = nl - lines;
			if (top < 0) top = 0;
			for (int l = 0; l < top; l++) lo = line_end(k, lo, wc, &e);            /* the first line shown */
			for (int l = 0; l < lines && lo >= 0; l++) {
				int le, nx = line_end(k, lo, wc, &le), c0 = char_of(k->text, lo), c1 = char_of(k->text, le), d0 = c0 + hx, d1 = c1 < d0 + maxc ? c1 : d0 + maxc;
				for (int i = 0; i < block_count(k); i++) {                         /* the marks first: they lie behind the text */
					int a, b, x0c, x1c;
					if (!block_range(k, i, &a, &b)) continue;
					a = char_of(k->text, a);
					b = char_of(k->text, b);
					x0c = a > d0 ? a : d0;
					x1c = b < d1 ? b : d1;
					if (x1c > x0c)
						gpu_draw_rect(ctx, 6, 20 + (x0c - d0) * fw, Y_FIELD + 3 + l * pitch, (x1c - x0c) * fw, pitch - 1,
						              i < k->nb ? 50 : 170, i < k->nb ? 90 : 120, i < k->nb ? 200 : 30);
				}
				if (d1 > d0) draw_span(ctx, 20, Y_FIELD + 4 + l * pitch, shown, d0, d1);
				if (lo == cs && ((VSync(-1) >> 4) & 1))
					cursor_rect(ctx, k, 20 + (cc - d0) * fw, Y_FIELD + 4 + l * pitch + 18);
				lo = nx;
			}
		}
		/* status line: the question, a message, what is marked, or where the cursor is */
		if (k->confirm) font_draw(ctx, 0, 16, Y_FIELD + lines * pitch + 6, T(TXT_DELETE_THE_MARKED_TEXT), 255, 190, 80);
		else if (k->msg && VSync(-1) < k->msg_until) font_draw(ctx, 0, 16, Y_FIELD + lines * pitch + 6, k->msg, 255, 220, 80);
		else if (block_count(k)) {
			sprintf(st, TN(block_count(k), TXT_BYTES_MARKED_IN_BLOCK_ONE, TXT_BYTES_MARKED_IN_BLOCK_MANY), marked_count(k), block_count(k));
			font_draw(ctx, 0, 16, Y_FIELD + lines * pitch + 6, st, 120, 170, 255);
		} else draw_counters(ctx, k, Y_FIELD + lines * pitch + 6);
		if (k->confirm) {
			font_draw(ctx, 0, 16, UI_HINT1, T(TXT_HINT_YES_DELETE_SELECTED), 255, 190, 80);
		} else {
			font_draw(ctx, 0, 16, UI_HINT1, T(TXT_HINT_MOVE_MARK_UNMARK_DELETE), 150, 160, 200);
			font_draw(ctx, 0, 16, Y_HINT, T(TXT_HINT_COPY_CLIPBOARD), 150, 160, 200);
		}
		return;
	}

	/* text field: the line of the text that has the cursor (Up / Down move between the lines); a keypad has one long line that scrolls around the cursor, "<" and ">" mark the cut off ends */
	if (!k->suggest) {
		gpu_draw_rect(ctx, 8, 14, Y_FIELD, GPU_XRES - 28, 22, 200, 200, 200);
		gpu_draw_rect(ctx, 7, 16, Y_FIELD + 2, GPU_XRES - 32, 18, 8, 8, 24);
		{
			int cs, ce, c0, d0, d1;
			cursor_line(k, wc, NULL, &cs, &ce, NULL, NULL);
			c0 = char_of(k->text, cs);
			d0 = c0 + hscroll(k, cc - c0);
			d1 = char_of(k->text, ce);
			if (d1 > d0 + maxc) d1 = d0 + maxc;
			if (d1 > d0) draw_span(ctx, 20, Y_FIELD + 2, shown, d0, d1);
			if ((VSync(-1) >> 4) & 1) cursor_rect(ctx, k, 20 + (cc - d0) * fw, Y_FIELD + 20);
			if (!k->hex) draw_counters(ctx, k, Y_CNT);
		}
	}

	/* word mode: the words that fit the typed letters in place of the text field, below them the counter */
	if (k->suggest) {
		int shown_n = k->sug_total - k->sug_from < KB_SUG ? k->sug_total - k->sug_from : KB_SUG;
		int x = (GPU_XRES - KB_SUG * SUG_ITEM) / 2, words = 0, intok = 0, cur_no;
		char cnt[48];

		for (const char *p = k->text; *p; p++) {                       /* the words typed so far */
			if (*p == ' ') intok = 0;
			else if (!intok) { intok = 1; words++; }
		}
		cur_no = intok ? words : words + 1;
		if (cur_no > k->goal) cur_no = k->goal;
		for (int i = 0; i < KB_SUG; i++) {
			int on = i < shown_n, sel = on && k->sug_from + i == k->sug_sel, c = sel ? 20 : 255;
			if (sel) cap(ctx, x + i * SUG_ITEM + 1, Y_FIELD, SUG_ITEM - 2, KEY_H, 255, 210, 60);
			else     cap(ctx, x + i * SUG_ITEM + 1, Y_FIELD, SUG_ITEM - 2, KEY_H, on ? 40 : 20, on ? 46 : 22, on ? 84 : 44);
			if (on) font_draw(ctx, 0, x + i * SUG_ITEM + (SUG_ITEM - font_width(k->sug[i])) / 2, Y_FIELD + (KEY_H - font_cell_h()) / 2, k->sug[i], c, c, c);
		}
		if (k->sug_total > 1) {
			font_draw(ctx, 0, 16, Y_FIELD + 2, ICO_L1, 150, 160, 200);
			font_draw(ctx, 0, GPU_XRES - 16 - font_width(ICO_R1), Y_FIELD + 2, ICO_R1, 150, 160, 200);
		}
		if (words >= k->goal && !intok) {
			font_draw(ctx, 0, 16, Y_BAR, T(TXT_ALL_WORDS_TYPED_OK_OR_START), 120, 255, 120);
		} else {
			sprintf(cnt, T(TXT_WORD_N_OF_N), cur_no, k->goal);
			font_draw(ctx, 0, 16, Y_BAR, cnt, 255, 220, 80);
			if (k->sug_pre[0]) {
				sprintf(cnt, "%s_", k->sug_pre);
				font_draw(ctx, 0, 16 + 18 * fw, Y_BAR, cnt, 255, 255, 255);
			}
			if (k->sug_total > 1) {
				sprintf(cnt, T(TXT_MATCH_N), k->sug_sel + 1, k->sug_total);
				font_draw(ctx, 0, GPU_XRES - 16 - font_width(cnt), Y_BAR, cnt, 150, 160, 200);
			}
		}
	}

	/* keys */
	for (int row = 0; row < kb_rows(k); row++) {
		int n = row_keys(k, row, keys);
		int y = Y_KEYS + (k->suggest ? 16 : 0) + row * ROW_PITCH;
		for (int i = 0; i < n; i++) {
			const kkey *key = &keys[i];
			int x = x0 + key->pos * HALF + 1, w = key->w * HALF - 2;
			int sel = row == k->row && i == k->idx;
			int special = key->kind != K_CHAR && key->kind != K_SPACE;
			int on = (key->kind == K_SHIFT && k->shift) || (key->kind == K_LAYER && k->sym) || (key->kind == K_INS && k->ovr);
			int locked = key->kind == K_SHIFT && k->shift == 2;
			int lc = 255;
			if ((key->kind == K_ENTER || key->kind == K_TAB) && !k->multiline) { cap(ctx, x, y, w, KEY_H, sel ? 150 : 34, sel ? 130 : 38, sel ? 60 : 64); lc = sel ? 60 : 100; }   /* off: a text of one line */
			else if (sel)     { cap(ctx, x, y, w, KEY_H, 255, 210, 60); lc = 20; }
			else if (locked)  cap(ctx, x, y, w, KEY_H, 220, 140, 40);
			else if (on)      cap(ctx, x, y, w, KEY_H, 90, 130, 220);
			else if (special) cap(ctx, x, y, w, KEY_H, 74, 82, 128);
			else              cap(ctx, x, y, w, KEY_H, 50, 56, 96);
			font_draw(ctx, 0, x + (w - font_width(key->lab)) / 2, y + (KEY_H - font_cell_h()) / 2, key->lab, lc, lc, lc);
			if (key->kind >= K_CURL && key->kind <= K_CURD) arrow(ctx, x + w / 2, y + KEY_H / 2, key->kind, lc);
			if (sel) draw_variants(ctx, k, key);
		}
	}

	/* hints */
	font_draw(ctx, 0, 16, Y_HINT, k->hex ? T(TXT_HINT_TYPE_DEL_DONE_CANCEL)
	                                     : k->suggest ? T(TXT_HINT_TYPE_DEL_TAKE_PICK_DONE_CANCEL)
	                                     : k->sym ? T(TXT_HINT_TYPE_DEL_SPACE_INS_DONE)
	                                     : T(TXT_HINT_TYPE_DEL_SPACE_SHIFT_DONE), 150, 160, 200);
}
