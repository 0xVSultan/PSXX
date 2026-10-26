/* The screens of the language module (hal/psx/lang_ui.c) on the host: the module is compiled into this file with stand-ins for the console (tests/langui_stub, a scripted
 * controller, a keyboard that types a text, a screen that only remembers what was drawn), and a person is imitated that types the words of a mnemonic in Japanese, Korean,
 * Chinese and Spanish, answers the check of the words, and makes the mistakes a person makes (a wrong last word, a wrong answer). What is checked: the entropy that comes
 * out, that the screen never draws a character whose glyph was not loaded, that every loop ends, that what was kept is forgotten.
 * Usage: test_langui <data.pkg> <data.json>   (the language card of tools/data_pack.py; without it the test says so and passes) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif

#include "layout_check.h"
#define ARENA1_LO ((uintptr_t) MM_LANG_LO + 0x9000)      /* where the module ends in the real thing (0x801ECF20, image and bss 36 640 bytes): the rest of its slot is the second segment of the data */
#include "lang_ui.c"                                  /* the module, with its statics */
#include "pkg/ovl.h"

/* ---- the console, as far as the module sees it ---- */

const psxx_release psxx_release_info = {{'P', 'S', 'X', 'X', 'R', 'E', 'L', '1'}, {0}, {0}, {1}, {0}};
const lang_api *psxx_lang;
int (*font_hook_draw)(RenderContext *ctx, int cp, int x, int y, int r, int g, int b);
int (*font_hook_width)(int cp);

static long frames;
static int  presents, missing_glyphs, loaded_n;
static uint16_t loaded[600];
static char screen[4096], last_screen[4096];

int VSync(int mode) { (void) mode; if (++frames > 4000000) { printf("FAIL: a loop does not end\n"); exit(1); } return (int) frames; }
void gpu_present(RenderContext *ctx) { presents++; memcpy(last_screen, screen, sizeof screen); screen[0] = 0; lc_frame("language module", ctx->yres); }    /* the layout of every frame */
void gpu_draw_rect(RenderContext *ctx, int z, int x, int y, int w, int h, int r, int g, int b) { (void) ctx; (void) z; (void) r; (void) g; (void) b; lc_rect(x, y, w, h); }

int font_utf8_next(const char **s)
{
	const unsigned char *p = (const unsigned char *) *s;
	int cp;

	if (!*p) return 0;
	if (*p < 0x80) { cp = *p; *s += 1; }
	else if ((*p & 0xE0) == 0xC0) { cp = (p[0] & 31) << 6 | (p[1] & 63); *s += 2; }
	else { cp = (p[0] & 15) << 12 | (p[1] & 63) << 6 | (p[2] & 63); *s += 3; }
	return cp;
}
int font_utf8_len(const char *s) { int n = 0; while (font_utf8_next(&s)) n++; return n; }
int font_utf8_encode(char *out, int cp) { (void) out; (void) cp; return 0; }

static int in_base_font(int cp) { return cp <= 0x24F || (cp >= 0x370 && cp <= 0x4FF) || (cp >= 0x1A0 && cp <= 0x1B0) || (cp >= 0x1EA0 && cp <= 0x1EFF) || cp < 0x20; }
static int is_loaded(int cp) { for (int i = 0; i < loaded_n; i++) if (loaded[i] == cp) return 1; return 0; }

void font_draw(RenderContext *ctx, int z, int x, int y, const char *s, int r, int g, int b)
{
	const char *p = s;
	int cp;

	(void) ctx; (void) z; (void) r; (void) g; (void) b;
	lc_text(x, y, s);
	if (strlen(screen) + strlen(s) + 2 < sizeof screen) { strcat(screen, s); strcat(screen, "\n"); }
	while ((cp = font_utf8_next(&p)) != 0)
		if (!in_base_font(cp) && !is_loaded(cp)) { missing_glyphs++; if (missing_glyphs < 5) printf("  glyph U+%04X is drawn but not loaded: %s\n", cp, s); }
}
int font_width(const char *s) { return lc_width(s); }
static int ext_width(int cp) { return in_base_font(cp) ? 0 : 32; }          /* a glyph of the card: 16 pixels, drawn twice as wide (fontext.c) */

int font_ext_load(const glyphset *gs, const uint16_t *cp, int n)
{
	loaded_n = 0;
	for (int i = 0; i < n && loaded_n < 580; i++) if (glyphset_find(gs, cp[i]) >= 0 && !is_loaded(cp[i])) loaded[loaded_n++] = cp[i];
	if (loaded_n > FONT_EXT_MAX) { printf("FAIL: %d glyphs, the page holds %d\n", loaded_n, FONT_EXT_MAX); exit(1); }
	return loaded_n;
}
void font_ext_clear(void) { loaded_n = 0; }

/* the controller: a queue of presses, or a function that decides from the state of the module */
static uint16_t queue[300000];
static int      qn, qi;
static uint16_t (*dyn)(uint16_t *held);
static uint16_t cur_pressed;

static void press(uint16_t m) { queue[qn++] = m; }
int input_poll(input_state *in, entropy_pool *pool)
{
	uint16_t held = 0;
	(void) pool;
	cur_pressed = dyn ? dyn(&held) : qi < qn ? queue[qi++] : 0;
	in->ps.buttons = held;
	return 1;
}
uint16_t input_take_pressed(input_state *in) { (void) in; return cur_pressed; }

/* the keyboard: it "types" the next text of a list when the module asks, and remembers the suggestion function */
static const char *kb_texts[8];
static int         kb_ntext, kb_next;
static kb_suggest_fn kb_sug;

void kb_init(kb_state *k, const char *title, const char *initial, int mask, int accents) { (void) title; (void) initial; (void) mask; (void) accents; memset(k, 0, sizeof *k); }
void kb_set(kb_state *k, int limit, int hex) { k->limit = limit; k->hex = hex; }
void kb_set_suggest(kb_state *k, kb_suggest_fn fn) { (void) k; kb_sug = fn; }
int kb_update(kb_state *k, uint16_t pressed)
{
	(void) pressed;
	if (kb_next >= kb_ntext) return KB_CANCEL;
	strcpy(k->text, kb_texts[kb_next++]);
	k->len = (int) strlen(k->text);
	return KB_DONE;
}
void kb_draw(RenderContext *ctx, const kb_state *k) { (void) ctx; if (k->note) strcat(screen, k->note); }
void kb_wipe(kb_state *k) { memset(k->text, 0, sizeof k->text); k->len = 0; }
void kb_clip_wipe(void) {}

/* the card: the groups come from the package file */
static uint8_t file_buf[1 << 18];
static size_t file_size;
static pkg data_pkg;
static uint8_t ostage[64 * 1024];
static uint16_t oprobs[OVL_PROBS];

static int mem_read(void *ctx_, uint32_t off, uint8_t *buf, uint32_t len) { (void) ctx_; if ((size_t) off + len > file_size) return -1; memcpy(buf, file_buf + off, len); return 0; }

void ldr_set_progress(ldr_progress_fn fn, void *user) { (void) fn; (void) user; }
int ldr_cancelled(void) { return 0; }
const char *ldr_describe(int code, int detail) { (void) code; (void) detail; return "error"; }
int ldr_unpack_group(ldr_pkg *p, uint16_t gid, uint8_t *dst, uint32_t dstcap, uint8_t *stage, uint32_t stagecap, uint32_t *rawlen, int *detail)
{
	(void) p;
	return ovl_unpack_group(&data_pkg, gid, dst, dstcap, stage, stagecap, oprobs, rawlen, detail);
}
void su_init(su *s, RenderContext *ctx, input_state *in, int hz, const char *title, const char *name, int kind, const uint8_t pin[32], const uint8_t base_id[32], uint16_t group)
{ (void) s; (void) ctx; (void) in; (void) hz; (void) title; (void) name; (void) kind; (void) pin; (void) base_id; (void) group; }
void su_enter(su *s, int frame) { (void) s; (void) frame; }
int su_update(su *s, uint16_t pressed, int frame) { (void) s; (void) pressed; (void) frame; return SU_RUNNING; }
void cw_refresh(cw *c, int frame) { (void) c; (void) frame; }
int cw_ok(const cw *c, int port) { (void) c; (void) port; return 0; }
void su_draw(su *s) { (void) s; }
ldr_pkg *su_package(su *s) { static ldr_pkg tp; (void) s; tp.pk = data_pkg; return &tp; }

/* ---- the tests ---- */

static int bad, total;
#define CHECK(c, ...) do { total++; if (!(c)) { bad++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static RenderContext rc = {640, 240};
static input_state inp;
static lang_info langs[LANG_MAX];
static int nlang;

static const lang_info *lang_by_id(int id) { for (int i = 0; i < nlang; i++) if (langs[i].id == id) return &langs[i]; return NULL; }

/* move the cursor of a grid (linear index, `cols` cells to a row) from c to t */
static int move_to(int c, int t, int cols, int ncell)
{
	while (t - c >= cols && c + cols < ncell) { press(PAD_DOWN); c += cols; }
	while (c - t >= cols) { press(PAD_UP); c -= cols; }
	while (c < t) { press(PAD_RIGHT); c++; }
	while (c > t) { press(PAD_LEFT); c--; }
	return c;
}

static int txmr;                                                   /* the list the person types: the BIP39 or the Monero one */
static int clen(const uint8_t *s) { return s[0] < 0x80 ? 1 : (s[0] & 0xE0) == 0xC0 ? 2 : 3; }

/* the person types word w (an index) on the kana, jamo or Cyrillic keyboard: enough letters, then the candidate */
static int type_word(int w, int cur)
{
	const words_list *wl = wl_of(txmr);
	uint8_t key[19];
	int tl = 0, total_, pos = -1, found_n, ncell = L.mode == M_KANA ? 84 : L.mode == M_CYR ? 33 : 51, cols = L.mode == M_KANA ? 19 : 17;
	static uint16_t found[2100];

	langin_key(key_mode(), (const char *) (wl->text + wl->off[w]), key, 19);
	for (int chars = 1;; chars++) {                                    /* the shortest start that leaves at most 14 candidates, else the whole word */
		int len = 0, k = 0;
		if (L.mode == M_HANGUL) len = chars;
		else for (; k < chars && key[len]; k++) len += clen(key + len);
		if (len > (int) strlen((const char *) key)) len = (int) strlen((const char *) key);
		tl = len;
		total_ = langin_find(fkeys[txmr], 19, wl->n, key, tl, 0, 0, found);
		if ((total_ <= 14 && chars >= 2) || tl == (int) strlen((const char *) key)) break;
	}
	if (L.mode == M_HANGUL) {
		for (int i = 0; i < tl; i++) { cur = move_to(cur, key[i] - 1, cols, ncell); press(PAD_CROSS); }
	} else {
		for (int i = 0; i < tl; i += clen(key + i)) {
			unsigned cp = clen(key + i) == 2 ? (unsigned) (key[i] & 31) << 6 | (key[i + 1] & 63) : (unsigned) (key[i] & 15) << 12 | (unsigned) (key[i + 1] & 63) << 6 | (key[i + 2] & 63);
			int cell = L.mode == M_KANA ? (cp == 0x30FC ? 83 : (int) cp - 0x3041) : (cp == 0x451 ? 32 : (int) cp - 0x430);
			cur = move_to(cur, cell, cols, ncell);
			press(PAD_CROSS);
		}
	}
	found_n = langin_find(fkeys[txmr], 19, wl->n, key, tl, 0, 2100, found);
	for (int i = 0; i < found_n; i++) if (found[i] == w) pos = i;
	if (pos < 0) { printf("FAIL: the word %d is not among the candidates\n", w); exit(1); }
	for (int i = 0; i < pos; i++) press(PAD_R1);
	press(PAD_SQUARE);
	return cur;
}

static int zh_rank(int w)                                          /* the place of the word in the grid of the characters */
{
	const words_list *wl = wl_of(txmr);
	int rank = 0, c = word_first(wl, w);
	for (int i = 0; i < wl->n; i++) if (word_first(wl, i) < c) rank++;
	return rank;
}

/* the words of the entropy / key, and for BIP39 the sentence that goes into the seed */
static int make_words(const uint8_t *ent, int elen, uint16_t *idx, char *want, size_t cap)
{
	int n;
	if (txmr) { n = lang_xmr_indexes(&L.xmr, L.prefix, ent, idx); want[0] = 0; return n; }
	n = lang_bip39_indexes(ent, (size_t) elen, idx);
	langin_sentence(&L.bip, idx, n, want, cap);
	return n;
}

/* Where the module writes while it reads a language (memmap.h): the data pocket, the second segment of its slot above its bss, and the scratch pocket for the decoders. Everything else the
 * loader owns - the slot of the signer, the module's own slot below the second segment, the rest of the scratch pocket - stays as it was; and the data lie in the segments. */
static void mem_case(int lid, int spills)
{
	const lang_info *li = lang_by_id(lid);
	volatile uint8_t *lo = (volatile uint8_t *) (uintptr_t) MM_P0_LO, *hi = (volatile uint8_t *) (uintptr_t) MM_LANG_HI;
	uintptr_t top = 0;
	long touched = 0;
	int rc;

	for (volatile uint8_t *q = lo; q < hi; q++) *q = 0xA5;
	rc = li ? load(li) : -1;
	CHECK(rc == 0, "memory case: load language %d (%s)", lid, msg);
	for (volatile uint8_t *q = lo; q < hi; q++) {
		uintptr_t a = (uintptr_t) q;
		int allowed = a < MM_P0_HI || (a >= STAGE && a < STAGE + STAGE_SZ + WORK_SZ) || a >= ARENA1_LO;
		if (!allowed && *q != 0xA5) touched++;
	}
	CHECK(touched == 0, "language %d: %ld bytes were written outside the data pocket, the second segment and the scratch pocket", lid, touched);
	if (rc) return;
	CHECK((uintptr_t) arena <= MM_LANG_HI && (uintptr_t) arena_end <= MM_LANG_HI, "language %d: the arena ends at %p", lid, (void *) arena);
	for (const words_list *wl = &L.bip; wl <= &L.xmr; wl++) {
		uintptr_t a = (uintptr_t) wl->text;
		if (wl->n) {
			CHECK((a >= MM_P0_LO && a < MM_P0_HI) || (a >= ARENA1_LO && a < MM_LANG_HI), "language %d: a word list at %p is outside the data segments", lid, (void *) a);
			if (a > top) top = a;
		}
	}
	if (spills) CHECK(top >= ARENA1_LO, "language %d should have spilled into the second segment, the lists end at %p", lid, (void *) top);
	/* what typing adds: the keys of the lists (or the order of the hanzi); then the whole language has to be inside the two segments */
	for (int x = 0; x < 2; x++) {
		if (!wl_of(x)->n) continue;
		CHECK((L.mode == M_HANZI ? make_order(x) : make_keys(x)) == 0, "language %d: the typing keys of list %d fit the memory", lid, x);
	}
	{
		uint32_t used0 = arena_end == (uint8_t *) (uintptr_t) MM_P0_HI ? (uint32_t) ((uintptr_t) arena - MM_P0_LO) : MM_P0_HI - MM_P0_LO;
		uint32_t used1 = arena_end == (uint8_t *) (uintptr_t) MM_P0_HI ? 0 : (uint32_t) ((uintptr_t) arena - ((ARENA1_LO + 3) & ~(uintptr_t) 3));
		CHECK((uintptr_t) arena <= MM_LANG_HI, "language %d: the arena with the typing keys ends at %p", lid, (void *) arena);
		if (getenv("PSXX_USAGE")) printf("[arena] %d %s %u %u\n", lid, L.name, (unsigned) used0, (unsigned) used1);      /* bytes of the data pocket, bytes above the module (tools/space_report.py) */
	}
	language_off();
	CHECK(!L.loaded && !psxx_lang && arena == (uint8_t *) (uintptr_t) MM_P0_LO && !fkeys[0] && !zord[0], "language_off leaves nothing loaded");
}

/* the word list viewer of a language (its lists, the first and the last page, the test mnemonic) and the list of the languages: drawn for the layout check */
static void view_case(int lid)
{
	const lang_info *li = lang_by_id(lid);

	CHECK(li && load(li) == 0, "view case: load language %d (%s)", lid, msg);
	if (!li || !L.loaded) return;
	for (fam = 0; fam < 2; fam++) {
		const words_list *wl = fam ? &L.xmr : &L.bip;
		if (!wl->n) continue;
		for (vmode = 0; vmode < 2; vmode++)
			for (int p = 0; p < 2; p++) {
				top = p ? (wl->n - 1) / (2 * ROWS) * (2 * ROWS) : 0;
				vtpage = p;                                                  /* the test mnemonic: its second page, if it has one */
				prepare_page();
				draw_view();
				gpu_present(rc_);
			}
	}
	fam = vmode = top = vtpage = 0;
	language_off();
}

static void index_case(void)
{
	for (int m = 0; m < 2; m++) {
		snprintf(msg, sizeof msg, "%s", m ? "The language card was changed: read it again" : "");
		for (sel = 0; sel < nlang; sel++) {
			if (sel < top) top = sel;
			if (sel >= top + 8) top = sel - 7;
			draw_index();
			gpu_present(rc_);
		}
	}
	msg[0] = 0; sel = top = 0;
}

/* the bump allocator: the data pocket first, then the second segment, then nothing */
static void arena_case(void)
{
	uint32_t p0 = MM_P0_HI - MM_P0_LO, s1 = MM_LANG_HI - (uint32_t) ((ARENA1_LO + 3) & ~(uintptr_t) 3);
	uint8_t *a, *b, *c;

	arena_reset();
	a = alloc(p0 - 100);
	CHECK(a == (uint8_t *) (uintptr_t) MM_P0_LO, "the first block is at the start of the data pocket");
	b = alloc(1000);
	CHECK(b == (uint8_t *) ((ARENA1_LO + 3) & ~(uintptr_t) 3), "a block that does not fit the pocket goes to the start of the second segment (%p)", (void *) b);
	c = alloc(s1 - 1000);
	CHECK(c == b + 1000 || c == b + ((1000 + 3) & ~3u), "the next block follows it");
	CHECK(alloc(4) == NULL, "nothing is left: NULL");
	CHECK(!arena_want(1), "no room is no room");
	arena_reset();
	CHECK(arena_want(p0) && alloc(p0) == (uint8_t *) (uintptr_t) MM_P0_LO, "the whole pocket can be had");
	CHECK(alloc(8) != NULL && arena_end == (uint8_t *) (uintptr_t) MM_LANG_HI, "and then the second segment");
	arena_reset();
}

/* the whole mnemonic, typed by the person; mistake: the last word is first a wrong one (a word that breaks the checksum) */
static void restore_case(int lid, const uint8_t *ent, int elen, int mistake, int xmr)
{
	const lang_info *li = lang_by_id(lid);
	uint16_t idx[25];
	uint8_t out[32];
	char sentence[800], want[800];
	int n, cur = 0, r, wrong;

	qn = qi = 0;
	txmr = xmr;
	CHECK(li && load(li) == 0, "load language %d (%s)", lid, msg);
	if (!li || !L.loaded || !wl_of(xmr)->n) return;
	n = make_words(ent, elen, idx, want, sizeof want);
	if (L.mode != M_HANZI && make_keys(xmr)) { CHECK(0, "keys"); return; }
	if (L.mode == M_HANZI) make_order(xmr);
	wrong = idx[n - 1];
	if (mistake) {
		uint16_t bad_idx[25];
		uint8_t tmp[32];
		memcpy(bad_idx, idx, sizeof bad_idx);
		for (wrong = 0; wrong < wl_of(xmr)->n; wrong++) {
			bad_idx[n - 1] = (uint16_t) wrong;
			if (wrong == idx[n - 1]) continue;
			if (xmr ? lang_xmr_decode(wl_of(1), L.prefix, bad_idx, tmp) < 0 : langin_bip39_entropy(bad_idx, n, tmp) < 0) break;
		}
	}
	for (int i = 0; i < n; i++) {
		int w = i == n - 1 ? wrong : idx[i];
		if (L.mode == M_HANZI) { int t_ = zh_rank(w); cur = move_to(cur, t_, 19, wl_of(xmr)->n); press(PAD_CROSS); }
		else cur = type_word(w, cur);
	}
	if (mistake) {                                                    /* the review, accepted: "checksum wrong"; the last word goes, the right one is typed */
		int w = idx[n - 1];
		press(PAD_CROSS);
		if (L.mode == M_HANZI) { int t_ = zh_rank(w); cur = move_to(cur, t_, 19, wl_of(xmr)->n); press(PAD_CROSS); }
		else cur = type_word(w, cur);
	}
	press(PAD_CROSS);                                                 /* accept */
	loaded_n = 0;
	r = api_restore(&rc, &inp, xmr, n, sentence, sizeof sentence, out);
	CHECK(r == (xmr ? 32 : elen) && r > 0 && !memcmp(out, ent, (size_t) r), "language %d, %s: restore gave %d", lid, xmr ? "Monero" : "BIP39", r);
	CHECK(xmr || (r > 0 && !strcmp(sentence, want)), "language %d: the sentence", lid);
	CHECK(qi == qn, "language %d: %d of %d presses were used", lid, qi, qn);
}

static void latin_case(int lid, const uint8_t *ent, int elen, int xmr)
{
	const lang_info *li = lang_by_id(lid);
	uint16_t idx[25];
	uint8_t out[32];
	static char text1[1000], text2[1000], text3[1000], sentence[800], want[800];
	int n, r;
	char sug[KB_SUG][KB_SUGLEN];

	txmr = xmr;
	CHECK(li && load(li) == 0, "load language %d", lid);
	if (!li || !wl_of(xmr)->n) return;
	n = make_words(ent, elen, idx, want, sizeof want);
	make_keys(xmr);
	cwl = wl_of(xmr); cxmr = xmr; ckeys = fkeys[xmr];
	text1[0] = text2[0] = text3[0] = 0;
	for (int i = 0; i < n; i++) {
		char w[40], pre[8];
		uint8_t key[19];
		word_text(cwl, idx[i], w, sizeof w);
		strcat(text1, i ? " " : ""); strcat(text1, w);                 /* the words as the suggestions insert them (with accents) */
		langin_key(LANGIN_LATIN, w, key, 19);
		memcpy(pre, key, 4); pre[4] = 0;                               /* or just the first four letters, without accents */
		strcat(text2, i ? " " : ""); strcat(text2, pre);
		strcat(text3, i ? " " : ""); strcat(text3, i == 3 ? "zzzz" : w);
	}
	{                                                                  /* the suggestions for the first letters of a word */
		uint8_t key[19];
		char w[40];
		int got;
		word_text(cwl, idx[0], w, sizeof w);
		langin_key(LANGIN_LATIN, w, key, 19);
		key[3] = 0;
		got = latin_sugg((const char *) key, 3, 0, sug, KB_SUG);
		CHECK(got >= 1 && sug[0][0], "language %d: suggestions for '%s' (%d)", lid, key, got);
	}
	for (int mode = 0; mode < 3; mode++) {
		kb_next = 0;
		kb_ntext = 0;
		if (mode == 2) kb_texts[kb_ntext++] = text3;                    /* an unknown word first ... */
		kb_texts[kb_ntext++] = mode == 1 ? text2 : text1;
		r = api_restore(&rc, &inp, xmr, n, sentence, sizeof sentence, out);
		CHECK(r == (xmr ? 32 : elen) && r > 0 && !memcmp(out, ent, (size_t) r) && (xmr || !strcmp(sentence, want)), "language %d, %s, text %d: restore gave %d", lid, xmr ? "Monero" : "BIP39", mode, r);
	}
	kb_next = 0; kb_ntext = 0;                                          /* nothing typed, then the user gives up */
	kb_texts[kb_ntext++] = "";
	r = api_restore(&rc, &inp, xmr, n, sentence, sizeof sentence, out);
	CHECK(r == -1, "language %d: nothing typed, then the user gives up (%d)", lid, r);
}

/* the check of the words: a person who answers right, and one who first answers wrong */
static int quiz_mode, quiz_wrong_done, phase_hold;
static uint16_t quiz_driver(uint16_t *held)
{
	if (phase_hold < 90) { phase_hold++; *held = PAD_CIRCLE | PAD_CROSS; return 0; }
	if (Q.fail) { phase_hold = 0; return PAD_CROSS; }                  /* back to the words: hold again */
	if (quiz_mode == 1 && !quiz_wrong_done) {
		if (Q.sel == Q.correct) return PAD_DOWN;
		quiz_wrong_done = 1;
		return PAD_CROSS;
	}
	if (Q.sel != Q.correct) return PAD_DOWN;
	return PAD_CROSS;
}
static void show_case(int lid, int xmr, int mode)
{
	const lang_info *li = lang_by_id(lid);
	uint8_t ent[32];
	char sentence[800], english[400];
	int r, n;

	CHECK(li && load(li) == 0, "load language %d", lid);
	if (!li) return;
	for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (i * 7 + lid);
	if (xmr) {
		uint8_t spend[32];
		memcpy(spend, ent, 32);
		spend[31] &= 0x0F;
		xmr_seed_encode(spend, english, sizeof english);
		CHECK(api_monero(english) == (L.xmr.n ? 0 : -1), "language %d: Monero words", lid);
		n = kept[1].n;
	} else {
		n = api_mnemonic(ent, 16, sentence, sizeof sentence);
		CHECK(n == (L.bip.n ? 12 : -1), "language %d: mnemonic (%d)", lid, n);
	}
	CHECK(n > 0 || (xmr ? !L.xmr.n : !L.bip.n), "language %d: words kept", lid);
	quiz_mode = mode;
	quiz_wrong_done = 0;
	phase_hold = 0;
	if (n > 0) {
		dyn = quiz_driver;
		if (mode == 2) {                                              /* the Monero key is to be saved: the square button */
			dyn = NULL; qn = qi = 0; press(PAD_SQUARE);
		}
		loaded_n = 0;
		r = api_show(&rc, &inp, xmr, "- test");
		dyn = NULL;
		CHECK(r == (mode == 2 ? 1 : 0), "language %d: show returned %d", lid, r);
		if (mode != 2) CHECK(kept[xmr].n == 0, "language %d: the words are forgotten after the check", lid);
		else api_wipe();
	} else {
		r = api_show(&rc, &inp, xmr, NULL);
		CHECK(r == -2, "language %d: nothing kept: -2 (%d)", lid, r);
	}
}

/* 24 of the longest Japanese words: two columns of 6 words on a page, two pages; the person turns the page, holds the buttons and answers */
static int long_first;
static uint16_t long_driver(uint16_t *held)
{
	if (long_first) { long_first = 0; return PAD_RIGHT; }
	return quiz_driver(held);
}

static void long_case(void)
{
	const lang_info *li = lang_by_id(1);
	int cols, per, pages, r, n = 0, best[24];

	CHECK(li && load(li) == 0, "load Japanese");
	if (!li || !L.loaded) return;
	for (int i = 0; i < 24; i++) best[i] = -1;
	for (int i = 0; i < L.bip.n; i++) {                              /* the 24 longest */
		int len = L.bip.off[i + 1] - L.bip.off[i], slot = -1;
		for (int k = 0; k < 24; k++) { if (best[k] < 0 || len > L.bip.off[best[k] + 1] - L.bip.off[best[k]]) { slot = k; break; } }
		if (slot >= 0) { for (int k = 23; k > slot; k--) best[k] = best[k - 1]; best[slot] = i; }
	}
	for (int i = 0; i < 24; i++) kept[0].idx[n++] = (uint16_t) best[i];
	kept[0].n = n;
	pages = page_layout(&L.bip, kept[0].idx, n, &cols, &per);
	CHECK(cols == 2 && per == 12 && pages == 2, "long Japanese words: %d columns, %d per page, %d pages", cols, per, pages);
	quiz_mode = 0; quiz_wrong_done = 0; phase_hold = 0; long_first = 1;
	dyn = long_driver;
	r = api_show(&rc, &inp, 0, NULL);
	dyn = NULL;
	CHECK(r == 0 && kept[0].n == 0, "long Japanese words: show returned %d", r);
}

int main(int argc, char **argv)
{
	FILE *f;
	char js[4000], *q;
	uint8_t pin[32];
	uint32_t raw;
	int detail;
	static uint8_t ibuf[1000];

	ui_reg_a();
	ui_reg_l();
#ifndef _WIN32
	printf("language module test: Windows only, skipped\n");
	return 0;
#else
	if (argc < 3 || !(f = fopen(argv[1], "rb"))) { printf("language module test: no package, skipped\n"); return 0; }
	lc_ext_width = ext_width;
	file_size = fread(file_buf, 1, sizeof file_buf, f);
	fclose(f);
	{
		FILE *jf = fopen(argv[2], "r");
		size_t jn = jf ? fread(js, 1, sizeof js - 1, jf) : 0;
		if (jf) fclose(jf);
		js[jn] = 0;
		q = strstr(js, "\"key\": \"");
		if (!q) { printf("no pin\n"); return 1; }
		for (int i = 0; i < 32; i++) { unsigned v; sscanf(q + 8 + 2 * i, "%2x", &v); pin[i] = (uint8_t) v; }
	}
	if (!VirtualAlloc((void *) (uintptr_t) 0x80000000u, 0x200000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) { printf("language module test: no memory at the console address, skipped\n"); return 0; }
	if (pkg_open(&data_pkg, mem_read, NULL, (uint32_t) file_size, PKG_KIND_DATA, pin)) { printf("FAIL: package\n"); return 1; }
	if (ovl_unpack_group(&data_pkg, LANG_ID_INDEX, ibuf, sizeof ibuf, ostage, sizeof ostage, oprobs, &raw, &detail)) { printf("FAIL: index\n"); return 1; }
	nlang = lang_index(ibuf, raw, langs, LANG_MAX);
	setvbuf(stdout, NULL, _IONBF, 0);
	rc.yres = 240;
	rc_ = &rc;
	in_ = &inp;

	for (int i = 0; i < data_pkg.ngroups; i++) {                       /* the work area of the module holds the decoder of every list */
		uint16_t gid = data_pkg.g[i].id;
		static uint8_t blob[20000];
		uint32_t br, at = 0;
		if ((gid >> 8) != 2 && (gid >> 8) != 3 && (gid >> 8) != 5) continue;
		if (ovl_unpack_group(&data_pkg, gid, blob, sizeof blob, ostage, sizeof ostage, oprobs, &br, &detail)) continue;
		if ((gid >> 8) == 5) { at = 2 + (uint32_t) (blob[0] | blob[1] << 8); if (br <= at) continue; }   /* a Monero list from the BIP39 one: the blob of its own words after the mask */
		CHECK(wl_work_size(blob + at, br - at) <= WORK_SZ && wl_work_size(blob + at, br - at), "list %04x needs a work area of %u bytes, the module has %u", gid,
		      (unsigned) wl_work_size(blob + at, br - at), (unsigned) WORK_SZ);
	}
	{
		uint8_t e16[16], e32[32];
		for (int i = 0; i < 16; i++) e16[i] = (uint8_t) (i * 11 + 3);
		for (int i = 0; i < 32; i++) e32[i] = (uint8_t) (i * 37 + 11);
		for (int mistake = 0; mistake < 2; mistake++) {
			restore_case(1, e16, 16, mistake, 0);                       /* Japanese */
			restore_case(2, e16, 16, mistake, 0);                       /* Korean */
			restore_case(8, e16, 16, mistake, 0);                       /* Chinese, simplified */
			restore_case(9, e16, 16, mistake, 0);                       /* Chinese, traditional */
			restore_case(1, e32, 32, mistake, 1);                       /* the Monero lists: Japanese, Chinese, Russian */
			restore_case(8, e32, 32, mistake, 1);
			restore_case(12, e32, 32, mistake, 1);
		}
		restore_case(1, e32, 32, 0, 0);
		restore_case(2, e32, 32, 0, 0);
		restore_case(8, e32, 32, 0, 0);
		for (int lid = 3; lid <= 7; lid++) { latin_case(lid, e16, 16, 0); latin_case(lid, e32, 32, 0); }
		for (int lid = 3; lid <= 11; lid++) { if (lid == 6 || lid == 8 || lid == 9) continue; latin_case(lid, e32, 32, 1); }    /* es fr it pt nl de */
		latin_case(13, e32, 32, 1); latin_case(14, e32, 32, 1);                                                    /* Esperanto, Lojban (the apostrophe is not typed) */
		show_case(1, 0, 0); show_case(1, 0, 1); show_case(2, 0, 0); show_case(3, 0, 0); show_case(8, 0, 1); show_case(9, 0, 0);
		show_case(1, 1, 0); show_case(8, 1, 0); show_case(3, 1, 2); show_case(12, 1, 0); show_case(2, 1, 0);   /* Korean has no Monero list: -2 */
		long_case();
		show_case(10, 0, 0);                                                                                     /* Dutch has no BIP39 list */
		for (int lid = 1; lid <= 14; lid++) mem_case(lid, 0);
		for (int lid = 1; lid <= 14; lid++) view_case(lid);
		index_case();
		arena_case();
	}
	CHECK(missing_glyphs == 0, "%d characters were drawn without their glyph", missing_glyphs);
	CHECK(lc_bad == 0, "%d layout problems in %d frames (tests/layout_check.h)", lc_bad, lc_frames);
	printf("language module: %d checks, %d bad, %ld frames, %d of them laid out\n", total, bad, frames, lc_frames);
	return bad != 0;
#endif
}
