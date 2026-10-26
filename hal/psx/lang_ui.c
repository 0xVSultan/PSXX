#include "lang_ui.h"
#include <stdio.h>
#include "ui.h"
#include <string.h>
#include <psxgpu.h>
#include "font.h"
#include "fontext.h"
#include "loader.h"
#include "release.h"
#include "source_ui.h"
#include "lang/lang.h"
#include "wordlist/wl.h"
#include "coin/words.h"
#include "coin/xmr_seed.h"
#include "hash/sha256.h"
#include "lang/nfkd.h"
#include "lang/langin.h"
#include "keyboard.h"
#include "lang_api.h"
#include "util.h"

#define DATA_PKG "BESCES-00000PSXXPK02"
#define STAGE_SZ 0xA000u                                      /* the packed bytes of a group (hanzi: 40 KB), and a stored group as it is */
#define WORK_SZ 0x16000u                                      /* the work area of the word list decoder (the Japanese list needs 87 930 bytes) */
#define STAGE LDR_SCRATCH_LO                                  /* the decoders work in the scratch pocket (memmap.h): the packed bytes, then the work area above them */
#define WORK (STAGE + STAGE_SZ)
_Static_assert(STAGE_SZ + WORK_SZ <= LDR_SCRATCH_HI - LDR_SCRATCH_LO, "the work areas of the decoders do not fit the scratch pocket");
#define LINE 20
#define ROWS 8                                                /* rows of two columns on a page of the list (18 pixels apart: above the first line of hints) */

enum { P_SRC, P_INDEX, P_LOAD, P_VIEW, P_MSG, P_CONFIRM };
enum { M_LATIN, M_KANA, M_HANGUL, M_HANZI, M_CYR };                    /* how the words of a language are typed (L.mode) */

static su            sui;
static RenderContext *rc_;
static input_state   *in_;
static lang_info     langs[LANG_MAX];
static int           nlang, phase, sel, top, fam, vmode, dirty;
static char          msg[64];
static char          c_dg[9];                                 /* the digest (first 4 bytes, hex) of the signed header and table of the data package that the index was read from: "" when none */
static int           chk;                                     /* the card is looked at first (the module was entered again): the list if it is the same package, else it is read again */
static uint8_t       *fkeys[2];                               /* the keys of the words of the BIP39 [0] and the Monero [1] list (langin.h), made when the first word is typed */
static uint16_t      *zord[2];                                /* hanzi: the words in the order of their characters */
static uint8_t       *arena, *arena_end;                      /* the bump allocator of what stays loaded (the language that is on): the data pocket first, then what is left of the module's slot above its bss */
#ifndef ARENA1_LO                                                     /* (the host test puts the second segment where its module would end) */
extern char          __ovl_bss_end[];                         /* ovl_lang.ld */
#define ARENA1_LO ((uintptr_t) __ovl_bss_end)
#endif

static struct {
	int         loaded, id, prefix, sep, mode;
	uint8_t     *ui[UI_RANGES];                               /* the tables of the UI texts of the language (ui_text.h), one per range, if the language has them */
	uint32_t    uilen[UI_RANGES];
	words_list  bip, xmr;                                     /* n == 0: the language has no such list */
	glyphset    gs;
	int         have_gs;
	char        name[17];
} L;

static void t(int x, int y, const char *s, int r, int g, int b) { font_draw(rc_, 0, x, y, s, r, g, b); }

static int word_first(const words_list *wl, int i)                      /* the first character of word i of a list */
{
	const unsigned char *s = (const unsigned char *) wl->text + wl->off[i];
	return s[0] < 0x80 ? s[0] : (s[0] & 0xF0) == 0xE0 ? (s[0] & 15) << 12 | (s[1] & 63) << 6 | (s[2] & 63) : (s[0] & 31) << 6 | (s[1] & 63);
}

static void arena_reset(void) { arena = (uint8_t *) MM_P0_LO; arena_end = (uint8_t *) MM_P0_HI; }

/* room for n contiguous bytes at `arena`: in the segment it is in, else (once) at the start of the second one; 0 when there is no such room */
static int arena_want(uint32_t n)
{
	if ((uint32_t) (arena_end - arena) >= n) return 1;
	if (arena_end == (uint8_t *) MM_P0_HI) {
		arena = (uint8_t *) ((ARENA1_LO + 3) & ~(uintptr_t) 3);
		arena_end = (uint8_t *) MM_LANG_HI;
		if ((uint32_t) (arena_end - arena) >= n) return 1;
	}
	return 0;
}

static void *alloc(uint32_t n)
{
	void *p;

	n = (n + 3) & ~3u;
	if (!arena_want(n)) return NULL;
	p = arena;
	arena += n;
	return p;
}

/* ---- reading ---- */

static uint32_t pbase, ptotal;                                        /* frames of the groups read so far, frames of all the groups of this loading (0: the bar is that of one group) */

static uint32_t gframes(uint16_t gid)                                 /* the frames the loader reads for a group of the package (ldr_unpack_group) */
{
	const pkg_group *g = pkg_find(&su_package(&sui)->pk, gid);

	return g ? (g->len + CF_FRAME - 1) / CF_FRAME + 1 : 0;
}

static int progress(void *user, uint32_t done, uint32_t total)
{
	int pct = ptotal ? (int) ((pbase + done) * 100u / ptotal) : total ? (int) (done * 100u / total) : 0;
	(void) user;
	if (pct > 100) pct = 100;
	gpu_draw_rect(rc_, 2, 16, 150, GPU_XRES - 32, 12, 30, 30, 50);
	gpu_draw_rect(rc_, 1, 16, 150, (GPU_XRES - 32) * pct / 100, 12, 255, 200, 60);
	t(16, 90, T(TXT_READING_THE_LANGUAGE_CARD), 255, 255, 255);
	t(16, 114, msg, 150, 160, 200);
	gpu_present(rc_);
	input_poll(in_, NULL);
	return (input_take_pressed(in_) & PAD_CIRCLE) != 0;
}

/* a group, unpacked to dst; 0 or a message */
static int rd(uint16_t gid, uint8_t *dst, uint32_t cap, uint32_t *raw)
{
	int detail = 0, r;
	int in_stage = dst == (uint8_t *) STAGE;                            /* a group read into the stage itself (a mapping, a mask, a list) has its packed bytes in the work area */

	ldr_set_progress(progress, NULL);
	r = ldr_unpack_group(su_package(&sui), gid, dst, cap, in_stage ? (uint8_t *) WORK : (uint8_t *) STAGE, in_stage ? WORK_SZ : STAGE_SZ, raw, &detail);
	ldr_set_progress(NULL, NULL);
	if (r) snprintf(msg, sizeof msg, "%s", ldr_cancelled() ? T(TXT_CANCELLED) : ldr_describe(r, detail));
	else pbase += gframes(gid);
	return r;
}

/* the work between two readings (the Chinese lists are made from their groups): the bar stays where it is, the text says what is going on */
static void building(void)
{
	snprintf(msg, sizeof msg, T(TXT_BUILDING_THE_WORD_LISTS));
	progress(NULL, 0, 0);
}

static const uint16_t GIDS[3] = {LANG_ID_HANZI, LANG_ID_HANGUL, LANG_ID_KANA};

/* the frames of all the groups that language li needs (what load() reads) */
static uint32_t plan(const lang_info *li)
{
	uint32_t n = 0;

	for (int b = 0; b < 3; b++) if (li->glyphs & (1 << b)) n += gframes(GIDS[b]);
	if (li->flags & LANG_ONE_CHAR) {
		if (li->bip_group == LANG_ID_ZH_SIMPLIFIED || li->bip_group == LANG_ID_ZH_TRADITIONAL || li->xmr_group == LANG_ID_ZH_XMR) n += gframes(LANG_ID_ZH_SIMPLIFIED);
		if (li->bip_group == LANG_ID_ZH_TRADITIONAL) n += gframes(LANG_ID_ZH_TRADITIONAL);
		if (li->xmr_group == LANG_ID_ZH_XMR) n += gframes(LANG_ID_ZH_XMR);
	} else {
		if (li->bip_group) n += gframes(li->bip_group);
		if (li->xmr_group) n += gframes(li->xmr_group);
	}
	if (li->ui_group) for (int r = 0; r < UI_RANGES; r++) n += gframes((uint16_t) (li->ui_group + 0x100 * r));
	return n;
}

static int nomem(void) { snprintf(msg, sizeof msg, T(TXT_OUT_OF_MEMORY)); return -1; }

static int zh_lists(const lang_info *li)
{
	static uint8_t *stext_p;
	static uint16_t *soff_p;
	uint32_t raw;
	uint8_t *map = (uint8_t *) STAGE;
	char *text;
	uint16_t *off;

	if (!L.have_gs) return -1;
	if (li->bip_group == LANG_ID_ZH_SIMPLIFIED || li->bip_group == LANG_ID_ZH_TRADITIONAL || li->xmr_group == LANG_ID_ZH_XMR) {   /* the simplified list first: the others are made from it */
		snprintf(msg, sizeof msg, T(TXT_SIMPLIFIED_CHINESE));
		if (rd(LANG_ID_ZH_SIMPLIFIED, map, STAGE_SZ, &raw)) return -1;
		text = alloc(8200); off = alloc(2 * 2100);
		if (!text || !off) return nomem();
		building();
		if (lang_zh_simplified(&L.gs, map, raw, text, 8200, off, 2100, (uint16_t *) WORK) != 2048) return -1;
		stext_p = (uint8_t *) text; soff_p = off;
		if (li->bip_group == LANG_ID_ZH_SIMPLIFIED) { L.bip.text = text; L.bip.off = off; L.bip.n = 2048; }
	}
	if (li->bip_group == LANG_ID_ZH_TRADITIONAL) {
		snprintf(msg, sizeof msg, T(TXT_TRADITIONAL_CHINESE));
		if (rd(LANG_ID_ZH_TRADITIONAL, map, STAGE_SZ, &raw)) return -1;
		text = alloc(8200); off = alloc(2 * 2100);
		if (!text || !off) return nomem();
		building();
		if (lang_zh_traditional(&L.gs, (const char *) stext_p, soff_p, map, raw, text, 8200, off, 2100, (uint16_t *) WORK) != 2048) return -1;
		L.bip.text = text; L.bip.off = off; L.bip.n = 2048;
	}
	if (li->xmr_group == LANG_ID_ZH_XMR) {
		int n;
		snprintf(msg, sizeof msg, T(TXT_MONERO_CHINESE));
		if (rd(LANG_ID_ZH_XMR, map, STAGE_SZ, &raw)) return -1;
		text = alloc(8200); off = alloc(2 * 2100);
		if (!text || !off) return nomem();
		building();
		n = lang_zh_monero((const char *) stext_p, soff_p, map, raw, text, 8200, off, 2100);
		if (n < 1) return -1;
		L.xmr.text = text; L.xmr.off = off; L.xmr.n = n;
	}
	return 0;
}

static int blob_list(uint16_t gid, words_list *wl)
{
	uint32_t raw;
	uint16_t *off;
	char *text;
	int n;

	if (rd(gid, (uint8_t *) STAGE, STAGE_SZ, &raw)) return -1;
	if (wl_work_size((uint8_t *) STAGE, raw) > WORK_SZ) { snprintf(msg, sizeof msg, T(TXT_LIST_TOO_BIG)); return -1; }
	off = alloc(2 * 2100);
	if (!off || !arena_want(30000)) return nomem();                       /* the decoder may write up to 30000 bytes of text */
	text = (char *) arena;
	n = wl_decode((uint8_t *) STAGE, raw, (void *) WORK, WORK_SZ, text, 30000, off, 2100);
	if (n <= 0) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
	alloc(off[n]);
	wl->text = text; wl->off = off; wl->n = n;
	return 0;
}

/* the Monero list of a language that keeps some of the words of its BIP39 list: a coded mask over that list (lang.h, LANG_ID_XSUB; u16 length, then the mask); Japanese, Spanish:
 * nothing else, French, Italian: then a blob of the words of its own, and the list is the two merged (wl_merge) */
static int sub_list(uint16_t gid, const words_list *bip, words_list *wl)
{
	uint32_t raw, mlen = ((uint32_t) bip->n + 7) / 8, clen;
	uint8_t *map = (uint8_t *) STAGE, *mask;
	uint16_t *off;
	char *text;
	size_t need;
	int n;

	if (!bip->n) { snprintf(msg, sizeof msg, T(TXT_NO_BIP39_LIST)); return -1; }
	if (rd(gid, map, STAGE_SZ, &raw)) return -1;
	clen = raw >= 2 ? (uint32_t) (map[0] | map[1] << 8) : 0;
	if (raw < 2 + clen) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
	mask = map + ((raw + 3) & ~3u);                                       /* the mask, decoded after the group in the stage */
	wl_mask_decode(map + 2, clen, (unsigned) bip->n, mask);
	if (raw > 2 + clen) {
		const uint8_t *blob = map + 2 + clen;
		uint16_t *ooff = alloc(2 * 2100);
		char *otext;
		int on;
		if (wl_work_size(blob, raw - 2 - clen) > WORK_SZ) { snprintf(msg, sizeof msg, T(TXT_LIST_TOO_BIG)); return -1; }
		if (!ooff || !arena_want(30000)) return nomem();
		otext = (char *) arena;
		on = wl_decode(blob, raw - 2 - clen, (void *) WORK, WORK_SZ, otext, 30000, ooff, 2100);
		if (on <= 0) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
		alloc(ooff[on]);
		need = lang_xmr_subset_size(bip->off, bip->n, mask, mlen) + ooff[on];
		off = alloc(2 * 2100);
		text = alloc((uint32_t) need);
		if (!off || !text) return nomem();
		n = wl_merge(bip->text, bip->off, bip->n, mask, mlen, otext, ooff, on, text, need, off, 2100);
		if (n < 1) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
		wl->text = text; wl->off = off; wl->n = n;
		return 0;
	}
	need = lang_xmr_subset_size(bip->off, bip->n, mask, mlen);
	if (!need) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
	off = alloc(2 * 2100);
	text = alloc((uint32_t) need);
	if (!off || !text) return nomem();
	n = lang_xmr_subset(bip->text, bip->off, bip->n, mask, mlen, text, need, off, 2100);
	if (n < 1) { snprintf(msg, sizeof msg, T(TXT_LIST_DAMAGED)); return -1; }
	wl->text = text; wl->off = off; wl->n = n;
	return 0;
}

/* all that language `li` needs: its glyph set, its lists; 0 or a message in msg */
static int load(const lang_info *li)
{
	uint32_t raw;
	static const uint32_t GMAX[3] = {100000, 24000, 8000};                 /* room the glyph set of each group is read into (hanzi: 93 100 bytes and the code points) */

	arena_reset();
	memset(&L, 0, sizeof L);
	fkeys[0] = fkeys[1] = NULL;
	zord[0] = zord[1] = NULL;
	font_ext_clear();
	pbase = 0;
	ptotal = plan(li);
	for (int b = 0; b < 3; b++) {
		if (!(li->glyphs & (1 << b))) continue;
		snprintf(msg, sizeof msg, T(TXT_GLYPHS));
		if (!arena_want(GMAX[b])) return nomem();
		if (rd(GIDS[b], arena, (uint32_t) (arena_end - arena), &raw)) return -1;
		{
			uint8_t *g = alloc(raw);
			unsigned n = g ? glyphset_count(g, raw) : 0;
			uint16_t *cps = n ? alloc(2 * n) : NULL;
			if (!n || !cps || glyphset_open(&L.gs, g, raw, cps)) { snprintf(msg, sizeof msg, T(TXT_GLYPHS_DAMAGED)); return -1; }
			L.have_gs = 1;
		}
	}
	if (li->flags & LANG_ONE_CHAR) { if (zh_lists(li)) return -1; }
	else {
		if (li->bip_group) { snprintf(msg, sizeof msg, T(TXT_BIP39_WORDS)); if (blob_list(li->bip_group, &L.bip)) return -1; }
		if (li->xmr_group) {
			snprintf(msg, sizeof msg, T(TXT_MONERO_WORDS));
			if ((li->xmr_group >> 8) == (LANG_ID_XSUB >> 8) ? sub_list(li->xmr_group, &L.bip, &L.xmr) : blob_list(li->xmr_group, &L.xmr)) return -1;
		}
	}
	if (li->ui_group) {                                                   /* the texts of the screens in this language: switched on with the language (START) */
		for (int r = 0; r < UI_RANGES; r++) {                             /* the main card's, the signer's, the module's: the groups ui_group, + 0x100, + 0x200 */
			uint32_t raw;
			if (!arena_want(16384)) return nomem();
			snprintf(msg, sizeof msg, T(TXT_TEXTS_OF_THE_SCREENS));
			if (rd((uint16_t) (li->ui_group + 0x100 * r), arena, (uint32_t) (arena_end - arena), &raw)) return -1;
			L.ui[r] = alloc(raw);
			L.uilen[r] = raw;
			if (!L.ui[r]) return nomem();
		}
	}
	L.id = li->id; L.prefix = li->xmr_prefix; L.sep = li->separator;
	L.mode = (li->flags & LANG_ONE_CHAR) ? M_HANZI : (li->glyphs & LANG_GLYPH_KANA) ? M_KANA : (li->glyphs & LANG_GLYPH_HANGUL) ? M_HANGUL : M_LATIN;
	if (L.mode == M_LATIN && (L.bip.n || L.xmr.n) && word_first(L.bip.n ? &L.bip : &L.xmr, 0) >= 0x400) L.mode = M_CYR;      /* Russian */
	memcpy(L.name, li->name, sizeof L.name);
	L.loaded = 1;
	ptotal = 0;
	return 0;
}

/* ---- the screens ---- */

static const words_list *cur(void) { return fam && L.xmr.n ? &L.xmr : L.bip.n ? &L.bip : &L.xmr; }

/* the characters the Latin font lacks in text s, appended to c (n so far) */
static int collect(const char *s, uint16_t *c, int n)
{
	int cp;

	while ((cp = font_utf8_next(&s)) != 0)
		if (cp > 0x24F && n < FONT_EXT_MAX * 2) c[n++] = (uint16_t) cp;
	return n;
}

static void word_text(const words_list *wl, int i, char *out, size_t cap)
{
	size_t l = (size_t) (wl->off[i + 1] - wl->off[i]) - 1;
	if (l >= cap) l = cap - 1;
	memcpy(out, wl->text + wl->off[i], l);
	out[l] = 0;
}

static uint16_t cps[FONT_EXT_MAX * 2], tw[25];                     /* tw: the words of the test mnemonic, cps: the characters of the page */
static int ntw, vtpage;                                             /* vtpage: the page of the test mnemonic (long words: two columns, 12 a page) */
static int page_layout(const words_list *wl, const uint16_t *idx, int n, int *cols, int *per);
static void draw_page(const words_list *wl, const uint16_t *idx, int n, int page, int cols, int per, const char *title, const char *note, const char *hint);

static void prepare_page(void)
{
	const words_list *wl = cur();
	int n = 0;
	char w[40];

	if (vmode) {                                                  /* the test mnemonic: the key 00 01 02 ... */
		uint8_t key[32];
		for (int i = 0; i < 32; i++) key[i] = (uint8_t) i;
		ntw = fam && L.xmr.n ? lang_xmr_indexes(&L.xmr, L.prefix, key, tw) : lang_bip39_indexes(key, 16, tw);
		for (int i = 0; i < ntw; i++) { word_text(wl, tw[i], w, sizeof w); n = collect(w, cps, n); }
	} else {
		for (int i = top; i < top + 2 * ROWS && i < wl->n; i++) { word_text(wl, i, w, sizeof w); n = collect(w, cps, n); }
	}
	if (L.have_gs) font_ext_load(&L.gs, cps, n);
	dirty = 0;
}

static void draw_view(void)
{
	const words_list *wl = cur();
	char line[64], w[40];

	if (!L.bip.n && !L.xmr.n) {                                    /* a language of the screens only: no word list to show */
		t(16, UI_TOP, L.name, 255, 255, 255);
		t(16, 26, T(TXT_ONLY_THE_TEXTS_OF_THE_SCREENS), 255, 255, 255);
		t(16, 26 + LINE, T(TXT_THE_WORDS_OF_SEEDS_STAY_ENGLISH), 255, 255, 255);
		t(16, UI_HINT1, T(TXT_HINT_SWITCH_THE_SCREENS_TO_THIS), 255, 220, 80);
		t(16, UI_HINT2, T(TXT_HINT_BACK), 150, 160, 200);
		return;
	}
	if (vmode) {                                                  /* the test mnemonic as the words of a mnemonic are shown: long words in two columns, in pages */
		int cols, per, pages = page_layout(wl, tw, ntw, &cols, &per);
		snprintf(line, sizeof line, T(TXT_KEY_FORMAT_CHECKSUM_LAST), L.name, fam && L.xmr.n ? T(TXT_MONERO) : T(TXT_BIP39));
		draw_page(wl, tw, ntw, vtpage < pages ? vtpage : 0, cols, per, line, NULL, NULL);
		if (L.bip.n && L.xmr.n) t(16, UI_HINT2, pages > 1 ? T(TXT_HINT_SWITCH_ON_PAGE_LIST_BIP39) : T(TXT_HINT_SWITCH_ON_LIST_BIP39_MONERO), 150, 160, 200);
		else t(16, UI_HINT2, pages > 1 ? T(TXT_HINT_SWITCH_ON_PAGE_LIST) : T(TXT_HINT_SWITCH_ON_LIST), 150, 160, 200);
		return;
	}
	{
		const words_list *ot = wl == &L.xmr ? &L.bip : &L.xmr;
		int pages = (wl->n + 2 * ROWS - 1) / (2 * ROWS);

		if (ot->n) snprintf(line, sizeof line, T(TXT_LIST_N_N_OTHER_LIST_N), L.name, wl == &L.xmr ? T(TXT_MONERO) : T(TXT_BIP39), wl == &L.xmr ? T(TXT_BIP39) : T(TXT_MONERO), ot->n);
		else snprintf(line, sizeof line, T(TXT_LIST_N_N_NO_OTHER_LIST), L.name, wl == &L.xmr ? T(TXT_MONERO) : T(TXT_BIP39));
		t(16, UI_TOP, line, 255, 255, 255);
		snprintf(line, sizeof line, T(TXT_PAGE_N_N), top / (2 * ROWS) + 1, pages);
		t(GPU_XRES - 16 - font_width(line), UI_TOP, line, 150, 160, 200);
	}
	for (int i = top; i < top + 2 * ROWS && i < wl->n; i++) {
		int c = (i - top) / ROWS, r = (i - top) % ROWS;
		word_text(wl, i, w, sizeof w);
		snprintf(line, sizeof line, "%4d", i + 1);
		t(16 + c * 320, 26 + r * 18, line, 150, 160, 200);
		t(16 + c * 320 + 48, 26 + r * 18, w, 255, 255, 255);
	}
	t(16, UI_HINT1, T(TXT_HINT_SWITCH_THIS_LANGUAGE_ON_FOR), 255, 220, 80);
	t(16, UI_HINT2, L.bip.n && L.xmr.n ? T(TXT_HINT_PAGE_LIST_TEST_BIP39_MONERO) : T(TXT_HINT_PAGE_LIST_TEST_ONE_LIST), 150, 160, 200);
}

static void draw_index(void)
{
	char line[64];

	t(16, UI_TOP, T(TXT_LANGUAGES_ON_THE_CARD), 255, 255, 255);
	for (int i = 0, e = top; i < 8 && e < nlang; i++, e++) {
		snprintf(line, sizeof line, "%c %s%s", e == sel ? '>' : ' ', langs[e].name, (psxx_lang || (!L.bip.n && !L.xmr.n && ui_lang_get() == UI_LANG_EXT)) && L.loaded && langs[e].id == L.id ? "   (on)" : L.loaded && langs[e].id == L.id ? T(TXT_LOADED) : "");
		t(16, 26 + i * LINE, line, e == sel ? 255 : 255, e == sel ? 220 : 255, e == sel ? 80 : 255);
		{
			int b = langs[e].flags & LANG_BIP39, m = langs[e].flags & LANG_XMR;
			const char *tag = b && m ? T(TXT_TAG_BIP39_AND_MONERO) : m ? T(TXT_TAG_MONERO_ONLY) : b ? T(TXT_TAG_BIP39_ONLY) : T(TXT_TAG_SCREEN_TEXTS_ONLY);

			t(GPU_XRES - 16 - font_width(tag), 26 + i * LINE, tag, b && m ? 150 : 255, b && m ? 160 : 190, b && m ? 200 : 100);          /* a language with one list only is marked in colour */
		}
	}
	if (msg[0]) t(16, UI_MSG, msg, 255, 160, 80);
	t(16, UI_HINT2, T(TXT_HINT_CHOOSE_READ_OFF_OTHER_CARD), 150, 160, 200);
}

/* ---- the words of a mnemonic, on the screen and typed (the lang_api of lang_api.h) ---- */

#define HOLD_FRAMES 75                                                /* as in the generator */
#define VQ 4                                                          /* words asked in the check */
#define VOPTS 5                                                       /* choices per question */
#define BOTH (PAD_CIRCLE | PAD_CROSS)

static struct { uint16_t idx[25]; int n; } kept[2];                   /* the word indexes of the last mnemonic() [0] and monero() [1] */
static const words_list *wl_of(int xmr) { return xmr ? &L.xmr : &L.bip; }

static void bar(int x, int y, int w, int h, uint32_t v, uint32_t max)
{
	gpu_draw_rect(rc_, 3, x - 2, y - 2, w + 4, h + 4, 200, 200, 200);
	gpu_draw_rect(rc_, 2, x, y, w, h, 30, 30, 50);
	if (v) gpu_draw_rect(rc_, 1, x, y, (int) ((uint32_t) w * (v > max ? max : v) / max), h, 220, 160, 60);
}

static int utf8_len(const char *s)
{
	int n = 0;
	for (; *s; s++) if ((*s & 0xC0) != 0x80) n++;
	return n;
}

/* the glyphs of the words idx[0 .. n) of list wl, plus the characters of `extra` (cells of a keyboard), into VRAM */
static void load_words(const words_list *wl, const uint16_t *idx, int n, const uint16_t *extra, int nextra)
{
	int m = 0;
	char w[40];

	for (int i = 0; i < n; i++) { word_text(wl, idx[i], w, sizeof w); m = collect(w, cps, m); }
	for (int i = 0; i < nextra && m < FONT_EXT_MAX * 2; i++) cps[m++] = extra[i];
	if (L.have_gs) font_ext_load(&L.gs, cps, m);
}

static int api_mnemonic(const uint8_t *ent, int len, char *sentence, size_t cap)
{
	int n;

	kept[0].n = 0;
	if (!L.loaded || !L.bip.n) return -1;
	n = lang_bip39_indexes(ent, (size_t) len, kept[0].idx);
	if (n < 1 || langin_sentence(&L.bip, kept[0].idx, n, sentence, cap) < 0) return -1;
	kept[0].n = n;
	return n;
}

static int api_monero(const char *english)
{
	uint8_t key[32];
	int n;

	kept[1].n = 0;
	if (!L.loaded || !L.xmr.n || xmr_seed_decode(english, key)) return -1;
	n = lang_xmr_indexes(&L.xmr, L.prefix, key, kept[1].idx);
	secure_zero(key, sizeof key);
	if (n < 1) return -1;
	kept[1].n = n;
	return 0;
}

static void api_wipe(void) { secure_zero(kept, sizeof kept); }

/* one page of words: 3 columns of up to 25 words, or, when the words are too wide for that (long Japanese words), 2 columns of 6 */
static int page_layout(const words_list *wl, const uint16_t *idx, int n, int *cols, int *per)
{
	int maxw = 0;
	char w[40];

	for (int i = 0; i < n; i++) {
		int cw;
		word_text(wl, idx[i], w, sizeof w);
		cw = utf8_len(w) * (L.have_gs ? 32 : 10);
		if (cw > maxw) maxw = cw;
	}
	*cols = 3 * (28 + maxw) <= GPU_XRES - 64 ? 3 : 2;
	*per = *cols == 3 ? 25 : 12;
	return (n + *per - 1) / *per;
}

static void draw_page(const words_list *wl, const uint16_t *idx, int n, int page, int cols, int per, const char *title, const char *note, const char *hint)
{
	int rows = (per + cols - 1) / cols, pitch = (GPU_XRES - 32) / cols;
	char w[40], line[16];

	t(16, UI_TOP + 2, title, 255, 255, 255);                              /* the icons of the hint reach 2 pixels higher */
	if (note) t(16 + 17 * 10, UI_TOP + 2, note, 150, 160, 200);
	if (hint) t(GPU_XRES - 16 - font_width(hint), UI_TOP + 2, hint, 150, 160, 200);
	for (int i = page * per; i < n && i < (page + 1) * per; i++) {
		int k = i - page * per, x = 16 + (k / rows) * pitch, y = 26 + (k % rows) * 19;           /* 9 rows: 26 .. 196, above the icons of the hint */
		word_text(wl, idx[i], w, sizeof w);
		snprintf(line, sizeof line, "%2d", i + 1);
		t(x, y, line, 150, 160, 200);
		t(x + 28, y, w, 255, 255, 255);
	}
}

/* the check: VQ questions, each asks for a word by its position; the choices are the word and its neighbours in the list (similar spelling), so the paper has to be read carefully */
static struct { int pos[VQ], q, fail, why, sel, correct, att; uint16_t opt[VOPTS]; } Q;

static void quiz_start(int xmr)
{
	sha256_ctx c;
	uint8_t h[32], a = (uint8_t) Q.att, b[2];
	int cnt = 0, n = kept[xmr].n;

	sha256_init(&c);
	sha256_update(&c, (const uint8_t *) "psx-verify", 10);
	sha256_update(&c, &a, 1);
	for (int i = 0; i < n; i++) { b[0] = (uint8_t) kept[xmr].idx[i]; b[1] = (uint8_t) (kept[xmr].idx[i] >> 8); sha256_update(&c, b, 2); }
	sha256_final(&c, h);
	for (int i = 0; i < 32 && cnt < VQ; i++) {
		int p = h[i] % n, dup = 0;
		for (int j = 0; j < cnt; j++) if (Q.pos[j] == p) dup = 1;
		if (!dup) Q.pos[cnt++] = p;
	}
	for (int i = 0; i < VQ; i++)                                      /* ascending order: easy to follow on the paper */
		for (int j = i + 1; j < VQ; j++)
			if (Q.pos[j] < Q.pos[i]) { int x = Q.pos[i]; Q.pos[i] = Q.pos[j]; Q.pos[j] = x; }
	secure_zero(h, sizeof h);
	Q.q = Q.fail = 0;
}

static void quiz_question(int xmr)
{
	const words_list *wl = wl_of(xmr);
	int idx = kept[xmr].idx[Q.pos[Q.q]], start = idx - 2, rot = (Q.pos[Q.q] * 7 + Q.q * 3 + Q.att) % VOPTS;

	if (start < 0) start = 0;
	if (start > wl->n - VOPTS) start = wl->n - VOPTS;
	Q.correct = 0;
	for (int j = 0; j < VOPTS; j++) {
		int cand = start + (j + rot) % VOPTS;
		Q.opt[j] = (uint16_t) cand;
		if (cand == idx) Q.correct = j;
	}
	Q.sel = 0;
	load_words(wl, Q.opt, VOPTS, NULL, 0);
}

static void quiz_draw(int xmr)
{
	const words_list *wl = wl_of(xmr);
	char line[64], w[40];

	if (Q.fail) {
		t(16, UI_TOP, T(TXT_MISMATCH), 255, 100, 100);
		t(16, 40, T(TXT_THE_PAPER_MUST_BE_EXACTLY_THE), 255, 255, 255);
		t(16, 40 + LINE, T(TXT_WORDS_SHOWN_ON_THE_SCREEN), 255, 255, 255);
		t(16, 40 + 3 * LINE, T(TXT_FIX_YOUR_NOTES_THEN_CHECK), 255, 255, 255);
		t(16, UI_HINT2, T(TXT_HINT_BACK_TO_THE_WORDS), 150, 160, 200);
		return;
	}
	snprintf(line, sizeof line, T(TXT_CHECK_N), Q.q + 1, VQ);
	t(16, UI_TOP, line, 255, 255, 255);
	snprintf(line, sizeof line, T(TXT_WHICH_IS_WORD_N_ON_YOUR_PAPER), Q.pos[Q.q] + 1);
	t(16, 28, line, 255, 220, 80);
	for (int i = 0; i < VOPTS; i++) {
		word_text(wl, Q.opt[i], w, sizeof w);
		snprintf(line, sizeof line, "%c %s", i == Q.sel ? '>' : ' ', w);
		t(40, 62 + i * LINE, line, 255, i == Q.sel ? 220 : 255, i == Q.sel ? 80 : 255);
	}
	t(16, UI_HINT1, T(TXT_HINT_CHOOSE_SELECT_2), 150, 160, 200);
	t(16, UI_HINT2, T(TXT_HINT_NONE_MATCH_SEE_WORDS), 150, 160, 200);
}

static int api_show(RenderContext *ctx, input_state *in, int xmr, const char *note)
{
	const words_list *wl = wl_of(xmr);
	const uint16_t *idx = kept[xmr].idx;
	int n = kept[xmr].n, last = -1, page = 0, hold = 0, dirty = 1, quiz = 0, cols, per, pages;

	rc_ = ctx;
	in_ = in;
	if (!L.loaded || !n) return -2;
	pages = page_layout(wl, idx, n, &cols, &per);
	Q.att = 0;
	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(in, NULL);
		pr = input_take_pressed(in);
		if (!quiz) {
			if ((pr & PAD_SQUARE) && xmr) { font_ext_clear(); return 1; }          /* the Monero key is forgotten once the words are confirmed: the time to save it */
			if ((pr & PAD_RIGHT) && page < pages - 1) { page++; hold = 0; dirty = 1; }
			if ((pr & PAD_LEFT) && page > 0) { page--; hold = 0; dirty = 1; }
			hold = (page == pages - 1 && (in->ps.buttons & BOTH) == BOTH) ? hold + 1 : 0;
			if (hold >= HOLD_FRAMES) { hold = 0; quiz = 1; quiz_start(xmr); quiz_question(xmr); continue; }
			if (dirty) { load_words(wl, idx + page * per, n - page * per < per ? n - page * per : per, NULL, 0); dirty = 0; }
			draw_page(wl, idx, n, page, cols, per, xmr ? T(TXT_MONERO_WORDS) : T(TXT_BIP39_WORDS), note, xmr ? T(TXT_HINT_SAVE_THE_KEY_TO_THE_CARD) : NULL);
			{
				const char *const HINT = T(TXT_HINT_HOLD_TO_CHECK), *const PG = T(TXT_HINT_PAGE);
				int bx = 16 + font_width(HINT) + 16, ex = pages > 1 ? GPU_XRES - 16 - font_width(PG) - 12 : GPU_XRES - 16;

				t(16, UI_HINT2, HINT, 150, 160, 200);
				if (pages > 1) t(GPU_XRES - 16 - font_width(PG), UI_HINT2, PG, 150, 160, 200);
				if (hold) bar(bx, UI_HINT2 + 6, ex - bx, 6, (uint32_t) hold, HOLD_FRAMES);
			}
		} else {
			if (Q.fail) {
				if (pr & PAD_CROSS) { Q.att++; Q.fail = 0; hold = 0; quiz = 0; dirty = 1; continue; }
			} else {
				if (pr & PAD_DOWN) Q.sel = (Q.sel + 1) % VOPTS;
				if (pr & PAD_UP) Q.sel = (Q.sel + VOPTS - 1) % VOPTS;
				if (pr & PAD_SQUARE) { Q.att++; hold = 0; quiz = 0; dirty = 1; continue; }
				if (pr & PAD_TRIANGLE) { Q.fail = 1; Q.why = 2; }
				if (pr & PAD_CROSS) {
					if (Q.sel != Q.correct) { Q.fail = 1; Q.why = 1; }
					else if (++Q.q >= VQ) { secure_zero(&kept[xmr], sizeof kept[xmr]); font_ext_clear(); return 0; }
					else quiz_question(xmr);
				}
			}
			quiz_draw(xmr);
		}
		gpu_present(ctx);
	}
}

/* ---- typing a mnemonic (BIP39: 12 .. 24 words of the BIP39 list; Monero: 25 words of the Monero list) ---- */

static int key_mode(void) { return L.mode == M_LATIN ? LANGIN_LATIN : L.mode == M_HANGUL ? LANGIN_HANGUL : LANGIN_KANA; }   /* kana and Cyrillic: the first characters as they are */

static const words_list *cwl;                                         /* the list that is typed, its keys, the order of the Chinese grid, which kind */
static uint8_t          *ckeys;
static uint16_t         *cord;
static int               cxmr;

/* the entropy (BIP39) or the key (Monero) of the indexes, and for BIP39 the sentence that goes into the seed; the length, or -1 if the checksum does not fit */
static int finish(const uint16_t *idx, int n, char *sentence, size_t cap, uint8_t ent[32])
{
	int el;

	if (cxmr) {
		if (n != 25 || lang_xmr_decode(cwl, L.prefix, idx, ent)) return -1;
		if (cap) sentence[0] = 0;
		return 32;
	}
	el = langin_bip39_entropy(idx, n, ent);
	if (el < 0) return -1;
	if (langin_sentence(cwl, idx, n, sentence, cap) < 0) { secure_zero(ent, 32); return -1; }
	return el;
}

static int make_keys(int xmr)
{
	const words_list *wl = wl_of(xmr);

	if (fkeys[xmr]) return 0;
	fkeys[xmr] = alloc((uint32_t) wl->n * 19);
	if (!fkeys[xmr]) return -1;
	for (int i = 0; i < wl->n; i++) {
		char w[40];
		word_text(wl, i, w, sizeof w);
		langin_key(key_mode(), w, fkeys[xmr] + i * 19, 19);
	}
	return 0;
}

/* Latin scripts: the keyboard of the generator with the suggestions of this list (the first letters of a word, accents are not needed) */

static kb_state kbs;
static char     kmsg[56];
static int      klen;

static int latin_sugg(const char *pre, int len, int from, char out[][KB_SUGLEN], int max)
{
	uint8_t key[19];
	uint16_t found[KB_SUG];
	char w[40];
	int total, kl;

	(void) len;
	langin_key(LANGIN_LATIN, pre, key, sizeof key);
	kl = (int) strlen((const char *) key);
	if (kl < 1) return 0;
	total = langin_find(ckeys, 19, cwl->n, key, kl, from, max > KB_SUG ? KB_SUG : max, found);
	for (int i = 0; i < total - from && i < max && i < KB_SUG; i++) { word_text(cwl, found[i], w, sizeof w); snprintf(out[i], KB_SUGLEN, "%.*s", KB_SUGLEN - 1, w); }
	return total;
}

/* the typed words -> indexes; 0, or -1 with kmsg */
static int latin_parse(int n, uint16_t *idx)
{
	const char *p = kbs.text;
	int k = 0;

	while (*p) {
		char tok[24];
		uint8_t key[19];
		uint16_t found[4];
		int l = 0, total, kl;

		while (*p == ' ') p++;
		if (!*p) break;
		while (*p && *p != ' ') { if (l < 23) tok[l++] = *p; p++; }
		tok[l] = 0;
		k++;
		langin_key(LANGIN_LATIN, tok, key, sizeof key);
		kl = (int) strlen((const char *) key);
		total = kl ? langin_find(ckeys, 19, cwl->n, key, kl, 0, 4, found) : 0;
		if (total > 1)                                                    /* a word that is the beginning of another one: the whole word wins */
			for (int j = 0; j < total && j < 4; j++) if (!memcmp(ckeys + found[j] * 19, key, 19)) { found[0] = found[j]; total = 1; break; }
		if (total != 1 || k > n) { snprintf(kmsg, sizeof kmsg, total ? T(TXT_WORD_N_TYPE_MORE_LETTERS) : T(TXT_WORD_N_IS_NOT_IN_THE_LIST), k); return -1; }
		idx[k - 1] = found[0];
	}
	if (k != n) { snprintf(kmsg, sizeof kmsg, T(TXT_N_WORDS_TYPED_N_CHOSEN), k, n); return -1; }
	return 0;
}

static int restore_latin(int n, char *sentence, size_t cap, uint8_t ent[32])
{
	uint16_t idx[25];
	int last = -1;

	kmsg[0] = 0;
	kb_init(&kbs, cxmr ? T(TXT_MONERO_WORDS) : T(TXT_RECOVERY_WORDS), NULL, 0, 0);
	kb_set(&kbs, cxmr ? 480 : 300, 0);
	kb_set_suggest(&kbs, latin_sugg);
	kbs.goal = n;
	klen = -1;
	for (;;) {
		int f = VSync(-1), r;
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(in_, NULL);
		pr = input_take_pressed(in_);
		kbs.held = in_->ps.buttons;
		r = kb_update(&kbs, pr);
		if (r == KB_CANCEL) { kb_wipe(&kbs); return -1; }
		if (r == KB_DONE) {
			if (latin_parse(n, idx) == 0) {
				int el = finish(idx, n, sentence, cap, ent);
				if (el > 0) { kb_wipe(&kbs); secure_zero(idx, sizeof idx); return el; }
				snprintf(kmsg, sizeof kmsg, cxmr ? T(TXT_CHECKSUM_WRONG_A_WORD_IS) : T(TXT_CHECKSUM_WRONG_A_WORD_IS));
			}
			klen = kbs.len;
		}
		if (klen != kbs.len) kmsg[0] = 0;                                 /* the message belongs to the text it was shown for */
		kbs.note = kmsg[0] ? kmsg : NULL;
		kbs.warn = 2;
		kb_draw(rc_, &kbs);
		gpu_present(rc_);
	}
}

/* Kana, jamo, Cyrillic and hanzi: a grid of the characters; the first three narrow the list of words (the candidates) as they are typed, a hanzi is a whole word */

#define GRID_X 16
#define GRID_Y 106
#define CELL 32

static uint16_t gcell[96];

static int cell_utf8(unsigned cp, char *o)
{
	if (cp < 0x800) { o[0] = (char) (0xC0 | cp >> 6); o[1] = (char) (0x80 | (cp & 63)); o[2] = 0; return 2; }
	o[0] = (char) (0xE0 | cp >> 12); o[1] = (char) (0x80 | ((cp >> 6) & 63)); o[2] = (char) (0x80 | (cp & 63)); o[3] = 0;
	return 3;
}

static int make_order(int xmr)
{
	static const int GAP[8] = {701, 301, 132, 57, 23, 10, 4, 1};
	const words_list *wl = wl_of(xmr);
	uint16_t *o;

	if (zord[xmr]) return 0;
	o = zord[xmr] = alloc(2 * (uint32_t) wl->n);
	if (!o) return -1;
	for (int i = 0; i < wl->n; i++) o[i] = (uint16_t) i;
	for (int g = 0; g < 8; g++)
		for (int i = GAP[g]; i < wl->n; i++) {
			uint16_t v = o[i];
			int j = i, c = word_first(wl, v);
			while (j >= GAP[g] && word_first(wl, o[j - GAP[g]]) > c) { o[j] = o[j - GAP[g]]; j -= GAP[g]; }
			o[j] = v;
		}
	return 0;
}

static int restore_grid(int n, char *sentence, size_t cap, uint8_t ent[32])
{
	uint16_t idx[25], cand[6];
	uint8_t typed[24];
	char gmsg[48];
	int nw = 0, tl = 0, cur = 0, csel = 0, ctop = 0, ncell, cols, per, dirty = 1, last = -1, total = 0, reviewing = 0, rpage = 0;

	gmsg[0] = 0;
	if (L.mode == M_HANZI) {
		cols = 19; per = 19 * 8; ncell = cwl->n;
	} else {
		if (L.mode == M_KANA) { ncell = 84; cols = 19; for (int i = 0; i < 83; i++) gcell[i] = (uint16_t) (0x3041 + i); gcell[83] = 0x30FC; }
		else if (L.mode == M_CYR) { ncell = 33; cols = 17; for (int i = 0; i < 32; i++) gcell[i] = (uint16_t) (0x430 + i); gcell[32] = 0x451; }
		else { ncell = 51; cols = 17; for (int i = 0; i < 51; i++) gcell[i] = (uint16_t) (0x3131 + i); }
		per = ncell;
	}
	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(in_, NULL);
		pr = input_take_pressed(in_);
		if (pr & PAD_SELECT) { secure_zero(idx, sizeof idx); font_ext_clear(); return -1; }
		if (reviewing) {
			int cols2, per2, pages2 = page_layout(cwl, idx, nw, &cols2, &per2);

			if ((pr & PAD_RIGHT) && rpage < pages2 - 1) { rpage++; dirty = 1; }
			if ((pr & PAD_LEFT) && rpage > 0) { rpage--; dirty = 1; }
			if (pr & PAD_CIRCLE) { nw--; reviewing = 0; dirty = 1; gmsg[0] = 0; continue; }
			if (pr & (PAD_START | PAD_CROSS)) {
				int el = finish(idx, nw, sentence, cap, ent);
				if (el > 0) { secure_zero(idx, sizeof idx); font_ext_clear(); return el; }
				snprintf(gmsg, sizeof gmsg, T(TXT_CHECKSUM_WRONG_A_WORD_IS));
				nw--; reviewing = 0; dirty = 1;
				continue;
			}
			if (dirty) { load_words(cwl, idx + rpage * per2, nw - rpage * per2 < per2 ? nw - rpage * per2 : per2, NULL, 0); dirty = 0; }
			draw_page(cwl, idx, nw, rpage, cols2, per2, T(TXT_CHECK_THE_WORDS), NULL, NULL);
			t(16, UI_HINT2, T(TXT_HINT_USE_THESE_WORDS_CHANGE_THE), 150, 160, 200);
			gpu_present(rc_);
			continue;
		}
		if (L.mode == M_HANZI) {
			int pages = (ncell + per - 1) / per, page = cur / per;

			if (pr & PAD_RIGHT) { if (cur + 1 < ncell) cur++; }
			if (pr & PAD_LEFT) { if (cur > 0) cur--; }
			if (pr & PAD_DOWN) { if (cur + cols < ncell) cur += cols; }
			if (pr & PAD_UP) { if (cur >= cols) cur -= cols; }
			if (pr & PAD_R1) { cur += per; if (cur >= ncell) cur = ncell - 1; }
			if (pr & PAD_L1) { cur -= per; if (cur < 0) cur = 0; }
			if (pr & PAD_R2) { cur += 5 * per; if (cur >= ncell) cur = ncell - 1; }
			if (pr & PAD_L2) { cur -= 5 * per; if (cur < 0) cur = 0; }
			if ((pr & PAD_CIRCLE) && nw > 0) { nw--; dirty = 1; }
			if ((pr & PAD_CROSS) && nw < n) { idx[nw++] = cord[cur]; gmsg[0] = 0; if (nw == n) { reviewing = 1; rpage = 0; } dirty = 1; }
			if (page != cur / per) dirty = 1;
			page = cur / per;
			if (dirty) {
				int m = 0;
				for (int i = page * per; i < ncell && i < (page + 1) * per; i++) cps[m++] = (uint16_t) word_first(cwl, cord[i]);
				if (nw) {
					char w[40];
					word_text(cwl, idx[nw - 1], w, sizeof w);
					m = collect(w, cps, m);
				}
				font_ext_load(&L.gs, cps, m);
				dirty = 0;
			}
			{
				char line[64], w[40];
				snprintf(line, sizeof line, T(TXT_WORD_N_OF_N_PAGE_N), nw + 1 > n ? n : nw + 1, n, L.name, page + 1, pages);
				t(16, UI_TOP, line, 255, 255, 255);
				if (gmsg[0]) t(16, 24, gmsg, 255, 120, 120);
				else if (nw) { word_text(cwl, idx[nw - 1], w, sizeof w); snprintf(line, sizeof line, T(TXT_LAST_N), w); t(16, 24, line, 150, 160, 200); }
				for (int i = page * per; i < ncell && i < (page + 1) * per; i++) {
					int k = i - page * per;
					word_text(cwl, cord[i], w, sizeof w);
					t(GRID_X + (k % cols) * CELL, 46 + (k / cols) * 20, w, 255, i == cur ? 220 : 255, i == cur ? 80 : 255);
				}
				t(16, UI_HINT2, T(TXT_HINT_MOVE_PAGE_X5_TAKE_BACK_CANCEL), 150, 160, 200);
			}
			gpu_present(rc_);
			continue;
		}
		/* kana / jamo / Cyrillic */
		{
			char line[96], w[40];
			int typed_changed = 0, nc;

			if (pr & PAD_RIGHT) { if (cur + 1 < ncell) cur++; }
			if (pr & PAD_LEFT) { if (cur > 0) cur--; }
			if (pr & PAD_DOWN) { if (cur + cols < ncell) cur += cols; }
			if (pr & PAD_UP) { if (cur >= cols) cur -= cols; }
			if (pr & PAD_CROSS) {
				if (L.mode == M_HANGUL) { if (tl < 12) { typed[tl++] = (uint8_t) (cur + 1); typed_changed = 1; } }
				else { char cb[4]; int l = cell_utf8(gcell[cur], cb); if (tl + l <= 18) { memcpy(typed + tl, cb, (size_t) l); tl += l; typed_changed = 1; } }
			}
			if (pr & PAD_CIRCLE) {
				if (tl > 0) { do tl--; while (tl > 0 && (typed[tl] & 0xC0) == 0x80); typed_changed = 1; }      /* one character off */
				else if (nw > 0) { nw--; dirty = 1; }
			}
			if (typed_changed) { csel = ctop = 0; dirty = 1; gmsg[0] = 0; }
			total = tl ? langin_find(ckeys, 19, cwl->n, typed, tl, 0, 0, cand) : 0;
			if ((pr & PAD_R1) && csel + 1 < total) csel++;
			if ((pr & PAD_L1) && csel > 0) csel--;
			if (csel < ctop) { ctop = csel; dirty = 1; }
			if (csel >= ctop + 6) { ctop = csel - 5; dirty = 1; }
			nc = total - ctop > 6 ? 6 : total - ctop;
			if (nc > 0) langin_find(ckeys, 19, cwl->n, typed, tl, ctop, 6, cand); else nc = 0;
			if ((pr & PAD_SQUARE) && nc > 0 && nw < n) {
				idx[nw++] = cand[csel - ctop];
				tl = 0; csel = ctop = 0; dirty = 1; gmsg[0] = 0;
				if (nw == n) { reviewing = 1; rpage = 0; }
				continue;
			}
			if (dirty) {
				uint16_t all[8];
				int na = nc;
				memcpy(all, cand, (size_t) nc * 2);
				if (nw) all[na++] = idx[nw - 1];
				load_words(cwl, all, na, gcell, ncell);
				dirty = 0;
			}
			snprintf(line, sizeof line, T(TXT_WORD_N_OF_N_2), nw + 1 > n ? n : nw + 1, n, L.name);
			t(16, UI_TOP, line, 255, 255, 255);
			if (total > 6) { snprintf(line, sizeof line, T(TXT_N_WORDS), total); t(GPU_XRES - 16 - font_width(line), UI_TOP, line, 150, 160, 200); }
			{
				char tb[40];
				int o = 0;
				if (L.mode != M_HANGUL) { memcpy(tb, typed, (size_t) tl); o = tl; }
				else for (int i = 0; i < tl; i++) o += cell_utf8(0x3131u + typed[i] - 1u, tb + o);
				tb[o++] = '_';
				tb[o] = 0;
				t(16, 24, tb, 255, 255, 255);
				if (gmsg[0]) snprintf(line, sizeof line, "%s", gmsg);                          /* at the right of the line, if the typed letters leave room */
				else if (nw) { word_text(cwl, idx[nw - 1], w, sizeof w); snprintf(line, sizeof line, T(TXT_LAST_N), w); }
				else line[0] = 0;
				if (line[0] && 16 + font_width(tb) + 16 <= GPU_XRES - 16 - font_width(line))
					t(GPU_XRES - 16 - font_width(line), 24, line, gmsg[0] ? 255 : 150, gmsg[0] ? 120 : 160, gmsg[0] ? 120 : 200);
			}
			for (int i = 0; i < nc; i++) {
				word_text(cwl, cand[i], w, sizeof w);
				snprintf(line, sizeof line, "%c %s", ctop + i == csel ? '>' : ' ', w);
				t(16 + (i / 3) * 320, 46 + (i % 3) * 20, line, 255, ctop + i == csel ? 220 : 255, ctop + i == csel ? 80 : 255);
			}
			if (tl && !total) t(16, 46, T(TXT_NO_WORD_BEGINS_LIKE_THIS), 255, 160, 80);

			for (int i = 0; i < ncell; i++) {
				char g[4];
				cell_utf8(gcell[i], g);
				t(GRID_X + (i % cols) * CELL, GRID_Y + (i / cols) * 20, g, 255, i == cur ? 220 : 255, i == cur ? 80 : 255);
			}
			t(16, UI_HINT2, T(TXT_HINT_MOVE_TYPE_DELETE_WORD_TAKE), 150, 160, 200);
		}
		gpu_present(rc_);
	}
}

static int api_restore(RenderContext *ctx, input_state *in, int xmr, int n, char *sentence, size_t cap, uint8_t ent[32])
{
	int r;

	rc_ = ctx;
	in_ = in;
	if (!L.loaded || !wl_of(xmr)->n) return -2;
	if (L.mode == M_HANZI ? make_order(xmr) : make_keys(xmr)) return -1;
	cwl = wl_of(xmr);
	cxmr = xmr;
	ckeys = fkeys[xmr];
	cord = zord[xmr];
	r = L.mode == M_LATIN ? restore_latin(n, sentence, cap, ent) : restore_grid(n, sentence, cap, ent);
	font_ext_clear();
	return r;
}

/* the texts of the language on the screens: its tables are made known (a table of another release is refused: English stays) and the screens are switched to it */
static int ui_ext_on(void)
{
	static const uint32_t TABID[UI_RANGES] = {UI_TABID_A, UI_TABID_B, UI_TABID_L};
	static const unsigned N[UI_RANGES] = {UI_N_A, UI_N_B, UI_N_L};

	if (!L.ui[0]) return 0;
	for (int r = 0; r < UI_RANGES; r++)
		if (L.ui[r] && ui_table_set(r, UI_LANG_EXT, L.ui[r], L.uilen[r], TABID[r], N[r])) { ui_ext_clear(); return -1; }
	ui_lang_set(UI_LANG_EXT);
	return 0;
}

static lang_api API = {api_mnemonic, api_monero, api_show, api_restore, api_wipe, NULL, 0};

/* the language is off: nothing of it is called, its words and keys are forgotten (the memory is free for the next one) */
static void language_off(void)
{
	psxx_lang = NULL;
	ui_ext_clear();
	api_wipe();
	font_ext_clear();
	memset(&L, 0, sizeof L);
	fkeys[0] = fkeys[1] = NULL;
	zord[0] = zord[1] = NULL;
	arena_reset();
}

/* on: the module stays, the generator calls it (and the screens speak the language, if it has texts) */
static void switch_on(void)
{
	API.name = L.name;
	API.id = L.id;
	psxx_lang = L.bip.n || L.xmr.n ? &API : NULL;
	if (ui_ext_on()) snprintf(msg, sizeof msg, T(TXT_THE_TEXTS_OF_THE_SCREENS_ARE));
}

static void open_source(RenderContext *ctx, input_state *in, int hz)
{
	su_init(&sui, ctx, in, hz, T(TXT_LOAD_A_LANGUAGE), DATA_PKG, PKG_KIND_DATA, psxx_release_info.data_key, psxx_release_info.base_id, 0);
	su_enter(&sui, VSync(-1));
	phase = P_SRC;
}

/* the slot of the data package, as the source (Auto: the only slot that has one), or -1 */
static int c_slot(void)
{
	int a = cw_ok(&sui.cw, 0), b = cw_ok(&sui.cw, 1);

	if (sui.src) return cw_ok(&sui.cw, sui.src - 1) ? sui.src - 1 : -1;
	return a && !b ? 0 : !a && b ? 1 : -1;
}

static void show_index(void)
{
	phase = P_INDEX;
	for (int i = 0; i < nlang; i++) if (L.loaded && langs[i].id == L.id) sel = i;
	if (sel < top) top = sel;
	if (sel >= top + 8) top = sel - 7;
}

static void lang_ui_run(RenderContext *ctx, input_state *in, int hz)
{
	int last = -1, r;

	rc_ = ctx;
	in_ = in;
	msg[0] = 0;
	{
		int filled = 0;
		for (int i = 0; i < 32; i++) filled |= psxx_release_info.data_key[i];
		if (!filled) { msg[0] = 0; return; }                    /* a release without a data card: nothing to pin */
	}
	if (nlang > 0) {                                            /* in again: the module stayed and the index is known; the cards are looked at (both slots, at once) and the list comes if the data card is the package it was read from, anything else is read again */
		open_source(ctx, in, hz);
		cw_refresh(&sui.cw, VSync(-1));
		chk = 1;
	} else {
		sel = top = 0;
		open_source(ctx, in, hz);
	}
	for (;;) {
		int f = VSync(-1);
		uint16_t pr;

		if (f == last) continue;
		last = f;
		input_poll(in, NULL);
		pr = input_take_pressed(in);
		switch (phase) {
		case P_SRC: {
			uint16_t x = 0;

			if (chk) {
				int t = c_slot();

				chk = 0;
				if (t >= 0 && !strcmp(sui.cw.s[t].digest, c_dg)) { show_index(); last = -1; continue; }
				x = PAD_CROSS;                                          /* another card, other data, or none: read again; with no data card in a slot this goes to the screen that asks for it */
			}
			r = su_update(&sui, pr | x, f);
			if (r == SU_CANCEL) goto leave;
			if (r == SU_LOADED) {
				uint8_t idx[LANG_MAX * 32 + 1];
				uint32_t raw;

				ptotal = 0;
				if (rd(LANG_ID_INDEX, idx, sizeof idx, &raw) || (nlang = lang_index(idx, raw, langs, LANG_MAX)) < 1) { if (!msg[0]) snprintf(msg, sizeof msg, T(TXT_THE_INDEX_OF_THE_CARD_IS)); phase = P_INDEX; nlang = 0; c_dg[0] = 0; }
				else {
					if (c_dg[0] && strcmp(c_dg, sui.cw.s[sui.port].digest)) language_off();      /* other data than the language that is on came from */
					snprintf(c_dg, sizeof c_dg, "%s", sui.cw.s[sui.port].digest);
					if (sel >= nlang) sel = top = 0;
					msg[0] = 0;
					phase = P_INDEX;
				}
			}
			su_draw(&sui);
			break;
		}
		case P_INDEX:
			if (nlang && (pr & PAD_DOWN) && sel < nlang - 1) sel++;
			if (nlang && (pr & PAD_UP) && sel > 0) sel--;
			if (sel < top) top = sel;
			if (sel >= top + 8) top = sel - 7;
			if (pr & (PAD_CIRCLE | PAD_SELECT)) goto leave;
			if (pr & PAD_TRIANGLE) { nlang = 0; open_source(ctx, in, hz); break; }       /* another card, or the same one again */
			if (pr & PAD_SQUARE) { language_off(); msg[0] = 0; break; }
			if (nlang && (pr & PAD_CROSS)) { phase = P_LOAD; }
			draw_index();
			break;
		case P_LOAD:
			if (L.loaded && L.id == langs[sel].id) { phase = P_VIEW; fam = L.bip.n ? 0 : 1; vmode = 0; top = 0; dirty = 1; msg[0] = 0; last = -1; continue; }      /* already in memory */
			psxx_lang = NULL;                                       /* the old words are replaced: nothing calls them until START */
			ui_ext_clear();
			api_wipe();
			snprintf(msg, sizeof msg, "%s", langs[sel].name);
			t(16, 90, T(TXT_READING_THE_LANGUAGE_CARD), 255, 255, 255);
			gpu_present(ctx);
			if (load(&langs[sel])) { phase = P_INDEX; L.loaded = 0; }
			else { phase = P_VIEW; fam = L.bip.n ? 0 : 1; vmode = 0; top = 0; dirty = 1; msg[0] = 0; }
			last = -1;
			continue;
		case P_VIEW: {
			const words_list *wl = cur();
			int page = 2 * ROWS;
			if (pr & PAD_CIRCLE) { font_ext_clear(); phase = P_INDEX; msg[0] = 0; break; }
			if (pr & PAD_START) {
				if (!L.bip.n != !L.xmr.n) { phase = P_CONFIRM; break; }                       /* one list only: what stays English is said first */
				switch_on();
				goto leave;
			}
			if (pr & PAD_SQUARE) { vmode = 0; dirty = 1; }
			if ((pr & PAD_TRIANGLE) && (L.bip.n || L.xmr.n)) { vmode = 1; vtpage = 0; dirty = 1; }
			if ((pr & PAD_SELECT) && L.bip.n && L.xmr.n) { fam ^= 1; top = 0; vtpage = 0; dirty = 1; }
			if (vmode) {
				int cols, per, pages = page_layout(wl, tw, ntw, &cols, &per);
				if ((pr & PAD_RIGHT) && vtpage < pages - 1) vtpage++;
				if ((pr & PAD_LEFT) && vtpage > 0) vtpage--;
			}
			if (!vmode) {
				int nt = top;
				if (pr & PAD_DOWN) nt += page;                                                /* whole pages only: the words do not slide */
				if (pr & PAD_UP) nt -= page;
				if (pr & PAD_R1) nt += 10 * page;
				if (pr & PAD_L1) nt -= 10 * page;
				if (nt > wl->n - 1) nt = (wl->n - 1) / page * page;
				if (nt < 0) nt = 0;
				if (nt != top) { top = nt; dirty = 1; }
			}
			if (dirty && (L.bip.n || L.xmr.n)) prepare_page();
			draw_view();
			break;
		}
		case P_CONFIRM: {
			int x = L.xmr.n;

			if (pr & PAD_CIRCLE) { phase = P_VIEW; dirty = 1; break; }
			if (pr & PAD_CROSS) { switch_on(); goto leave; }
			t(16, UI_TOP, L.name, 255, 255, 255);
			t(16, 40, x ? T(TXT_ONLY_MONERO_LIST_A) : T(TXT_ONLY_BIP39_LIST_A), 255, 220, 80);
			t(16, 40 + LINE, x ? T(TXT_ONLY_MONERO_LIST_B) : T(TXT_ONLY_BIP39_LIST_B), 255, 255, 255);
			t(16, 40 + 2 * LINE, x ? T(TXT_ONLY_MONERO_LIST_C) : T(TXT_ONLY_BIP39_LIST_C), 255, 255, 255);
			t(16, UI_HINT2, T(TXT_HINT_CONFIRM_SWITCH_ON_BACK), 150, 160, 200);
			break;
		}
		default:
			break;
		}
		gpu_present(ctx);
	}
leave:
	font_ext_clear();                                            /* the glyph hooks are off; the module and the language stay in memory (the caller calls again, or wipes the slot with ldr_forget_slot) */
}

/* The entry of the overlay (group 2 of the package on the B card): the caller passes what the screens need. */
int ovl_main(RenderContext *ctx, input_state *in, int hz)
{
	ui_reg_l();                                                  /* the texts of the module */
	lang_ui_run(ctx, in, hz);
	return 0;
}
