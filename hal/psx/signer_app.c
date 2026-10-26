/*
 * Offline transaction signer: type the recovery words, load a signing request from the memory card in slot 2 (or type it in hex),
 * read what is being signed, hold X to sign, take the result as a QR code / UR animation, or save it to the card.
 *
 * Flow:  start (curve tables) -> HOME -> [RESTORE words -> passphrase] -> SOURCE -> request -> VIEW (pages) -> hold X -> RESULT
 *
 * This is the "signer" build of the spec (section 9): it contains no entropy collection and no key generation. The seed lives in RAM
 * only, wiped when the user asks or the console is switched off. All nonces are deterministic (RFC 6979 and friends), so nothing here
 * depends on the quality of a random source.
 */
#include <stdio.h>
#include "ui.h"
#include "log.h"
#include <string.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "keyboard.h"
#include "mcfile.h"
#ifdef SIGNER_KEYS
#include "keystore.h"
#include "lang_api.h"
#include "blob.h"
#include "pwtools.h"
#endif
#include "b64.h"
#include "ur.h"
#include "timer.h"
#include "util.h"
#include "qr.h"
#include "qr_view.h"
#include "ec/ed25519.h"
#include "ec/secp256k1.h"
#include "coin/bip39.h"
#include "coin/chains.h"
#ifdef SIGNER_KEYS
#include "coin/bip32.h"
#include "coin/xmr.h"
#endif
#include "coin/xmr_seed.h"
#include "handoff.h"
#ifndef SIGNER_OVERLAY
psxx_handoff_t psxx_handoff;                          /* the signer alone (psxx_signer): no generator hands a seed over */
#endif
#include "coin/orchard.h"
#include "ec/pallas.h"
#include "sign/dispatch.h"
#include "sign/nip44.h"
#ifdef SIGNER_KEYS
#include "sign/btc.h"
#endif
#include "sign/xmr.h"

#ifndef PSXX_EMULATED
#define PSXX_EMULATED 0
#endif

enum state { S_BOOT, S_HOME, S_RESTOPT, S_REST, S_REST_PASS, S_SRC, S_LIST, S_HEX, S_VIEW, S_OUT, S_ERR,
             S_KEY_LIST, S_KEY_PW, S_KEY_CONFIRM, S_KEY_DEL,
             S_VAN_KIND, S_VAN_DEP, S_VAN_INIT, S_VAN_PRE, S_VAN_SUF, S_VAN_PLAN, S_VAN_ENT, S_VAN_RUN, S_VAN_DONE,
             S_MS_LIST, S_MS_CONFIRM, S_MS_DEL,
             S_EXTRAS, S_CDP, S_TE_MENU, S_TE_TEXT, S_TE_HEX, S_TE_VIEW, S_TE_BRAILLE, S_NOTES,
             S_KM_MENU, S_RK_KIND, S_RK_TEXT, S_KD_CONFIRM, S_KE_LIST, S_KE_CONFIRM };                             /* the chooser the overlay starts with (the signer, the CD player), and the CD player's screen */

#define LINE 20
#define MARGIN 16
#define REQ_MAX 7936                    /* one memory card block holds 62 data frames */
#define RES_MAX 8192
#define REQ_TAG "PSXXRQ"
#define RES_TAG "PSXXSG"
#define QR_CAP 271
#define UR_FRAG 50
#define HOLD_NORMAL 75                  /* frames of holding X: 1.5 s */
#define HOLD_BLIND 150

extern uint32_t fb_buf[2560];           /* the 10 KB work area of the table builders, free once the tables stand */

static RenderContext ctx;
static input_state   in;
static enum state    state;
static kb_state      kb;
static char          msg[64];
static hd_secret     hs;
static char          hs_pass[KB_DEFAULT_LIMIT + 1];
static int           hs_valid;
static int           esel, tables_ready, tsel, nt_top;                    /* the chooser's row; the tables of the curves are built (S_BOOT done once) */
static char          mnemonic[BIP39_MAX_MNEMONIC];
static int           ropt_row, rest_nw, rest_pp, rest_goal, rest_len, rest_xmr;      /* rest_xmr: the 25 Monero words instead of BIP39 */
static int           hsel, ssel, boot_p, leave;                          /* leave: the chooser is left with back (the overlay returns to the generator) */
/* Keys on the card are in the build with SIGNER_KEYS only: with them the program does not fit the boot card any more (a packed image of 128 KB, the card takes 122 KB);
 * they are for the overlay build of the signer and for runs of the plain EXE. */
static int           from_card;                    /* the seed that is being loaded comes from a key on the card: it is checked on screen before use */
#ifdef SIGNER_KEYS
/* Keys on the card: the key stores of the card in slot 2, one key opened with its password, shown by its fingerprint and address, and loaded
 * like typed words. */
extern void addr_modal(const hd_secret *s, const char *pass);     /* wallet_app.c: the address pages of the main card for the seed that is passed (its copy is wiped there) */
#define KS_PORT 1
#define KEY_ROWS 7
static ksd_state     ks_st;
static uint8_t       ks_img[KS_DATA];
static int           ks_rc, ks_sel, ks_top, ks_total, ks_store, ks_key, ks_type;
static uint8_t       ks_k[32];                         /* the key of a store password, kept while the key list is used (wiped when it is left) */
static int           ks_kok, ks_kblock, ks_pw_for, ks_slot;      /* ks_pw_for: 0 the own password of a key, 1 the store password to open a key, 2 the store password to delete one */
static uint16_t      ks_kid;
static char          ks_label[KS_LABEL_STORE + 1], ck_fp[9], ck_addr[200];
static int           rk_pending, rk_show;               /* the key on the confirm screen was typed (not read from the card): it can be saved; rk_show: a raw key (typed or from the card) is shown with its addresses */
static void          rk_show_prepare(void);              /* signer_keys.h */
static char          ck_npub[100], ck_btc[100];                      /* the Nostr public key of a typed secp256k1 key, to compare with what the user knows */
static int           ck_hint;                           /* a raw key made by the vanity search: the kind of address it was looked for (the row of the table of the kinds plus one), or 0 */
static const char *van_hint_name(int hint);             /* signer_vanity.h */
static int van_hint_address(int hint, const uint8_t key[32], char *out, size_t cap);
static char          ks_pub[KSD_MAX_STORES][KS_SLOTS][KS_PUBLIC + 1];     /* the open labels of the own entries, by store and key, read when the list is made */
#endif
static uint8_t       req_buf[REQ_MAX + 8];
static char          msg_text[NIP_PT_MAX + 1];            /* a long text of the view (a decrypted message, a long note), shown on pages of its own */
static size_t        req_len;
static sign_req      req;
static tx_view       view;
static uint8_t       res_buf[RES_MAX];
static sign_result   res;
static int           vpage, hold, vnpages, armed;
static void          view_paginate(void);              /* the output pages of the transaction (below) */
static mcf_entry     rlist[8];
static int           rn, rsel, rrc;
static qr_code       qr;
static ur_plan       urp;
static char          urtxt[400], b64txt[300];       /* b64txt: only a result that fits one QR code is shown as base64 */
static int           qr_ok, qr_scale, out_ur, ur_seq, ur_tick, ur_fpp = 12, out_page, out_scroll;

/* timing marks on the debug console (core/prof.h): frames of the vertical blank since the previous mark */
void prof_mark(const char *label)
{
	static int last = -1;
	int now = VSync(-1), d = last < 0 ? 0 : now - last;
	last = now;
	LOG("[prof] %-40s +%d frames (about %d ms)\n", label, d, d * (GetVideoMode() == MODE_PAL ? 20 : 17));
}

/* ---- the table of the Sinsemilla points of Orchard (64 KB, core/ec/pallas.h): built in the idle time of the main loop while the user is in
 * the menus or types the words, a few field multiplications at a time. Points not ready yet are computed on the spot. ---- */
#define TBL_OPS 4                       /* field multiplications a step: about 0.4 ms */
static int tbl_next_log, tbl_start_frame, tbl_started, tbl_done_logged, warm_left = 6, warm_frame;
static const char *const STATE_NAME[] = {"BOOT", "HOME", "RESTOPT", "REST (typing the words)", "REST_PASS", "SRC", "LIST", "HEX", "VIEW", "OUT", "ERR", "KEY_LIST", "KEY_PW", "KEY_CONFIRM", "KEY_DEL",
                                       "VAN_KIND", "VAN_DEP", "VAN_INIT", "VAN_PRE", "VAN_SUF", "VAN_PLAN", "VAN_ENT", "VAN_RUN", "VAN_DONE", "MS_LIST", "MS_CONFIRM", "MS_DEL", "EXTRAS", "CDP", "TE_MENU", "TE_TEXT", "TE_HEX", "TE_VIEW", "TE_BRAILLE", "NOTES", "KM_MENU", "RK_KIND", "RK_TEXT", "KD_CONFIRM", "KE_LIST", "KE_CONFIRM"};

static int idle_state(void)
{
	return state != S_BOOT && state != S_EXTRAS && state != S_CDP && !(state >= S_TE_MENU && state <= S_NOTES);      /* the table of the signer is not built before it is chosen */
}

static void tbl_step(void)
{
	int n;
	if (!tbl_started) {
		pl_stable_reset();
		orchard_set_sinsemilla_table(pl_stable_get);
		tbl_start_frame = VSync(-1);
		tbl_started = 1;
		LOG("[prof] Sinsemilla table: building in the background starts (state %s)\n", STATE_NAME[state]);
	}
	n = pl_stable_step(TBL_OPS);
	if (n >= tbl_next_log + 128 || (n >= 1024 && !tbl_done_logged)) {
		int fr = VSync(-1) - tbl_start_frame;
		tbl_next_log = n & ~127;
		LOG("[prof] Sinsemilla table: %4d of 1024 points, %d s after the start (state %s)\n", n, fr / (GetVideoMode() == MODE_PAL ? 50 : 60), STATE_NAME[state]);
		if (n >= 1024) tbl_done_logged = 1;
	}
}

#include "ui_draw.h"

/* a long string over several lines of `chunk` characters (z slots 6..11: the hint lines use 0..5 for their icons) */
static int wrapped(int x, int y, const char *s, int chunk, int maxl, int r, int g, int b)
{
	char buf[72];
	size_t n = strlen(s), o = 0;
	int lines = 0;
	if (chunk > (int) sizeof buf - 1) chunk = (int) sizeof buf - 1;
	while (o < n && lines < maxl) {
		size_t l = n - o < (size_t) chunk ? n - o : (size_t) chunk;
		while (o + l < n && l > 1 && ((uint8_t) s[o + l] & 0xC0) == 0x80) l--;           /* not in the middle of a character */
		memcpy(buf, s + o, l);
		buf[l] = 0;
		font_draw(&ctx, 6, x, y + lines * LINE, buf, r, g, b);
		o += l;
		lines++;
	}
	return lines;
}

static void show_status(const char *l1, const char *l2)
{
	text(16, 90, l1);
	if (l2) dim(16, 90 + LINE + 4, l2);
	gpu_present(&ctx);
}

/* ---- the menus ---- */

/* ---- text encoding: type text and see its bytes (UTF-8 or ASCII), or type bytes in hex and see the text; and a braille test ---- */
#define TE_MAX 128                                          /* bytes */
#define TE_ROW_BYTES 4
#define TE_ROWS 6
static uint8_t te_raw[TE_MAX];                              /* what was typed: the UTF-8 bytes of a text, or the bytes of the hex */
static int     te_raw_len, te_from_text, te_ascii, te_top;

/* The bytes shown for the chosen preset: UTF-8 is the bytes as they are; ASCII is one byte a character (a text typed in: every character that is not ASCII becomes '?'; hex bytes
 * stay as typed, only the text made from them shows '?' for those over 127). Returns the length; `bad` the number of characters or bytes that are not ASCII. */
static int te_bytes(uint8_t *out, int *bad, int *nchars)
{
	const char *p = (const char *) te_raw, *e = (const char *) te_raw + te_raw_len;
	int n = 0;

	*bad = *nchars = 0;
	if (!te_from_text) {
		memcpy(out, te_raw, (size_t) te_raw_len);
		for (int i = 0; i < te_raw_len; i++) { if (te_raw[i] >= 0x80) (*bad)++; if ((te_raw[i] & 0xC0) != 0x80) (*nchars)++; }
		return te_raw_len;
	}
	while (p < e) {
		const char *q = p;
		int cp = font_utf8_next(&q);

		if (!cp) break;
		(*nchars)++;
		if (!te_ascii) { memcpy(out + n, p, (size_t) (q - p)); n += (int) (q - p); }
		else { if (cp >= 0x80) (*bad)++; out[n++] = (uint8_t) (cp < 0x80 ? cp : '?'); }
		p = q;
	}
	return n;
}

static void te_open(int from_text)
{
	te_from_text = from_text;
	te_top = 0;
	te_ascii = 0;
	state = S_TE_VIEW;
}

static void draw_te_menu(void)
{
	static const uint16_t M[] = {TXT_TEXT_TO_BYTES, TXT_BYTES_TO_TEXT, TXT_BRAILLE_TEST, TXT_TYPE_TEXT_SEE_ITS_BYTES_IN, TXT_TYPE_HEX_BYTES_SEE_THE_TEXT, TXT_BRAILLE_PATTERNS_ARE_DRAWN_FROM};

	ui_menu_ids(TXT_TEXT_ENCODING, M, 3, 1, tsel, TXT_HINT_CHOOSE_SELECT_BACK_2);
	wrapped(16, 132, T(TXT_YOUR_KEYBOARD_AND_THE_SYSTEM_USE), 58, 2, 150, 160, 200);
}

static void draw_te_view(void)
{
	uint8_t b[TE_MAX];
	char line[96], shown[56];
	int bad, nchars, n = te_bytes(b, &bad, &nchars), k = 0, cells = 0;
	const char *p;

	text(16, UI_TOP, T(TXT_TEXT_AND_BYTES));
	dim(GPU_XRES - 16 - 11 * 10, UI_TOP, te_ascii ? T(TXT_PRESET_ASCII) : T(TXT_PRESET_UTF_8));
	for (int i = 0; i < n && cells < 54; ) {                       /* the text: control bytes show as dots; a character is never cut in the middle */
		int l = 1;
		if (b[i] >= 0xC0) l = b[i] >= 0xF0 ? 4 : b[i] >= 0xE0 ? 3 : 2;
		if (te_ascii && b[i] >= 0x80) { shown[k++] = '?'; i++; cells++; continue; }
		for (int j = 0; j < l && i + j < n && k < (int) sizeof shown - 5; j++) shown[k++] = (char) (b[i + j] < 0x20 || b[i + j] == 0x7F ? '.' : b[i + j]);
		i += l;
		cells++;
	}
	shown[k] = 0;
	text(16, 28, shown);
	sprintf(line, T(TXT_N_BYTES_N_CHARACTERS), n, nchars);
	if (bad) sprintf(line + strlen(line), T(TXT_N_NOT_ASCII_SHOWN_AS), bad);
	dim(16, 50, line);
	for (int r = 0; r < TE_ROWS; r++) {
		int o = te_top + r * TE_ROW_BYTES;
		char hex[16] = "", bin[48] = "";

		if (o >= n) break;
		for (int i = 0; i < TE_ROW_BYTES && o + i < n; i++) {
			sprintf(hex + strlen(hex), "%02X ", b[o + i]);
			for (int bit = 7; bit >= 0; bit--) strcat(bin, (b[o + i] >> bit & 1) ? "1" : "0");
			strcat(bin, " ");
		}
		ctext(16, 74 + r * 20, hex, UI_SEL_RGB);
		text(150, 74 + r * 20, bin);
	}
	if (n > TE_ROWS * TE_ROW_BYTES) { sprintf(line, "%d-%d / %d", te_top + 1, te_top + TE_ROWS * TE_ROW_BYTES < n ? te_top + TE_ROWS * TE_ROW_BYTES : n, n); dim(GPU_XRES - 16 - font_width(line), 50, line); }
	p = T(TXT_HINT_SCROLL_PRESET_BACK);
	dim(16, UI_HINT2, p);
}

static void draw_te_braille(void)
{
	text(16, UI_TOP, T(TXT_BRAILLE_TEST));
	for (int i = 0; i < 8; i++) text(16 + 4 * 10, 26 + i * 18, T(TXT_BRAILLE_1 + i));
	dim(16, 174, T(TXT_EVERY_PATTERN_IS_DRAWN_FROM_ITS));
	dim(16, UI_HINT2, T(TXT_HINT_BACK_3));
}

/* ---- the safety notes: very short lines (the NOTE_n texts), eight rows a page ---- */
#define NOTE_COUNT 13
#define NOTE_ROWS 8
_Static_assert(TXT_NOTE_1 + NOTE_COUNT - 1 == TXT_NOTE_13, "the notes are NOTE_COUNT texts in a row (tools/strings/en_b.txt)");

static void draw_notes(void)
{
	char line[40];

	text(16, UI_TOP, T(TXT_SAFETY_NOTES));
	for (int i = 0; i < NOTE_ROWS && nt_top + i < NOTE_COUNT; i++) text(16, 28 + i * 22, T(TXT_NOTE_1 + nt_top + i));
	sprintf(line, "%d-%d / %d", nt_top + 1, nt_top + NOTE_ROWS < NOTE_COUNT ? nt_top + NOTE_ROWS : NOTE_COUNT, NOTE_COUNT);
	dim(GPU_XRES - 16 - font_width(line), UI_TOP, line);
	dim(16, UI_HINT2, T(TXT_HINT_SCROLL_BACK));
}

static void draw_extras(void)
{
	static const uint16_t M[] = {TXT_SIGNER, TXT_TEXT_ENCODING, TXT_SAFETY_NOTES, TXT_CD_PLAYER,
	                             TXT_TRANSACTIONS_KEYS_VANITY_ADDRESSES_MULTISIG, TXT_TEXT_BYTES_UTF_8_ASCII_BRAILLE, TXT_SHORT_NOTES_ON_SEEDS_DICE_AND, TXT_PLAY_AUDIO_DISCS};

	ui_menu_ids(TXT_EXTRAS, M, 4, 1, esel, TXT_HINT_CHOOSE_SELECT_BACK_2);
}

#ifdef SIGNER_KEYS
#define HOME_N 7
#else
#define HOME_N 3
#endif

static void draw_home(void)
{
	/* the names of the first HOME_N items, then their descriptions (ui_menu_ids reads n of each) */
	static const uint16_t M[] = {TXT_SIGN_A_TRANSACTION, TXT_LOAD_ANOTHER_SEED, TXT_FORGET_THE_SEEDS,
#ifdef SIGNER_KEYS
	                             TXT_KEY_FROM_THE_CARD, TXT_VANITY_ADDRESS, TXT_MULTISIG_WALLETS, TXT_ADDRESSES,
#endif
	                             TXT_TYPE_YOUR_WORDS_LOAD_A_REQUEST, TXT_BIP39_WORDS_OR_THE_25_WORDS_OF, TXT_WIPE_THE_WORDS_AND_KEYS_FROM,
#ifdef SIGNER_KEYS
	                             TXT_A_PASSWORD_PROTECTED_KEY_SAVED, TXT_SEARCH_FOR_AN_ADDRESS_WITH_A, TXT_REGISTER_THE_COSIGNERS_OF_A, TXT_OTHER_COINS_MORE_ADDRESSES_PATHS
#endif
	};
	char line[64];
	ui_menu_ids(TXT_PSX_SIGNER, M, HOME_N, 1, hsel, TXT_HINT_CHOOSE_SELECT_BACK_2);
	sprintf(line, T(TXT_LOADED_N), hs.raw_curve ? T(TXT_RAW_KEY) : hs.no_bip ? "" : (hs_valid ? T(TXT_BIP39_WORDS) : "nothing"), (hs_valid && (hs.raw_curve || !hs.no_bip) && hs.xmr_ok) ? ", " : "", hs.xmr_ok ? T(TXT_MONERO_WORDS) : "");
	dim(16, UI_HINT2, line);
}

static void draw_src(void)
{
	static const uint16_t M[] = {TXT_REQUEST_ON_THE_CARD_IN_SLOT_2, TXT_TYPE_THE_REQUEST_IN_HEX, TXT_FILES_WRITTEN_BY_TOOLS_PSXX_TX, TXT_FOR_SHORT_REQUESTS_A_MESSAGE_A};
	ui_menu_ids(TXT_SIGNING_REQUEST, M, 2, 1, ssel, TXT_HINT_CHOOSE_SELECT_BACK_2);
}

/* ---- restore from words: the same screens as the generator ---- */

static void draw_restopt(void)
{
	char line[64];

	text(16, UI_TOP, T(TXT_RECOVERY_WORDS));
	if (rest_nw == 5) sprintf(line, T(TXT_N_WORDS_N_MONERO_25_N), ropt_row == 0 ? '>' : ' ', '<', '>');
	else sprintf(line, T(TXT_N_WORDS_N_2), ropt_row == 0 ? '>' : ' ', '<', 12 + 3 * rest_nw, '>');
	ui_hl(16, 40, ropt_row == 0, line);
	if (rest_nw == 5) strcpy(line, T(TXT_NO_PASSPHRASE_2));
	else sprintf(line, T(TXT_N_PASSPHRASE_N), ropt_row == 1 ? '>' : ' ', '<', rest_pp ? "yes" : "no", '>');
	ui_hl(16, 68, ropt_row == 1, line);
	dim(16, 110, T(TXT_TYPE_THE_WORDS_WITH_THE));
	dim(16, UI_HINT2, T(TXT_HINT_ROW_CHANGE_CONTINUE_BACK));
}

static int rest_suggest(const char *pre, int len, int from, char out[][KB_SUGLEN], int max)
{
	char w[KB_SUG][BIP39_MAX_WORD + 1];
	int n = bip39_complete(pre, (size_t) len, from, w, max > KB_SUG ? KB_SUG : max);
	for (int i = 0; i < n - from && i < max; i++) strcpy(out[i], w[i]);
	return n;
}

/* the Monero word list; words longer than the suggestion boxes are cut (the first three letters name a word) */
static int rest_suggest_xmr(const char *pre, int len, int from, char out[][KB_SUGLEN], int max)
{
	char w[KB_SUG][13];
	int n = xmr_complete(pre, (size_t) len, from, w, max > KB_SUG ? KB_SUG : max);
	for (int i = 0; i < n - from && i < max && i < KB_SUG; i++) { memcpy(out[i], w[i], KB_SUGLEN - 1); out[i][KB_SUGLEN - 1] = 0; }
	return n;
}

static void rest_kb(void)
{
	kb_init(&kb, T(TXT_RECOVERY_WORDS), NULL, 0, 0);
	kb_set(&kb, 300, 0);
	kb_set_suggest(&kb, rest_xmr ? rest_suggest_xmr : rest_suggest);
	kb.goal = rest_goal;
	rest_len = -1;
}

static void draw_rest(void)
{
	if (rest_len != kb.len) msg[0] = 0;
	kb.note = msg[0] ? msg : NULL;
	kb.warn = 2;
	kb_draw(&ctx, &kb);
}

/* the typed words -> `mnemonic` and the entropy; the length of the entropy or -1 with msg */
static int rest_parse(uint8_t ent[32])
{
	const char *p = kb.text;
	int n = 0, o = 0, r;

	mnemonic[0] = 0;
	while (*p) {
		char tok[16];
		int l = 0, idx;
		while (*p == ' ') p++;
		if (!*p) break;
		while (*p && *p != ' ') { if (l < 15) tok[l++] = (*p >= 'A' && *p <= 'Z') ? (char) (*p + 32) : *p; p++; }
		tok[l] = 0;
		n++;
		idx = l <= BIP39_MAX_WORD ? bip39_find(tok, (size_t) l) : -1;
		if (idx < 0 || o + BIP39_MAX_WORD + 1 >= (int) sizeof mnemonic) { sprintf(msg, T(TXT_WORD_N_IS_NOT_IN_THE_LIST), n); return -1; }
		o += bip39_word((unsigned) idx, mnemonic + o);
		mnemonic[o++] = ' ';
		mnemonic[o] = 0;
	}
	if (o) mnemonic[o - 1] = 0;
	if (n != rest_goal) { sprintf(msg, T(TXT_N_WORDS_TYPED_N_CHOSEN), n, rest_goal); return -1; }
	r = bip39_mnemonic_to_entropy(mnemonic, ent);
	if (r < 0) sprintf(msg, T(TXT_CHECKSUM_WRONG_A_WORD_IS));
	return r;
}

/* the 25 Monero words typed: check them and keep the key */
static int rest_parse_xmr(void)
{
	uint8_t key[32];
	int n = 0;
	for (const char *p = kb.text; *p;) {
		while (*p == ' ') p++;
		if (!*p) break;
		n++;
		while (*p && *p != ' ') p++;
	}
	if (n != 25) { sprintf(msg, T(TXT_N_WORDS_TYPED_25_NEEDED), n); return -1; }
	if (xmr_seed_decode(kb.text, key)) { sprintf(msg, T(TXT_A_WORD_IS_WRONG_OR_THE)); return -1; }
	if (!hs_valid) hs.no_bip = 1;
	memcpy(hs.xmr_seed, key, 32);
	hs.xmr_ok = 1;
	hs_valid = 1;
	secure_zero(key, sizeof key);
	kb_wipe(&kb);
	kb_clip_wipe();
	msg[0] = 0;
	ssel = 0;
	state = S_SRC;
	return 0;
}

#ifdef SIGNER_KEYS
static void confirm_prepare(void);
#else
#define confirm_prepare() ((void) 0)
#endif

/* the words are right: the seed (about 2 seconds of PBKDF2) */
static void restore_derive(void)
{
	show_status(T(TXT_HASHING_THE_SEED), T(TXT_ABOUT_5_SECONDS));
	bip39_seed(mnemonic, kb.text, hs.seed);
	snprintf(hs_pass, sizeof hs_pass, "%s", kb.text);
	hs.passphrase = hs_pass;
	hs.no_bip = 0;
	hs.raw_curve = 0;                                                 /* words replace a raw key: only one of them signs at a time */
	secure_zero(hs.raw, sizeof hs.raw);
	hs_valid = 1;
	secure_zero(mnemonic, sizeof mnemonic);
	kb_wipe(&kb);
	kb_clip_wipe();
	msg[0] = 0;
	ssel = 0;
	if (from_card) confirm_prepare();
	else state = S_SRC;
}

/* the seed the generator handed over ("sign with this seed"): whatever list it was typed in there, here it is the result */
static void take_handoff(void)
{
	if (!psxx_handoff.valid) return;
	hs = psxx_handoff.hs;
	snprintf(hs_pass, sizeof hs_pass, "%s", psxx_handoff.pass);
	hs.passphrase = hs_pass;
	hs_valid = 1;
	secure_zero(&psxx_handoff, sizeof psxx_handoff);
}

static void forget(void)
{
	xmr_tx_forget();
#ifdef SIGNER_KEYS
	secure_zero(ks_img, sizeof ks_img);
	secure_zero(ks_label, sizeof ks_label);
	secure_zero(ks_k, sizeof ks_k);
	ks_kok = 0;
	rk_pending = rk_show = 0;
	secure_zero(ck_npub, sizeof ck_npub);
	secure_zero(ck_btc, sizeof ck_btc);
#endif
	from_card = 0;
	secure_zero(&hs, sizeof hs);
	secure_zero(hs_pass, sizeof hs_pass);
	secure_zero(mnemonic, sizeof mnemonic);
	secure_zero(req_buf, sizeof req_buf);
	secure_zero(res_buf, sizeof res_buf);
	secure_zero(msg_text, sizeof msg_text);
	secure_zero(&view, sizeof view);
	kb_wipe(&kb);
	kb_clip_wipe();
	qr_view_clear();
	qr_ok = 0;
	hs_valid = 0;
	msg[0] = 0;
}

#ifdef SIGNER_KEYS
/* ---- keys on the card ---- */

static const char *card_error(int r);

static const char *key_error(int r)
{
	return r == KSD_ERR_IMAGE ? T(TXT_DAMAGED_KEY_STORE) : r == KSD_ERR_CHANGED ? T(TXT_THE_CARD_WAS_CHANGED) : r == KSD_ERR_FULL ? T(TXT_NO_FREE_BLOCK) : r == KSD_ERR_VERIFY ? T(TXT_THE_CARD_DID_NOT_KEEP_IT)
	     : r == KSD_ERR_PASSWORD ? T(TXT_WRONG_PASSWORD_OR_DAMAGED_KEY) : r == KSD_ERR_LIMIT || r == KSD_ERR_ARG ? T(TXT_NOT_POSSIBLE) : card_error(r);
}

static void keys_scan(void)
{
	ks_rc = ksd_scan(KS_PORT, &ks_st, 0);
	for (int i = 0; ks_rc == MCF_OK && i < ks_st.nstores; i++) {         /* a store whose pair map does not hold together is left alone, like one with no directory */
		if (ks_dir_pairs_ok(&ks_st.st[i].dir)) continue;
		for (int j = i; j + 1 < ks_st.nstores; j++) ks_st.st[j] = ks_st.st[j + 1];
		ks_st.nstores--;
		ks_st.corrupt++;
		i--;
	}
	ks_total = 0;
	memset(ks_pub, 0, sizeof ks_pub);
	if (ks_rc == MCF_OK) for (int i = 0; i < ks_st.nstores; i++) {
		ks_total += ks_st.st[i].n;
		if (ks_st.st[i].n && ksd_read(KS_PORT, &ks_st.st[i], ks_img) == MCF_OK)                  /* the open labels: in the frames of the entries */
			for (int k = 0; k < ks_st.st[i].n && k < KS_SLOTS; k++) {
				int slot = ks_live_slot(&ks_st.st[i].dir, k);

				if (slot >= 0) ks_own_entry_open_label(ks_img + (KS_DIR_FRAMES + slot) * KS_FRAME, ks_pub[i][k]);
			}
	}
	secure_zero(ks_img, sizeof ks_img);
	ks_sel = ks_top = 0;
	msg[0] = 0;
}

static void ks_locate(int e, int *store, int *key)
{
	for (int i = 0; i < ks_st.nstores; i++) {
		if (e < ks_st.st[i].n) { *store = i; *key = e; return; }
		e -= ks_st.st[i].n;
	}
	*store = *key = 0;
}

static void ks_forget_key(void) { secure_zero(ks_k, sizeof ks_k); ks_kok = 0; }
static int ks_has_k(void) { return ks_kok && ks_kblock == ks_st.st[ks_store].block && ks_kid == ks_st.st[ks_store].id; }
static const uint8_t *ks_frame(void) { return ks_img + (KS_DIR_FRAMES + ks_slot) * KS_FRAME; }

static void ks_ask(const char *title)
{
	kb_init(&kb, title, NULL, 1, 0);
	kb_set(&kb, PW_MAX, 0);                                          /* long enough for a phrase of words */
	state = S_KEY_PW;
}

static void key_decrypt(void);
static void key_delete(void);

/* a key is chosen: its store is read, then the password is asked: its own, or the one of the store (once for all the keys of the store) */
static void key_open(void)
{
	int r;

	ks_locate(ks_sel, &ks_store, &ks_key);
	ks_slot = ks_live_slot(&ks_st.st[ks_store].dir, ks_key);
	show_status(T(TXT_READING_THE_KEY_STORE), NULL);
	r = ksd_read(KS_PORT, &ks_st.st[ks_store], ks_img);
	if (r || ks_slot < 0) { sprintf(msg, T(TXT_CANNOT_READ_IT_N), key_error(r ? r : KSD_ERR_IMAGE)); return; }
	msg[0] = 0;
	if (ks_entry_kind(ks_frame()) == KS_ENTRY_STORE) {
		if (ks_has_k()) { key_decrypt(); return; }
		ks_pw_for = 1;
		ks_ask(T(TXT_PASSWORD_OF_THE_STORE));
	} else {
		ks_pw_for = 0;
		ks_ask(T(TXT_PASSWORD_OF_THIS_KEY));
	}
}

/* the store password is typed: the key of the store, checked against the store (the check value, then the mac of its directory); 1 when it is right */
static int store_unlock(void)
{
	const ks_dir *d = &ks_st.st[ks_store].dir;
	uint8_t k[32], chk[16];
	char when[32];
	int ok;

	sprintf(when, T(TXT_ABOUT_N_SECONDS), (unsigned) (d->iter * 9 / 10000 + 1));
	show_status(T(TXT_OPENING_THE_STORE), when);
	ks_store_key(k, chk, (const uint8_t *) kb.text, (size_t) kb.len, d->iter, d->salt);
	kb_wipe(&kb);
	kb_clip_wipe();
	ok = !memcmp(chk, d->check, 16) && ks_dir_mac_ok(d, k);
	if (ok) { memcpy(ks_k, k, 32); ks_kok = 1; ks_kblock = ks_st.st[ks_store].block; ks_kid = ks_st.st[ks_store].id; }
	secure_zero(k, sizeof k);
	return ok;
}

/* the master fingerprint and first address (or the Monero main address) of the key that was loaded, to be compared with what the user knows */
static void confirm_prepare(void)
{
	ck_fp[0] = ck_addr[0] = 0;
	show_status(T(TXT_CHECKING_THE_KEY), T(TXT_ABOUT_3_SECONDS));
	if (ks_type == KS_TYPE_RAW) {                                      /* a raw key: the addresses of the chains it serves, as for a typed one */
		rk_show_prepare();
		return;
	} else if (ks_type == KS_TYPE_MONERO) {
		xmr_keys k;

		xmr_keys_from_seed(&k, hs.xmr_seed);
		if (xmr_address(ck_addr, sizeof ck_addr, 0x12, k.spend_pub, k.view_pub) <= 0) ck_addr[0] = 0;
		secure_zero(&k, sizeof k);
	} else {
		bip32_node n;
		uint8_t fp[4];

		if (bip32_master(&n, hs.seed, 64) == 0 && bip32_fingerprint(&n, fp) == 0) sprintf(ck_fp, "%02x%02x%02x%02x", fp[0], fp[1], fp[2], fp[3]);
		secure_zero(&n, sizeof n);
		if (chain_address_str(ck_addr, sizeof ck_addr, chain_find("btc84"), &hs, "m/84'/0'/0'/0/0") <= 0) ck_addr[0] = 0;
	}
	state = S_KEY_CONFIRM;
}

/* the entry is opened (its own password is in kb, or the store key is known); a BIP39 key goes on like typed words (a passphrase is asked if the key says it was used), a Monero key is loaded at once */
static void key_decrypt(void)
{
	uint8_t ent[KS_KEY_MAX];
	int flags, elen, r;

	if (ks_entry_kind(ks_frame()) == KS_ENTRY_STORE) {
		r = ks_store_entry_open(ks_frame(), ks_k, ks_st.st[ks_store].id, ks_slot, &ks_type, &flags, ent, &elen, ks_label);
	} else {
		char when[32];

		sprintf(when, T(TXT_ABOUT_N_SECONDS), (unsigned) (ks_own_entry_iterations(ks_frame()) * 9 / 10000 + 1));
		show_status(T(TXT_OPENING_THE_KEY), when);
		r = ks_own_entry_open(ks_frame(), (const uint8_t *) kb.text, (size_t) kb.len, &ks_type, &flags, ent, &elen, ks_label);
		kb_wipe(&kb);
		kb_clip_wipe();
	}
	if (r == KS_ERR_PASSWORD) { ks_pw_for = 0; ks_ask(T(TXT_WRONG_PASSWORD_OR_DAMAGED_KEY)); return; }
	secure_zero(ks_img, sizeof ks_img);
	if (r != KS_OK) { sprintf(msg, T(TXT_THAT_IS_NOT_A_KEY_ENTRY)); state = S_KEY_LIST; return; }
	ck_hint = ks_type == KS_TYPE_RAW ? KS_LANG(flags) : 0;             /* a raw key has no language: the bits say what the vanity search looked for */
	if (KS_LANG(flags) && ks_type != KS_TYPE_RAW && !(ks_type == KS_TYPE_BIP39 && psxx_lang && psxx_lang->id == KS_LANG(flags))) {      /* BIP39 words of another language: the seed is made from their text, so that language has to be on in the language module */
		secure_zero(ent, sizeof ent);
		sprintf(msg, T(TXT_SWITCH_ON_THE_LANGUAGE_OF_THIS_KEY));
		state = S_KEY_LIST;
		return;
	}
	from_card = 1;
	if (ks_type == KS_TYPE_RAW) {
		memset(hs.seed, 0, sizeof hs.seed);
		memset(hs.entropy, 0, sizeof hs.entropy);
		hs.entlen = 0;
		hs.no_bip = 1;
		memset(hs.raw, 0, sizeof hs.raw);
		memcpy(hs.raw, ent, (size_t) elen);
		hs.raw_curve = KS_CURVE(flags) == KS_CURVE_SECP256K1 ? 2 : KS_CURVE(flags) == KS_CURVE_SR25519 ? 3 : KS_CURVE(flags) == KS_CURVE_ORCHARD ? 4 : KS_CURVE(flags) == KS_CURVE_CARDANO ? 5 : 1;
		hs_valid = 1;
		confirm_prepare();
	} else if (ks_type == KS_TYPE_MONERO) {
		if (!hs_valid) hs.no_bip = 1;
		memcpy(hs.xmr_seed, ent, 32);
		hs.xmr_ok = 1;
		hs_valid = 1;
		confirm_prepare();
	} else if ((KS_LANG(flags) ? psxx_lang->mnemonic(ent, elen, mnemonic, sizeof mnemonic) : bip39_entropy_to_mnemonic(ent, (size_t) elen, mnemonic, sizeof mnemonic)) <= 0) {      /* the sentence of the language that is on (NFKD), or the English one */
		from_card = 0;
		sprintf(msg, T(TXT_THAT_IS_NOT_A_KEY_ENTRY));
		state = S_KEY_LIST;
	} else {
		memcpy(hs.entropy, ent, (size_t) elen);
		hs.entlen = elen;
		kb_init(&kb, T(TXT_PASSPHRASE_OF_THIS_KEY), NULL, 1, 0);
		if (flags & KS_FLAG_PASSPHRASE) state = S_REST_PASS;           /* restore_derive follows, then the check */
		else restore_derive();
	}
	secure_zero(ent, sizeof ent);
}

/* delete: the store is read again (its chain checked), a store with a password needs its key (its directory is signed with it) */
static void key_delete_do(void)
{
	int r;

	show_status(T(TXT_DELETING_THE_KEY), T(TXT_KEEP_THE_CARD_IN_THE_SLOT));
	if (ks_st.st[ks_store].single) {                                    /* a single key: its block stays for the next one; the file goes with the last key */
		int left = 0;

		r = ksd_del2(KS_PORT, &ks_st, ks_store, ks_slot, NULL, ks_img);
		for (int i = 0; i < ks_st.nstores; i++) left += ks_st.st[i].single ? ks_st.st[i].n : 0;
		if (r == KSD_OK && !left) r = ksd_remove_singles(KS_PORT, &ks_st);
	}
	else if (ks_st.st[ks_store].n <= 1) r = ksd_remove_store(KS_PORT, &ks_st, ks_store);
	else r = ksd_del2(KS_PORT, &ks_st, ks_store, ks_slot, ks_has_k() ? ks_k : NULL, ks_img);
	secure_zero(ks_img, sizeof ks_img);
	keys_scan();
	if (r == KSD_OK) sprintf(msg, T(TXT_DELETED));
	else sprintf(msg, T(TXT_NOT_DELETED_N), key_error(r));
	state = S_KEY_LIST;
}

static void key_delete(void)
{
	if (ks_st.st[ks_store].n > 1 && (ks_st.st[ks_store].dir.flags & KS_DIR_PW) && !ks_has_k()) { ks_pw_for = 2; ks_ask(T(TXT_PASSWORD_OF_THE_STORE)); return; }
	key_delete_do();
}

#endif

/* ---- the request ---- */

static const char *card_error(int r)
{
	return r == MCF_NO_CARD ? T(TXT_NO_CARD_IN_SLOT_2) : r == MCF_BAD_CARD ? T(TXT_CARD_NOT_FORMATTED) : r == MCF_FULL ? T(TXT_CARD_IS_FULL)
	     : r == MCF_NOT_FOUND ? T(TXT_FILE_NOT_FOUND) : T(TXT_CARD_ERROR);
}

static void scan_requests(void)
{
	int nfiles, next, blk;
	rrc = mcf_scan(1, REQ_TAG, rlist, 7, &nfiles, &next, &blk);
	rn = rrc == MCF_OK ? (nfiles < 8 ? nfiles : 8) : 0;
	rsel = 0;
}

/* a file: frame 2 starts with the length of the request (u32 LE), then the request */
static int load_request(int block)
{
	uint8_t f[MC_FRAME];
	size_t n = 0, got = 0;
	int r, frame = 2;

	r = mcf_read(1, block, frame++, f);
	if (r) return r;
	n = (size_t) f[0] | (size_t) f[1] << 8 | (size_t) f[2] << 16 | (size_t) f[3] << 24;
	if (n < 20 || n > REQ_MAX) return MCF_IO;
	memcpy(req_buf, f + 4, MC_FRAME - 4);
	got = MC_FRAME - 4;
	while (got < n && frame < 64) {
		r = mcf_read(1, block, frame++, f);
		if (r) return r;
		memcpy(req_buf + got, f, MC_FRAME);
		got += MC_FRAME;
	}
	if (got < n) return MCF_IO;
	req_len = n;
	return MCF_OK;
}

static void error_screen(const char *m)
{
	snprintf(msg, sizeof msg, "%s", m);
	state = S_ERR;
}

#ifdef SIGNER_KEYS
static void ms_scan(int files);                           /* signer_ms.h: the registered multisig wallets of the card */
static int ms_nwal;
#endif

/* the request in req_buf: parse it and make the pages */
static void open_request(void)
{
	int e = sign_req_parse(&req, req_buf, req_len);
	if (!e && req.chain->kind == K_MONERO) show_status(T(TXT_CHECKING_THE_TRANSACTION), T(TXT_OUTPUTS_INPUTS_KEY_IMAGES_A));
	if (!e && req.chain->kind == K_ORCHARD) { show_status(T(TXT_CHECKING_THE_TRANSACTION), T(TXT_READING_THE_SHIELDED_OUTPUTS)); LOG("[prof] Sinsemilla table at the request: %d of 1024 points ready, %d s after the start\n", pl_stable_built(), (VSync(-1) - tbl_start_frame) / (GetVideoMode() == MODE_PAL ? 50 : 60)); }
#ifdef SIGNER_KEYS
	if (!e && hs_valid && !hs.no_bip && btc_net_for(req.chain)) {              /* the registered multisig wallets of the card, checked against the seed */
		ms_scan(0);
		if (ms_nwal) show_status(T(TXT_CHECKING_THE_WALLETS), T(TXT_A_FEW_SECONDS));
	}
#endif
	prof_mark(T(TXT_SUMMARY_START));
	txv_text = msg_text; txv_text_cap = sizeof msg_text;                 /* a long text goes to the text pages; the summaries that need room use the result buffer, which is idle until the signing */
	txv_work = res_buf; txv_work_cap = sizeof res_buf;
	if (!e) e = sign_summary(&req, &hs, &view);
	txv_text = NULL; txv_text_cap = 0; txv_work = NULL; txv_work_cap = 0;
	prof_mark(T(TXT_SUMMARY_DONE));
	if (e) {
		secure_zero(req_buf, sizeof req_buf);
		secure_zero(res_buf, sizeof res_buf);
		secure_zero(msg_text, sizeof msg_text);
		error_screen(sign_error_text(e));
		return;
	}
	vpage = 0;
	hold = 0;
	armed = 0;                                          /* X must be let go of first: it opened this screen */
	view_paginate();
	state = S_VIEW;
}

/* ---- the transaction pages ---- */

#define VIEW_TOP 26
#define VIEW_END UI_MSG                /* an output page ends above the hint line (UI_HINT2: its icons begin at 202) */
static uint8_t vfirst[TXV_OUTS + 2];   /* the first output of output page p is vfirst[p - 1]; vfirst[last page] = nout */
static int     vout_pages;              /* the pages of outputs (after the summary page) */
#define TEXT_LINES ((VIEW_END - VIEW_TOP) / LINE)
#define TEXT_PAGES_MAX 12
static uint16_t tpage[TEXT_PAGES_MAX + 1];   /* the text pages (after the output pages): where each starts in msg_text */
static int      ntp;

static int text_lines(const char *s, int chunk) { int n = (int) strlen(s); return n ? (n + chunk - 1) / chunk : 0; }
/* an output on the screen: its address (two lines at most), its amount (a 256 bit amount and its token take up to three; never cut), a gap */
static int amount_chunk(const txv_out *o) { return o->mine ? 52 : 60; }
static int out_height(const txv_out *o)
{
	int a = text_lines(o->to, 60);
	return (a > 2 ? 2 : a) * LINE + text_lines(o->amount, amount_chunk(o)) * LINE + 4;
}

/* the length of the line of a text at offset o: 60 bytes, not cut in the middle of a character (what wrapped() draws) */
static size_t text_line(size_t o, size_t n)
{
	size_t l = n - o < 60 ? n - o : 60;
	while (o + l < n && l > 1 && ((uint8_t) msg_text[o + l] & 0xC0) == 0x80) l--;
	return l;
}

/* pages: the summary, then as many outputs a page as fit, then the pages of a long text */
static void view_paginate(void)
{
	int y = VIEW_TOP, p = 0;
	size_t o = 0, n = (size_t) view.text_len;

	vfirst[0] = 0;
	for (int i = 0; i < view.nout; i++) {
		int h = out_height(&view.out[i]);
		if (y + h > VIEW_END && i > vfirst[p]) { vfirst[++p] = (uint8_t) i; y = VIEW_TOP; }
		y += h;
	}
	vfirst[p + 1] = (uint8_t) view.nout;
	vout_pages = view.nout ? p + 1 : 0;
	ntp = 0;
	while (o < n && ntp < TEXT_PAGES_MAX) {
		tpage[ntp++] = (uint16_t) o;
		for (int l = 0; l < TEXT_LINES && o < n; l++) o += text_line(o, n);
	}
	vnpages = 1 + vout_pages + ntp;
}

static void draw_view(void)
{
	char line[100];
	int y = VIEW_TOP;

	sprintf(line, "%.30s  %d/%d", view.title, vpage + 1, vnpages);
	text(16, UI_TOP, line);
	if (vpage == 0) {
		struct { uint32_t f; const char *t; int red; } W[] = {
			{TXW_BLIND, T(TXT_BLIND_THIS_CANNOT_BE_CHECKED), 1},
			{TXW_NOT_MINE, T(TXT_NO_KEY_OF_THIS_SEED_FITS_THIS), 1},
			{TXW_HIGH_FEE, T(TXT_THE_FEE_IS_HIGH), 1},
			{TXW_NO_FEE, T(TXT_THE_FEE_CANNOT_BE_TOLD), 0},
			{TXW_UNKNOWN_SCRIPT, T(TXT_AN_OUTPUT_SCRIPT_IS_NOT_KNOWN), 0},
			{TXW_NONSTD_SIGHASH, T(TXT_UNUSUAL_SIGNATURE_TYPE), 1},
			{TXW_DELEGATION, T(TXT_DELEGATES_CONTROL_OF_AN), 1},
			{TXW_UNREG_MULTISIG, T(TXT_MULTISIG_OF_A_WALLET_NOT), 1},
			{TXW_DATA, T(TXT_IT_CONTAINS_DATA_OR_A_CONTRACT), 0},
			{TXW_UNVERIFIED, T(TXT_SOME_DATA_COULD_NOT_BE), 0},
			{TXW_TRUNCATED, T(TXT_THERE_ARE_MORE_OUTPUTS_THAN), 0},
		};
		if (view.total[0]) { sprintf(line, T(TXT_SENDS_N), view.total); text(16, y, line); y += LINE; }
		if (view.fee[0]) { sprintf(line, T(TXT_FEE_N), view.fee); text(16, y, line); y += LINE; }
		if (view.nout || !view.text_len) {
			sprintf(line, TN(view.nout + view.nmore, TXT_COUNT_OUTPUT_ONE, TXT_COUNT_OUTPUT_MANY), view.nout + view.nmore);
			dim(16, y, line);
			y += LINE;
		}
		for (unsigned i = 0; i < sizeof W / sizeof W[0] && y < 150; i++)
			if (view.warn & W[i].f) { ctext(16, y, W[i].t, 255, W[i].red ? 90 : 190, W[i].red ? 90 : 60); y += LINE; }
		for (int i = 0; i < view.nnote && y + 2 * LINE <= UI_HINT2 - 4; i++) y += wrapped(16, y, view.note[i], 60, 2, 150, 160, 200) * LINE;        /* an npub in a note is 63 characters: never cut */
	} else if (vpage > vout_pages) {                                          /* the text pages: the whole text, 60 characters a line */
		wrapped(16, VIEW_TOP, msg_text + tpage[vpage - 1 - vout_pages], 60, TEXT_LINES, 255, 255, 255);
	} else {
		for (int i = vfirst[vpage - 1]; i < vfirst[vpage]; i++) {
			const txv_out *o = &view.out[i];
			int n = wrapped(16, y, o->to, 60, 2, 255, 255, 255);
			y += n * LINE;
			if (o->mine) ctext(16, y, T(TXT_CHANGE), 150, 160, 200);
			y += wrapped(16 + (o->mine ? 90 : 0), y, o->amount, amount_chunk(o), 3, UI_SEL_RGB) * LINE + 4;
		}
	}
	if (hold > 0) {
		int need = (view.warn & (TXW_BLIND | TXW_DELEGATION)) ? HOLD_BLIND : HOLD_NORMAL;
		gpu_draw_rect(&ctx, 2, 16, UI_HINT2 + 4, 300, 10, 30, 30, 50);
		gpu_draw_rect(&ctx, 1, 16, UI_HINT2 + 4, 300 * (hold > need ? need : hold) / need, 10, 90, 220, 90);
		dim(330, UI_HINT2, T(TXT_KEEP_HOLDING_TO_SIGN));
	} else {
		dim(16, UI_HINT2, T(TXT_HINT_PAGE_HOLD_TO_SIGN_CANCEL));
	}
}

/* ---- the result ---- */

static void hex_of(char *out, size_t cap, const uint8_t *d, size_t n)
{
	static const char D[] = "0123456789abcdef";
	size_t o = 0;
	for (size_t i = 0; i < n && o + 3 < cap; i++) {
		if (i && i % 4 == 0) out[o++] = ' ';
		out[o++] = D[d[i] >> 4];
		out[o++] = D[d[i] & 15];
	}
	out[o] = 0;
}

static void show_part(void)
{
	qr_ok = 0;
	if (ur_part(&urp, res.buf, (unsigned) ur_seq, urtxt, sizeof urtxt) > 0 && qr_encode(&qr, (const uint8_t *) urtxt, strlen(urtxt), QR_ECC_L) > 0) {
		qr_ok = 1;
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	}
}

/* one QR code with the whole result if it fits (text, or base64), else the animated UR */
static void prepare_output(void)
{
	const uint8_t *data = res.text ? res.buf : (const uint8_t *) b64txt;
	size_t n = res.len;

	if (!res.text) {
		if (res.len <= 200) { b64_encode(res.buf, res.len, b64txt, sizeof b64txt); n = strlen(b64txt); }
		else n = QR_CAP + 1;                                 /* too long for one code: the UR animation */
	}
		ur_plan_make(&urp, res.buf, res.len, UR_FRAG);
	out_page = 0;
	out_scroll = 0;
	out_ur = 0;
	qr_ok = 0;
	if (n <= QR_CAP && qr_encode(&qr, data, n, QR_ECC_L) > 0) {
		qr_ok = 1;
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	} else {
		out_ur = 1;
		ur_seq = 1;
		ur_tick = 0;
		show_part();
	}
	msg[0] = 0;
}

static void save_result(void)
{
	mcf_entry e[1];
	uint8_t f[MC_FRAME];
	int nfiles, next, blk, r;
	size_t o = 0, total = res.len + 4;
	int frame = MCF_FIRST_DATA;

	r = mcf_scan(1, RES_TAG, e, 0, &nfiles, &next, &blk);
	if (r == MCF_OK && !blk) r = MCF_FULL;
	if (r == MCF_OK && total > 62 * MC_FRAME) r = MCF_FULL;
	if (r == MCF_OK) r = mcf_begin(1, blk, "PSXX signature", MCF_ICON_LOCK);
	while (r == MCF_OK && o < total) {
		size_t k;
		memset(f, 0, sizeof f);
		for (k = 0; k < MC_FRAME && o + k < total; k++) {
			size_t at = o + k;
			f[k] = at < 4 ? (uint8_t) (res.len >> (8 * at)) : res.buf[at - 4];
		}
		r = mcf_write(1, blk, frame++, f);
		o += MC_FRAME;
	}
	if (r == MCF_OK) r = mcf_commit(1, blk, RES_TAG, next);
	if (r == MCF_OK) sprintf(msg, T(TXT_SAVED_AS_N), RES_TAG, next);
	else sprintf(msg, T(TXT_NOT_SAVED_N), card_error(r));
}

static void draw_out(void)
{
	const int tx = 16 + 2 * 190 + 12;
	char line[96];
	int y = 26;

	if (out_page == 0) {
		text(16, UI_TOP, res.label);
		if (qr_ok) qr_view_draw(&ctx, 12, 16, 26, &qr, qr_scale);
		if (out_ur && urp.parts > 1) sprintf(line, T(TXT_UR_CODE_N_OF_N), ur_seq, urp.parts);
		else if (out_ur) sprintf(line, T(TXT_UR_ONE_CODE));
		else sprintf(line, T(TXT_ONE_QR_CODE));
		ctext(tx, y, line, UI_SEL_RGB);
		sprintf(line, T(TXT_N_BYTES_2), (unsigned) res.len);
		dim(tx, y += LINE, line);
		if (out_ur && urp.parts > 1) { sprintf(line, T(TXT_N_CODES_N_S), urp.parts, 60 / ur_fpp, (600 / ur_fpp) % 10); dim(tx, y += LINE, line); }
		if (msg[0]) wrapped(tx, y += LINE, msg, 22, 2, UI_SEL_RGB);         /* the column holds 22 characters: two lines down to 124 */
		dim(tx, 130, T(TXT_HINT_SAVE_TO_CARD_2));
		if (out_ur && urp.parts > 1) dim(tx, 152, T(TXT_HINT_SPEED));
		dim(tx, UI_HINT2, T(TXT_HINT_HEX_DONE));
	} else {
		const size_t per = 20, nl = 6;                   /* bytes a line, lines a page (the primitive buffer holds about 300 glyphs a frame) */
		size_t pages = (res.len + per * nl - 1) / (per * nl), first = (size_t) out_scroll * per * nl, last = first + per * nl < res.len ? first + per * nl : res.len;
		text(16, UI_TOP, T(TXT_RESULT_IN_HEX));
		if ((size_t) out_scroll >= pages) out_scroll = 0;
		first = (size_t) out_scroll * per * nl;
		last = first + per * nl < res.len ? first + per * nl : res.len;
		for (size_t l = 0; first + l * per < last; l++) {
			size_t o = first + l * per, n = last - o < per ? last - o : per;
			char hl[64];
			hex_of(hl, sizeof hl, res.buf + o, n);
			text(16, 26 + (int) l * LINE, hl);
		}
		sprintf(line, T(TXT_BYTES_N_OF_N), (unsigned) first + 1, (unsigned) last, (unsigned) res.len);
		dim(16, 160, line);
		dim(16, UI_HINT2, T(TXT_HINT_SCROLL_BACK));
	}
}

static void wipe_request(void)
{
	xmr_tx_forget();
	secure_zero(req_buf, sizeof req_buf);
	secure_zero(res_buf, sizeof res_buf);
	secure_zero(msg_text, sizeof msg_text);
	secure_zero(&view, sizeof view);
	secure_zero(fb_buf, sizeof fb_buf);
	secure_zero(b64txt, sizeof b64txt);
	qr_view_clear();
	qr_ok = 0;
	req_len = 0;
}

static void do_sign(void)
{
	int e;
	if (req.chain->kind == K_MONERO) show_status(T(TXT_SIGNING), T(TXT_ABOUT_15_SECONDS_FOR_EVERY));
	else show_status(T(TXT_SIGNING), T(TXT_A_FEW_SECONDS));
	res.buf = res_buf; res.cap = RES_MAX;
	res.scratch = (uint8_t *) fb_buf; res.scap = sizeof fb_buf;
	prof_mark(T(TXT_SIGN_START));
	e = sign_execute(&req, &hs, &res);
	prof_mark(T(TXT_SIGN_DONE));
	secure_zero(fb_buf, sizeof fb_buf);
	if (e) { secure_zero(res_buf, sizeof res_buf); error_screen(sign_error_text(e)); return; }
	prepare_output();
	state = S_OUT;
}

/* ---- the frame ---- */

static uint16_t repeat_updown(uint16_t pr)
{
	static uint16_t btn;
	static int cnt, last_state = -1;
	int lists = state == S_HOME || state == S_EXTRAS || state == S_TE_MENU || state == S_TE_VIEW || state == S_NOTES || state == S_SRC || state == S_LIST || state == S_RESTOPT || state == S_KEY_LIST || state == S_VAN_KIND || state == S_MS_LIST || state == S_KM_MENU || state == S_RK_KIND || state == S_KE_LIST;

	if ((int) state != last_state) { last_state = (int) state; btn = 0; }
	if (btn && (!lists || !(in.ps.buttons & btn))) btn = 0;
	if (lists && (pr & (PAD_UP | PAD_DOWN))) { btn = (pr & PAD_UP) ? PAD_UP : PAD_DOWN; cnt = 0; return pr; }
	if (btn && ++cnt >= 22 && (cnt - 22) % 3 == 0) pr |= btn;
	return pr;
}

static int kb_step(uint16_t pr)
{
	kb.held = in.ps.buttons;
	return kb_update(&kb, pr);
}

#ifdef SIGNER_KEYS
#include "signer_vanity.h"
#include "signer_ms.h"
#include "signer_keys.h"
#endif

static void update(uint16_t pr)
{
	switch (state) {
	case S_BOOT: {                                      /* the tables of the two curves, a few milliseconds per frame */
		int a = secp256k1_table_step();
		int b = a >= 100 ? ed25519_table_step() : 0;
		boot_p = (a + b) / 2;
		if (a >= 100 && b >= 100) { state = S_HOME; tables_ready = 1; take_handoff(); }
		break;
	}
	case S_EXTRAS:
		ui_nav(&esel, 4, pr);
#ifdef SIGNER_OVERLAY
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) leave = 1;                 /* back to the generator's menu (ovl_main returns, the loader wipes the bss) */
#endif
		if (pr & PAD_CROSS) {
			if (esel == 1) { tsel = 0; state = S_TE_MENU; }
			else if (esel == 2) { nt_top = 0; state = S_NOTES; }
			else state = esel == 0 ? (tables_ready ? S_HOME : S_BOOT) : S_CDP;
		}
		break;
	case S_CDP:
		if (pr & (PAD_CROSS | PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) state = S_EXTRAS;
		break;
	case S_TE_MENU:
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_EXTRAS; break; }
		ui_nav(&tsel, 3, pr);
		if (pr & PAD_CROSS) {
			if (tsel == 0) { kb_init(&kb, T(TXT_TEXT_UTF_8_2), NULL, 0, 1); kb_set(&kb, TE_MAX, 0); state = S_TE_TEXT; }
			else if (tsel == 1) { kb_init(&kb, T(TXT_BYTES_IN_HEX), NULL, 0, 0); kb_set(&kb, 2 * TE_MAX, 1); state = S_TE_HEX; }
			else state = S_TE_BRAILLE;
		}
		break;
	case S_TE_TEXT: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_TE_MENU; }
		else if (r == KB_DONE) {
			te_raw_len = kb.len < TE_MAX ? kb.len : TE_MAX;
			memcpy(te_raw, kb.text, (size_t) te_raw_len);
			kb_wipe(&kb);
			te_open(1);
		}
		break;
	}
	case S_TE_HEX: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_TE_MENU; }
		else if (r == KB_DONE) {
			te_raw_len = 0;
			for (int i = 0; i + 1 < kb.len && te_raw_len < TE_MAX; i += 2) {
				int hi = kb.text[i] <= '9' ? kb.text[i] - '0' : kb.text[i] - 'a' + 10, lo = kb.text[i + 1] <= '9' ? kb.text[i + 1] - '0' : kb.text[i + 1] - 'a' + 10;
				te_raw[te_raw_len++] = (uint8_t) (hi * 16 + lo);
			}
			kb_wipe(&kb);
			te_open(0);
		}
		break;
	}
	case S_TE_VIEW: {
		uint8_t b[TE_MAX];
		int bad, nchars, n = te_bytes(b, &bad, &nchars);
		if (pr & (PAD_TRIANGLE | PAD_SELECT | PAD_CIRCLE)) { state = S_TE_MENU; break; }
		if (pr & (PAD_LEFT | PAD_RIGHT)) { te_ascii ^= 1; te_top = 0; }
		if ((pr & PAD_DOWN) && te_top + TE_ROW_BYTES < n) te_top += TE_ROW_BYTES;
		if ((pr & PAD_UP) && te_top >= TE_ROW_BYTES) te_top -= TE_ROW_BYTES;
		break;
	}
	case S_TE_BRAILLE:
		if (pr & (PAD_CROSS | PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) state = S_TE_MENU;
		break;
	case S_NOTES:
		if (pr & (PAD_TRIANGLE | PAD_SELECT | PAD_CIRCLE)) { state = S_EXTRAS; break; }
		if ((pr & PAD_DOWN) && nt_top + NOTE_ROWS < NOTE_COUNT) nt_top++;
		if ((pr & PAD_UP) && nt_top > 0) nt_top--;
		break;
	case S_HOME:
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_EXTRAS; break; }
		ui_nav(&hsel, HOME_N, pr);
		if (pr & PAD_CROSS) {
			if (hsel == 2) { forget(); break; }
#ifdef SIGNER_KEYS
			if (hsel == 3) { ks_forget_key(); kmsel = 0; state = S_KM_MENU; break; }
			if (hsel == 4) { vsel = vtop = 0; state = S_VAN_KIND; break; }
			if (hsel == 5) {
				if (!hs_valid || hs.no_bip) { error_screen(T(TXT_LOAD_YOUR_SEED_FIRST_LOAD)); break; }
				ms_msg[0] = 0; ms_scan(1); state = S_MS_LIST; break;
			}
			if (hsel == 6) {                                                         /* the address pages of the main card, for the seed that is loaded */
				if ((hs_valid && !hs.no_bip) || hs.xmr_ok) { addr_modal(&hs, hs_pass); gpu_init(&ctx, 20, 20, 60); }
				else error_screen(hs.raw_curve ? T(TXT_A_RAW_KEY_HAS_ONE_ADDRESS_ONLY) : T(TXT_LOAD_YOUR_SEED_FIRST));
				break;
			}
#endif
			if (hsel == 0 && hs_valid) { ssel = 0; state = S_SRC; }
			else { ropt_row = 0; msg[0] = 0; state = S_RESTOPT; }
		}
		break;
	case S_RESTOPT:
		if ((pr & (PAD_DOWN | PAD_UP)) && rest_nw != 5) ropt_row ^= 1;
		if (pr & (PAD_LEFT | PAD_RIGHT)) {
			if (ropt_row == 0 || rest_nw == 5) { rest_nw = (rest_nw + ((pr & PAD_RIGHT) ? 1 : 5)) % 6; ropt_row = 0; }
			else rest_pp ^= 1;
		}
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) state = S_HOME;
		if (pr & PAD_CROSS) { rest_xmr = rest_nw == 5; rest_goal = rest_xmr ? 25 : 12 + 3 * rest_nw; rest_kb(); msg[0] = 0; state = S_REST; }
		break;
	case S_REST: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); secure_zero(mnemonic, sizeof mnemonic); msg[0] = 0; state = S_HOME; }
		else if (r == KB_DONE) {
			uint8_t ent[32];
			int n;
			if (rest_xmr) { if (rest_parse_xmr()) rest_len = kb.len; break; }
			n = rest_parse(ent);
			if (n < 0) rest_len = kb.len;
			else {
				memcpy(hs.entropy, ent, (size_t) n);
				hs.entlen = n;
				secure_zero(ent, sizeof ent);
				kb_wipe(&kb);
				kb_init(&kb, T(TXT_PASSPHRASE_EMPTY_NONE), NULL, 1, 0);
				if (rest_pp) state = S_REST_PASS;
				else restore_derive();
			}
		}
		break;
	}
	case S_REST_PASS: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); secure_zero(mnemonic, sizeof mnemonic); from_card = 0; state = S_HOME; }
		else if (r == KB_DONE) restore_derive();
		break;
	}
	case S_SRC:
		ui_nav(&ssel, 2, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_HOME; break; }
		if (pr & PAD_CROSS) {
			if (ssel == 0) { scan_requests(); msg[0] = 0; state = S_LIST; }
			else { kb_init(&kb, T(TXT_REQUEST_IN_HEX), NULL, 0, 0); kb_set(&kb, 2 * REQ_MAX, 1); state = S_HEX; }
		}
		break;
	case S_LIST:
		ui_wrap(&rsel, rn, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_SRC; break; }
		if ((pr & PAD_CROSS) && rn > 0) {
			int r = load_request(rlist[rsel].block);
			if (r) { sprintf(msg, T(TXT_CANNOT_READ_IT_N), card_error(r)); break; }
			open_request();
		}
		break;
	case S_HEX: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_SRC; }
		else if (r == KB_DONE) {
			size_t n = 0;
			for (int i = 0; i + 1 < kb.len && n < REQ_MAX; i += 2) {
				int hi = kb.text[i] <= '9' ? kb.text[i] - '0' : kb.text[i] - 'a' + 10, lo = kb.text[i + 1] <= '9' ? kb.text[i + 1] - '0' : kb.text[i + 1] - 'a' + 10;
				req_buf[n++] = (uint8_t) (hi * 16 + lo);
			}
			req_len = n;
			kb_wipe(&kb);
			open_request();
		}
		break;
	}
	case S_VIEW: {
		int need = (view.warn & (TXW_BLIND | TXW_DELEGATION)) ? HOLD_BLIND : HOLD_NORMAL;
		if ((pr & PAD_RIGHT) && vpage < vnpages - 1) vpage++;
		if ((pr & PAD_LEFT) && vpage > 0) vpage--;
		if (pr & (PAD_CIRCLE | PAD_SELECT | PAD_TRIANGLE)) { wipe_request(); state = S_SRC; break; }
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= need) { hold = 0; armed = 0; do_sign(); }
		break;
	}
	case S_OUT:
		if (pr & PAD_TRIANGLE) {
			if (out_page) { out_page = 0; if (out_ur) show_part(); }       /* from the hex page back to the QR code */
			else { wipe_request(); state = S_SRC; }
			break;
		}
		if (pr & PAD_R2) { out_page ^= 1; if (!out_page && out_ur) show_part(); }
		if (out_page) {
			if ((pr & PAD_DOWN) && (size_t) (out_scroll + 1) * 120 < res.len) out_scroll++;
			if ((pr & PAD_UP) && out_scroll > 0) out_scroll--;
			break;
		}
		if (pr & PAD_CROSS) save_result();
		if (pr & PAD_L1) { ur_fpp += 3; if (ur_fpp > 45) ur_fpp = 45; }
		if (pr & PAD_R1) { ur_fpp -= 3; if (ur_fpp < 3) ur_fpp = 3; }
		if (out_ur && urp.parts > 1 && ++ur_tick >= ur_fpp) { ur_tick = 0; ur_seq = ur_seq % (int) urp.parts + 1; show_part(); }
		break;
#ifdef SIGNER_KEYS
	case S_KEY_LIST: {
		ui_wrap(&ks_sel, ks_total, pr);
		if (ks_sel < ks_top) ks_top = ks_sel;
		if (ks_sel >= ks_top + KEY_ROWS) ks_top = ks_sel - KEY_ROWS + 1;
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { msg[0] = 0; ks_forget_key(); kd_mode = 0; state = S_KM_MENU; break; }
		if (kd_mode) {                                                           /* Delete keys: X marks, START goes on */
			if ((pr & PAD_CROSS) && ks_total > 0) { ks_locate(ks_sel, &ks_store, &ks_key); kd_mark[ks_store][ks_key] ^= 1; msg[0] = 0; }
			if (pr & PAD_START) {
				if (!kd_count()) sprintf(msg, T(TXT_MARK_AT_LEAST_ONE_KEY_FIRST));
				else { hold = 0; armed = 0; msg[0] = 0; state = S_KD_CONFIRM; }
			}
			break;
		}
		if ((pr & PAD_CROSS) && ks_total > 0) key_open();
		if ((pr & PAD_SQUARE) && ks_total > 0) { ks_locate(ks_sel, &ks_store, &ks_key); ks_slot = ks_live_slot(&ks_st.st[ks_store].dir, ks_key); hold = 0; armed = 0; msg[0] = 0; state = S_KEY_DEL; }
		break;
	}
	case S_KEY_PW: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); secure_zero(ks_img, sizeof ks_img); state = S_KEY_LIST; }
		else if (r == KB_DONE) {
			if (ks_pw_for == 0) key_decrypt();
			else if (!store_unlock()) ks_ask(T(TXT_WRONG_PASSWORD_OR_DAMAGED_KEY));
			else if (ks_pw_for == 1) key_decrypt();
			else if (ks_pw_for == 3) kd_run();
			else key_delete_do();
		}
		break;
	}
	case S_KEY_CONFIRM:
		if (pr & PAD_CROSS) { from_card = 0; rk_pending = rk_show = 0; msg[0] = 0; ssel = 0; state = S_SRC; }
		else if (rk_pending && (pr & PAD_SQUARE)) rk_save();
		else if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { forget(); state = S_HOME; }
		break;
	case S_KEY_DEL:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { state = S_KEY_LIST; break; }
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= HOLD_NORMAL) { hold = 0; armed = 0; key_delete(); }
		break;
#endif
#ifdef SIGNER_KEYS
	case S_VAN_KIND: case S_VAN_DEP: case S_VAN_INIT: case S_VAN_PRE: case S_VAN_SUF: case S_VAN_PLAN: case S_VAN_ENT: case S_VAN_RUN: case S_VAN_DONE:
			van_update(pr);
		break;
	case S_MS_LIST: case S_MS_CONFIRM: case S_MS_DEL:
		ms_update(pr);
		break;
	case S_KM_MENU: case S_RK_KIND: case S_RK_TEXT: case S_KD_CONFIRM: case S_KE_LIST: case S_KE_CONFIRM:
		km_update(pr);
		break;
#endif
	case S_ERR:
		if (pr & (PAD_CROSS | PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { msg[0] = 0; state = hs_valid ? S_SRC : S_HOME; }
		break;
	}
}

static void draw(void)
{
	char line[64];
	switch (state) {
	case S_BOOT: {
		text(16, UI_TOP, T(TXT_PSX_SIGNER));
		dim(16, 60, T(TXT_PREPARING_THE_TABLES_OF_THE));
		gpu_draw_rect(&ctx, 3, 14, 98, 292, 22, 200, 200, 200);
		gpu_draw_rect(&ctx, 2, 16, 100, 288, 18, 30, 30, 50);
		gpu_draw_rect(&ctx, 1, 16, 100, 288 * boot_p / 100, 18, 255, 200, 60);
		sprintf(line, "%d %%", boot_p);
		dim(16, 130, line);
		break;
	}
	case S_HOME: draw_home(); break;
	case S_EXTRAS: draw_extras(); break;
	case S_TE_MENU: draw_te_menu(); break;
	case S_TE_TEXT: case S_TE_HEX: kb_draw(&ctx, &kb); break;
	case S_TE_VIEW: draw_te_view(); break;
	case S_TE_BRAILLE: draw_te_braille(); break;
	case S_NOTES: draw_notes(); break;
	case S_CDP:
		text(16, UI_TOP, T(TXT_CD_PLAYER));
		dim(16, 60, T(TXT_NOT_IMPLEMENTED_YET));
		dim(16, UI_HINT2, T(TXT_HINT_BACK_3));
		break;
	case S_RESTOPT: draw_restopt(); break;
	case S_REST: draw_rest(); break;
	case S_REST_PASS: kb_draw(&ctx, &kb); break;
	case S_SRC: draw_src(); break;
	case S_LIST: {
		text(16, UI_TOP, T(TXT_REQUESTS_ON_THE_CARD_IN_SLOT_2));
		if (rrc) { sprintf(line, T(TXT_CARD_N), card_error(rrc)); ctext(16, 34, line, 255, 100, 100); }
		else if (!rn) dim(16, 34, T(TXT_NO_REQUESTS_FILES_PSXXQ_ON_THE));
		for (int i = 0; i < rn && i < 7; i++) ui_row(16, 28 + i * LINE, i == rsel, rlist[i].name + 12);
		if (msg[0]) ctext(16, UI_MSG, msg, 255, 100, 100);                 /* below the 8th row, above the icons of the hints */
		dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_OPEN_BACK));
		break;
	}
	case S_HEX: kb_draw(&ctx, &kb); break;
	case S_VIEW: draw_view(); break;
	case S_OUT: draw_out(); break;
#ifdef SIGNER_KEYS
	case S_KEY_LIST: {
		text(16, UI_TOP, T(kd_mode ? TXT_DELETE_KEYS : TXT_KEYS_ON_THE_CARD_IN_SLOT_2));
		if (ks_rc) { sprintf(line, T(TXT_CARD_N), key_error(ks_rc)); ctext(16, 34, line, 255, 100, 100); }
		else if (!ks_total) dim(16, 34, T(TXT_NO_KEYS_ON_THE_CARD_SAVED_BY));
		for (int i = 0, e = ks_top; i < KEY_ROWS && e < ks_total; i++, e++) {
			int st, k;

			ks_locate(e, &st, &k);
			if (ks_st.st[st].single) sprintf(line, "%c %.40s", e == ks_sel ? '>' : ' ', ks_pub[st][k][0] ? ks_pub[st][k] : "?");                    /* a single key: the name it has in the list */
			else sprintf(line, T(TXT_N_STORE_N_KEY_N_2), e == ks_sel ? '>' : ' ', ks_st.st[st].dir.label, k + 1);                                         /* a key of a vault: the vault and the place in it */
			if (kd_mode && kd_mark[st][k]) line[1] = '*';
			ui_hl(16, 34 + i * LINE, e == ks_sel, line);
		}
		if (kd_mode) { sprintf(line, T(TXT_N_MARKED), kd_count()); dim(GPU_XRES - 16 - font_width(line), UI_TOP, line); }
		else if (ks_total > KEY_ROWS) { sprintf(line, "%d / %d", ks_sel + 1, ks_total); dim(GPU_XRES - 16 - 8 * 10, UI_TOP, line); }
		if (!ks_rc && ks_st.corrupt) { sprintf(line, TN(ks_st.corrupt, TXT_DAMAGED_STORE_BLOCK_NOT_USED_ONE, TXT_DAMAGED_STORE_BLOCK_NOT_USED_MANY), ks_st.corrupt); ctext(16, 34 + KEY_ROWS * LINE + 4, line, 255, 160, 80); }
		else if (msg[0]) ctext(16, 34 + KEY_ROWS * LINE + 4, msg, 255, 160, 80);
		dim(16, UI_HINT2, T(kd_mode ? TXT_HINT_CHOOSE_MARK_DELETE_BACK : TXT_HINT_CHOOSE_OPEN_DELETE_BACK));
		break;
	}
	case S_KEY_PW: kb_draw(&ctx, &kb); break;
	case S_KEY_CONFIRM:
		text(16, UI_TOP, T(TXT_IS_THIS_YOUR_KEY));
		if (rk_pending || (rk_show && ks_type == KS_TYPE_RAW)) {
			if (rk_pending) text(16, 34, T(TXT_IMPORTED_KEY));
			else {
				sprintf(line, T(TXT_LABEL_N), ks_label[0] ? ks_label : T(TXT_NONE));
				text(16, 34, line);
			}
			rk_confirm_body();
		} else {
			sprintf(line, T(TXT_LABEL_N), ks_label[0] ? ks_label : T(TXT_NONE));
			text(16, 34, line);
			if (ks_type == KS_TYPE_RAW) {
				dim(16, 60, hs.raw_curve == 1 ? T(TXT_A_RAW_ED25519_KEY_TON_WALLET) : ck_hint ? van_hint_name(ck_hint) : T(TXT_A_RAW_SECP256K1_KEY_ETHEREUM));
				wrapped(16, 82, ck_addr, 48, 3, 255, 255, 255);
			} else if (ks_type == KS_TYPE_MONERO) {
				dim(16, 60, T(TXT_MONERO_MAIN_ADDRESS));
				wrapped(16, 82, ck_addr, 48, 3, 255, 255, 255);
			} else {
				sprintf(line, T(TXT_MASTER_FINGERPRINT_N), ck_fp);
				text(16, 60, line);
				dim(16, 86, T(TXT_FIRST_BITCOIN_ADDRESS_M_84_0_0));
				wrapped(16, 108, ck_addr, 48, 2, 255, 255, 255);
			}
		}
		if (msg[0] && rk_pending) ctext(16, UI_MSG, msg, 255, 160, 80);                          /* the result of a save of a typed key */
		else dim(16, 176, T(TXT_COMPARE_IT_WITH_WHAT_YOU_KNOW));
		dim(16, UI_HINT2, T(rk_pending && rk_savable(rk_kind) ? TXT_HINT_USE_SAVE_ON_THE_CARD_WIPE : TXT_HINT_YES_USE_IT_NO_WIPE_EVERYTHING));
		break;
	case S_KEY_DEL:
		text(16, UI_TOP, T(TXT_DELETE_THIS_KEY));
		if (ks_st.st[ks_store].single) sprintf(line, "%.40s", ks_pub[ks_store][ks_key][0] ? ks_pub[ks_store][ks_key] : "?");
		else sprintf(line, T(TXT_STORE_N_KEY_N), ks_st.st[ks_store].dir.label, ks_key + 1);
		text(16, 40, line);
		dim(16, 70, T(TXT_IT_CANNOT_BE_RESTORED_FROM_THE));
		dim(16, 90, T(TXT_KEEP_THE_RECOVERY_WORDS));
		gpu_draw_rect(&ctx, 2, 16, 124, GPU_XRES - 32, 10, 30, 30, 50);
		gpu_draw_rect(&ctx, 1, 16, 124, (GPU_XRES - 32) * hold / HOLD_NORMAL, 10, 220, 60, 60);
		dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_DELETE_BACK));
		break;
#endif
#ifdef SIGNER_KEYS
	case S_VAN_KIND: case S_VAN_DEP: case S_VAN_INIT: case S_VAN_PRE: case S_VAN_SUF: case S_VAN_PLAN: case S_VAN_ENT: case S_VAN_RUN: case S_VAN_DONE:
			van_draw();
		break;
	case S_MS_LIST: case S_MS_CONFIRM: case S_MS_DEL:
		ms_draw();
		break;
	case S_KM_MENU: case S_RK_KIND: case S_RK_TEXT: case S_KD_CONFIRM: case S_KE_LIST: case S_KE_CONFIRM:
		km_draw();
		break;
#endif
	case S_ERR:
		text(16, UI_TOP, T(TXT_CANNOT_CONTINUE));
		wrapped(16, 40, msg, 58, 4, 255, 100, 100);
		dim(16, UI_HINT2, T(TXT_HINT_BACK_3));
		break;
	}
}

#ifdef SIGNER_OVERLAY
int ovl_main(void)                                                      /* M4: the signer is the overlay of the generator image */
#else
int main(void)
#endif
{
	int last_frame = -1, last_state = -1;

#ifndef SIGNER_OVERLAY
	ui_reg_a();                                                         /* a program of its own: the texts of the main card are in it, too */
#endif
	ui_reg_b();                                                         /* the texts of the signer (the overlay: the main card has made its own known) */

	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	state = psxx_handoff.valid ? S_BOOT : S_EXTRAS;                         /* a seed from the generator goes straight to the signer */
	while (!leave) {
		int f = VSync(-1);
		if (f != last_frame) {
			last_frame = f;
#ifdef SIGNER_KEYS
			input_poll(&in, state == S_VAN_ENT ? &vpool : NULL);   /* once a frame: the rest of the time goes to the table of the Sinsemilla points (or the vanity search) */
#else
			input_poll(&in, NULL);
#endif
			update(repeat_updown(input_take_pressed(&in)));
			draw();
			gpu_present(&ctx);
			if ((int) state != last_state) {
				last_state = (int) state;
				LOG("[prof] screen %s, %d s after the start, table %d of 1024\n", STATE_NAME[state], (f - tbl_start_frame) / (GetVideoMode() == MODE_PAL ? 50 : 60), pl_stable_built());
			}
		} else if (idle_state()) {                                           /* the rest of the frame: the table of the Sinsemilla points, then the constants */
#ifdef SIGNER_KEYS
			if (state == S_VAN_RUN) van_idle();
			else
#endif
			if (pl_stable_built() < 1024) tbl_step();
			else if (warm_left && f != warm_frame && f - tbl_start_frame > 0) {
				warm_frame = f + 60;                                    /* one constant (about 0.1 s) a second at most */
				warm_left = orchard_warm_constants();
				LOG("[prof] Orchard constants: %d left, %d s after the start\n", warm_left, (f - tbl_start_frame) / (GetVideoMode() == MODE_PAL ? 50 : 60));
			}
		}
	}
	return 0;
}
