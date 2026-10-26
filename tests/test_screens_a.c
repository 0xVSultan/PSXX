/* The screens of the main card (hal/psx/wallet_app.c, with the keyboard, the loader screens and the QR view) on the host, checked for their layout (tests/layout_check.h):
 * every screen is drawn in the states that change what it shows (a menu with every item selected, the longest messages, a wallet made from fixed entropy so that the words,
 * addresses and QR codes have their real lengths), on a 240 and a 256 line picture, and every frame must have no overlapping texts and stay in the safe area.
 * The program is compiled into this file with stand-ins for the console (tests/langui_stub: gpu.h, psxgpu.h; tests/screen_stubs.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "layout_check.h"

#define main wallet_main
#include "wallet_app.c"
#undef main
#include "source_ui.c"                                 /* the loader screens, with their statics (the reading screen) */

/* ---- the console, as far as the screens see it ---- */

const psxx_release psxx_release_info = {{'P', 'S', 'X', 'X', 'R', 'E', 'L', '1'}, {1}, {1}, {1}, {0}};
const lang_api *psxx_lang;
extern int screen_yres;                                   /* tests/screen_stubs.c: the GPU, the font, the controller */
static int resident_signer, resident_lang;

void coin_init(void) {}
void coin_draw(RenderContext *c, int z, int cx, int cy, int w, int side, int bright) { (void) c; (void) z; (void) side; (void) bright; lc_pic(cx - w / 2, cy - COIN_DRAW_H / 2, w, COIN_DRAW_H, "coin"); }
void coin_shadow(RenderContext *c, int z, int cx, int gy, int lift) { (void) c; (void) z; (void) cx; (void) gy; (void) lift; }
void coin_flip_frame(int step, int steps, int start, int height, int *w, int *dy, int *side) { (void) step; (void) steps; (void) height; *w = COIN_DRAW_W; *dy = 0; *side = start; }
void dice_init(void) {}
void dice_draw(RenderContext *c, int z, int x, int y, int w, int h, int face) { (void) c; (void) z; (void) face; lc_pic(x, y, w, h, "dice"); }
static int cd_result = CD_OK;
int cd_open(cd_disc *d) { memset(d, 0, sizeof *d); d->leadout = 333000; d->first = 1; d->last = 12; return cd_result; }
int cd_seek(uint32_t s, cd_seek_result *r) { (void) s; memset(r, 0, sizeof *r); return CD_OK; }
int cdlog_open(const cd_disc *d, uint32_t f, uint32_t cap) { (void) d; (void) f; (void) cap; return CDLOG_OK; }
int cdlog_add(const cdlog_rec *r) { (void) r; return CDLOG_OK; }
int cdlog_count(void) { return 123; }
void cdview_init(uint32_t leadout) { (void) leadout; }
void cdview_step(void) {}
void cdview_draw(RenderContext *c, int x, int y) { (void) c; lc_pic(x, y, 2 * CDV_TEX, CDV_TEX, "disc"); }
uint32_t cdview_target(void) { return 0; }
void cdview_pos(uint16_t *r, uint16_t *a) { *r = 0; *a = 0; }
uint32_t cdview_capacity(void) { return 359849; }
uint32_t cdview_used(void) { return 123456; }

int mcf_scan(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block) { (void) port; (void) tag; (void) out; (void) max; *nfiles = 0; *next = 0; *free_block = 0; return MCF_NO_CARD; }
int mcf_begin(int port, int block, const char *title, int icon) { (void) port; (void) block; (void) title; (void) icon; return MCF_NO_CARD; }
int mcf_write(int port, int block, int frame, const uint8_t *data) { (void) port; (void) block; (void) frame; (void) data; return MCF_NO_CARD; }
int mcf_read(int port, int block, int frame, uint8_t *data) { (void) port; (void) block; (void) frame; (void) data; return MCF_NO_CARD; }
int mcf_commit(int port, int block, const char *tag, int number) { (void) port; (void) block; (void) tag; (void) number; return MCF_NO_CARD; }
void mcf_name(char out[MCF_NAME], const char *tag, int number) { snprintf(out, MCF_NAME, "BESCES-00000%s%02d", tag, number); }
int ksd_scan(int port, ksd_state *s, int clean) { (void) port; (void) clean; memset(s, 0, sizeof *s); return MCF_NO_CARD; }
int ksd_create(int port, ksd_state *s, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id_hint, uint8_t work[KS_DATA], int *store)
{ (void) port; (void) s; (void) label; (void) pw; (void) key; (void) id_hint; (void) work; (void) store; return MCF_NO_CARD; }
int ksd_add(int port, ksd_state *s, int store, const uint8_t entry[KS_FRAME], const uint8_t key[32], uint8_t work[KS_DATA])
{ (void) port; (void) s; (void) store; (void) entry; (void) key; (void) work; return MCF_NO_CARD; }
int ksd_remove_store(int port, ksd_state *s, int store) { (void) port; (void) s; (void) store; return MCF_NO_CARD; }
int ksd_make_block(int port, ksd_state *s, int single, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id, const uint8_t *entry, int nf, uint8_t work[KS_DATA], int *store)
{ (void) port; (void) s; (void) single; (void) label; (void) pw; (void) key; (void) id; (void) entry; (void) nf; (void) work; (void) store; return MCF_NO_CARD; }
uint16_t ksd_free_id(const ksd_state *s, uint16_t hint) { (void) s; return hint; }
int ksd_new_single(int port, ksd_state *s, const uint8_t *entry, int nf, uint16_t id_hint, uint8_t work[KS_DATA], int *store) { (void) port; (void) s; (void) entry; (void) nf; (void) id_hint; (void) work; (void) store; return MCF_NO_CARD; }
int ksd_single_title(int port, const ksd_state *s) { (void) port; (void) s; return MCF_NO_CARD; }

void cw_init(cw *c, int hz, const char *name, int kind, const uint8_t pin[32]) { (void) hz; (void) name; (void) kind; (void) pin; memset(c, 0, sizeof *c); }
void cw_begin(cw *c, int frame, int ms) { (void) c; (void) frame; (void) ms; }
void cw_tick(cw *c, int frame) { (void) c; (void) frame; }
void cw_refresh(cw *c, int frame) { (void) c; (void) frame; }
static int slot_ok[2] = {0, 1};
static const char *slot_text[2] = {"FreePSXBoot card, not a package", "package a4ceecfa, this release"};
int cw_ok(const cw *c, int port) { (void) c; return slot_ok[port]; }
void cw_text(const cw *c, int port, char *buf, size_t n) { (void) c; snprintf(buf, n, "%s", slot_text[port]); }

static ldr_overlay fake_overlay;
int ldr_open(ldr_pkg *p, int port, const char *name, int kind, const uint8_t pin[32], int *detail) { (void) p; (void) port; (void) name; (void) kind; (void) pin; *detail = 0; return -1; }
int ldr_slot_of(uint16_t g) { return g == LDR_GROUP_LANG ? LDR_SLOT_LANG : LDR_SLOT_SIGNER; }
const ldr_overlay *ldr_resident(int slot) { return (slot == LDR_SLOT_SIGNER ? resident_signer : resident_lang) ? &fake_overlay : NULL; }
int ldr_load_overlay(ldr_pkg *p, uint16_t g, const uint8_t b[32], ldr_overlay *ov, int *detail) { (void) p; (void) g; (void) b; (void) ov; *detail = 0; return -1; }
int ldr_check_group(ldr_pkg *p, uint16_t g, uint32_t *bytes, int *detail) { (void) p; (void) g; *bytes = 0; *detail = 0; return -1; }
int ldr_call(const ldr_overlay *ov) { (void) ov; return 0; }
int ldr_call_args(const ldr_overlay *ov, void *a, void *b, int c) { (void) ov; (void) a; (void) b; (void) c; return 0; }
void ldr_set_progress(ldr_progress_fn fn, void *user) { (void) fn; (void) user; }
int ldr_cancelled(void) { return 0; }
void ldr_forget_slot(int slot) { (void) slot; }
void ldr_scrub(void) {}
int ldr_scan(int port, dirscan *d, int *detail) { (void) port; (void) d; *detail = 0; return -1; }
const char *ldr_describe(int code, int detail) { (void) code; (void) detail; return "the package is not the one this card was built with"; }

/* ---- the screens ---- */

static void shot(const char *name)
{
	draw();
	lc_frame(name, screen_yres);
}

static void flush(const char *name) { lc_frame(name, screen_yres); }      /* what a step drew by itself (a status screen) */

static const char LONG_MSG[] = "Card in slot 2: the card was taken out while it was written";

static void menus(void)
{
	static const lang_api fake_lang = {NULL, NULL, NULL, NULL, NULL, "Chinese (simp.)", 8};

	state = S_HOME;
	for (int v = 0; v < 4; v++) {
		resident_signer = resident_lang = v & 1;
		psxx_lang = (v & 2) ? &fake_lang : NULL;
		snprintf(sig_msg, sizeof sig_msg, "%s", v == 3 ? "Signer: the package is not the one this card was built" : "");
		for (hsel = 0; hsel < HOME_N; hsel++) shot("home");
	}
	psxx_lang = NULL; sig_msg[0] = 0;
	for (tip = 0; tip < TIP_COUNT; tip++)
		for (hsel = 0; hsel < HOME_N; hsel += HOME_N - 1) shot("home with a tip");
	tip = -1; hsel = 0;
	state = S_ENCMENU;
	for (esel = 0; esel < 2; esel++) shot("encryption menu");
	state = S_RESTOPT;
	for (rest_kind = 0; rest_kind < 4; rest_kind++)
		for (ropt_row = 0; ropt_row < 2; ropt_row++) shot("restore options");
	rest_kind = 0;
	state = S_RAW_CURVE;
	for (raw_sel = 0; raw_sel < 2; raw_sel++) { snprintf(msg, sizeof msg, "%s", raw_sel ? "Not a valid secp256k1 key (0 or >= n)" : ""); shot("raw key curve"); }
	msg[0] = 0;
	state = S_TYPE;
	for (failed = 0; failed < 2; failed++)
		for (tsel = 0; tsel < 3; tsel++) shot("what to create");
	failed = 0;
	state = S_TYPE2;
	for (t2sel = 0; t2sel < 3; t2sel++) shot("BIP39 options");
	state = S_ENC_KIND;
	for (enc_hex = 0; enc_hex < 2; enc_hex++) shot("encrypt: input kind");
	enc_hex = 0;
	state = S_PW_CHOOSE;
	for (pw_for = 0; pw_for < 2; pw_for++)
		for (pw_sel = 0; pw_sel < 3; pw_sel++) shot("password choice");
}

static void entropy_screens(void)
{
	state = S_SOURCE;
	for (int v = 0; v < 3; v++) {
		entropy_init(&pool, 0);
		failed = v == 2;
		if (v == 1) { pool.credit = UNITS(300); coin_units = UNITS(120); dice_units = UNITS(100); }
		for (srcsel = 0; srcsel < NSOURCES; srcsel++) { hold = srcsel == 1 ? HOLD_FRAMES / 2 : 0; shot("entropy sources"); }
	}
	failed = 0; hold = 0;
	state = S_COLLECT;
	entropy_init(&pool, 0); shot("entropy: joystick");
	pool.credit = UNITS(300); shot("entropy: joystick");
	state = S_COIN;
	entropy_init(&pool, 0); nflips = 0; shot("coin flips");
	nflips = MAX_FLIPS; for (int i = 0; i < nflips; i++) flips[i] = (uint8_t) (i & 1); shot("coin flips");
	nflips = 0;
	state = S_DICE;
	for (int v = 0; v < 2; v++) {
		nrolls = v ? MAX_ROLLS : 0;
		for (int i = 0; i < nrolls; i++) rolls[i] = (uint8_t) (1 + i % 6);
		for (dsel = 1; dsel <= 6; dsel++) shot("dice rolls");
	}
	nrolls = 0; dsel = 1;
	state = S_CD;
	cd_rc = CD_NO_DISC; shot("CD seek: no disc");
	cd_rc = CD_TIMEOUT; shot("CD seek: drive error");
	cd_rc = CD_OK;
	for (int v = 0; v < 3; v++) {
		nseek = v; log_rc = v == 2 ? CDLOG_NO_CARD : CDLOG_OK; cd_pending = v == 1;
		cd_last.flags = v == 2 ? CDS_FAIL : 0;
		shot("CD seek");
	}
	cd_pending = 0;
}

static void keyboards(void)
{
	static const char *const REST_MSG[] = {"", "Word 13 is not in the list", "12 words typed, 24 chosen", "Checksum wrong: a word is mistyped", "A word is wrong or the checksum fails",
	                                       "25 words typed, 25 needed"};
	for (rest_kind = 0; rest_kind < 4; rest_kind++) {
		if (rest_kind == 2) continue;
		rest_goal = rest_kind == 3 ? 25 : 24;
		rest_kb(rest_kind == 1 ? "TON phrase (24 words)" : rest_kind == 3 ? "Monero words (25)" : "Recovery words");
		strcpy(kb.text, "abandon ability able about above absent absorb abstract");
		kb.len = (int) strlen(kb.text);
		state = S_REST;
		for (unsigned i = 0; i < sizeof REST_MSG / sizeof REST_MSG[0]; i++) { snprintf(msg, sizeof msg, "%s", REST_MSG[i]); rest_len = kb.len; shot("keyboard: restore"); }
	}
	msg[0] = 0; rest_kind = 0;
	kb_init(&kb, "Key: 64 hex digits", NULL, 1, 0); state = S_RAW_KEY; shot("keyboard: raw key");
	kb_init(&kb, "BIP39 passphrase (empty: none)", NULL, 1, 0); state = S_PASS; shot("keyboard: passphrase");
	kb_init(&kb, "They differ - enter it again", NULL, 1, 0); state = S_REST_PASS; shot("keyboard: passphrase");
	for (int h = 0; h < 2; h++) {
		static const char *const T[] = {"Text to encrypt", "Nothing to encrypt", "Even digits only"};
		enc_hex = h;
		for (int t = 0; t < 3; t++) {
			enc_kb(T[t]);
			for (int len = 0; len <= 1024; len += 512) { memset(kb.text, 'a', (size_t) len); kb.text[len] = 0; kb.len = len; state = S_ENC_TEXT; shot("keyboard: text to encrypt"); }
		}
	}
	enc_hex = 0;
	kb_init(&kb, "Ciphertext in hex", NULL, 0, 0); kb.len = 200; state = S_DEC_HEX; shot("keyboard: ciphertext");
	kb_init(&kb, "Hex: whole bytes, at least 58 - again", NULL, 0, 0); kb.len = 57; state = S_DEC_HEX; shot("keyboard: ciphertext");
	kb_init(&kb, "Name of the saved text (empty: none)", NULL, 0, 1); state = S_ENC_NAME; shot("keyboard: name");
	for (pass_stage = 0; pass_stage < 2; pass_stage++) {
		pw_kb(pass_stage ? "Repeat the password" : "Password (not empty)", NULL);
		strcpy(kb.text, "correct horse"); kb.len = 13;
		state = S_ENC_PASS; shot("keyboard: password");
		state = S_KS_PASS; shot("keyboard: password of the key");
	}
	pass_stage = 0;
	kb_init(&kb, "Label (shown with the password)", NULL, 0, 1); state = S_KS_LABEL; shot("keyboard: label");
	kb_init(&kb, "Text to encrypt", NULL, 0, 1);
	for (int i = 0; i < 400; i++) kb.text[i] = (char) ('a' + i % 26);
	kb.text[400] = 0; kb.len = 400; kb.cur = 200;
	state = S_ENC_TEXT;
	kb.full = 1;
	for (kb.confirm = 0; kb.confirm < 2; kb.confirm++) shot("keyboard: the full view");
	kb.confirm = 0; kb.clip_view = 1;
	for (kb.confirm = 0; kb.confirm < 2; kb.confirm++) shot("keyboard: the clipboard");
	kb.confirm = 0; kb.clip_view = 0; kb.full = 0;
	kb_init(&kb, "Derivation path", "m/44'/60'/0'/0/0", 0, 0); kb_set(&kb, 60, 2); state = S_PATHTXT; shot("keyboard: path");
}

static void encryption_screens(void)
{
	static uint8_t blob[700];

	state = S_PW_SHOW;
	for (pw_kind = PW_CHARS; pw_kind <= PW_WORDS; pw_kind++) {
		snprintf(pw_sug, sizeof pw_sug, "%s", pw_kind == PW_WORDS ? "abstract absurd category criminal elephant festival purchase umbrella" : "Xq7mPz2KdW9vRt4");
		pw_sug_bits = 88;
		for (hold = 0; hold <= HOLD_FRAMES; hold += HOLD_FRAMES) shot("random password");
	}
	hold = 0;
	for (int i = 0; i < (int) sizeof blob; i++) blob[i] = (uint8_t) (i * 37 + 11);
	enc_len = (int) sizeof blob;
	b64_encode(blob, (size_t) enc_len, enc_b64, sizeof enc_b64);
	hex_fmt(enc_hexs, blob, enc_len);
	qr_ok = qr_encode(&qr, (const uint8_t *) enc_b64, strlen(enc_b64), QR_ECC_M) > 0;
	if (qr_ok) qr_scale = qr_view_scale(&qr);
	ur_plan_make(&urp, blob, (size_t) enc_len, UR_FRAG);
	state = S_ENC_OUT;
	for (out_page = 0; out_page < 3; out_page++)
		for (out_ur = 0; out_ur < 2; out_ur++) {
			msg[0] = 0; shot("encrypted text");
			snprintf(msg, sizeof msg, "%s", "Saved to card 2 as PSXXET03"); shot("encrypted text");
		}
	msg[0] = 0; out_page = 0; out_ur = 0;
	state = S_DEC_LIST;
	dec_rc = MCF_NO_CARD; shot("decrypt: the texts");
	dec_rc = 0; dn = 0; shot("decrypt: the texts");
	dn = 8;
	for (int i = 0; i < dn; i++) { snprintf(dnames[i], sizeof dnames[i], "%s", "Shopping list for May 26"); mcf_name(dlist[i].name, "PSXXET", i); }
	for (dsel_i = 0; dsel_i < dn; dsel_i++) shot("decrypt: the texts");
	snprintf(msg, sizeof msg, "%s", "Not an encrypted text of this program"); shot("decrypt: the texts");
	msg[0] = 0;
	state = S_DEC_OUT;
	memset(dec_text, 'x', 900); dec_text[900] = 0; dec_len = 900;
	hex_fmt(dec_hexs, blob, 400);
	for (dec_hexview = 0; dec_hexview < 2; dec_hexview++) shot("decrypted text");
	dec_hexview = 0;
}

static void keystore_screens(void)
{
	state = S_KS_STORE;
	ks_type = KS_TYPE_BIP39; ks_elen = 32; ks_flags = KS_FLAG_PASSPHRASE;
	ks_rc = MCF_NO_CARD; shot("save the key: stores");
	ks_rc = 0;
	for (int nv = 0; nv <= KSD_MAX_VAULTS; nv++)
		for (int single = 0; single < 2; single++) {                       /* the vaults, with the single keys or without */
			memset(&ks_st, 0, sizeof ks_st);
			ks_st.nstores = nv + single; ks_st.free_count = nv == KSD_MAX_VAULTS ? 0 : 4; ks_st.corrupt = nv == KSD_MAX_VAULTS ? 2 : 0;
			for (int i = 0; i < ks_st.nstores; i++) {
				int v = i - single;                                           /* the single keys' block comes first */

				ks_st.st[i].n = i < single ? 7 : 3;
				ks_st.st[i].single = i < single;
				ks_st.st[i].next_slot = 1;
				if (v >= 0) ks_st.st[i].dir.flags = KS_DIR_PW;
				if (v == 0) snprintf(ks_st.st[i].dir.label, sizeof ks_st.st[i].dir.label, "%s", "Family wallets, a long name of a vault");
				if (v == 1) snprintf(ks_st.st[i].dir.label, sizeof ks_st.st[i].dir.label, "%s", "Work");
			}
			for (ks_sel = 0; ks_sel < nv + 2; ks_sel++) {
				snprintf(ks_msg, sizeof ks_msg, "%s", ks_sel == 1 ? "That vault is full (60 keys)" : ks_sel == nv + 1 && nv == KSD_MAX_VAULTS ? "No room for a new vault: use an existing one" : "");
				shot("save the key: stores");
			}
		}
	ks_msg[0] = 0;
	ks_type = KS_TYPE_RAW; ks_flags = 0; shot("save the key: stores");
	kb_init(&kb, "Name of the new vault", NULL, 0, 1); kb_set(&kb, KS_STORE_LABEL, 0); state = S_KS_SLABEL; shot("save the key: store name");
	kb_init(&kb, "Password of the vault", NULL, 1, 0); kb_set(&kb, PW_MAX, 0); state = S_KS_SPW; shot("save the key: vault password");
	kb_init(&kb, "Wrong vault password - again", NULL, 1, 0); kb_set(&kb, PW_MAX, 0); shot("save the key: vault password");
	kb_init(&kb, "Name of the key (shown only after the password)", NULL, 0, 1); kb_set(&kb, KS_LABEL_STORE, 0); state = S_KS_LABEL; shot("save the key: name of a key");
	kb_init(&kb, "Name in the list (visible without the password)", "Key 4", 0, 1); kb_set(&kb, KS_PUBLIC, 0); state = S_KS_PLABEL; shot("save the key: name in the list");
	pw_for = PW_FOR_STORE; pw_sel = 0; state = S_PW_CHOOSE; shot("save the key: password of the store");
	state = S_KS_DONE;
	snprintf(ks_msg, sizeof ks_msg, "%s", "Saved: key 3 of the vault Family"); shot("save the key: done");
	snprintf(ks_msg, sizeof ks_msg, "%s", "Saved: single key (8 saved)"); shot("save the key: done");
	snprintf(ks_msg, sizeof ks_msg, "%s", "Not saved: the card was taken out"); shot("save the key: done");
	ks_msg[0] = 0;
}

static void loader_screens(void)
{
	static const uint8_t pin[32] = {1};

	static const char *const TEXTS[][2] = {{"FreePSXBoot card, not a package", "package a4ceecfa, this release"}, {"another release (version mismatch)", "card, no package"},
	                                       {"card not formatted", "no card"}, {"package a4ceecfa, this release", "package a4ceecfa, this release"}};
	static const struct { cw_state st[2]; int code[2]; } V[5] = {
		{{CW_BOOT, CW_PKG_OK}, {0, 0}}, {{CW_PKG_BAD, CW_NO_PACKAGE}, {LDR_ERR_BASE, 0}}, {{CW_UNFORMATTED, CW_NO_CARD}, {0, 0}},
		{{CW_PKG_OK, CW_PKG_OK}, {0, 0}}, {{CW_NO_PACKAGE, CW_READ_ERROR}, {0, 0}}};
	su_init(&sui, &ctx, &in, 60, "B card", SIGNER_PKG, PKG_KIND_OVERLAY, pin, pin, SIGNER_GROUP);
	state = S_SIGNER;
	for (int v = 0; v < 5; v++) {
		slot_text[0] = TEXTS[v % 4][0]; slot_text[1] = TEXTS[v % 4][1];
		for (int p = 0; p < 2; p++) { sui.cw.s[p].state = V[v].st[p]; sui.cw.s[p].have = V[v].st[p] != CW_NO_CARD; sui.cw.s[p].code = V[v].code[p]; slot_ok[p] = V[v].st[p] == CW_PKG_OK; }
		for (int src = 0; src < 3; src++) {
			sui.src = src;
			sui.phase = SU_SELECT; sui.note[0] = 0; shot("loader");
			if (v == 3) { snprintf(sui.note, sizeof sui.note, "Two B cards found: take one out."); shot("loader"); }
		}
	}
	slot_ok[0] = 0; slot_ok[1] = 1;
	su_init(&sui, &ctx, &in, 60, "Load a language", "BESCES-00000PSXXPK02", PKG_KIND_DATA, pin, pin, 0);
	sui.phase = SU_SELECT; shot("loader: language data");
	su_init(&sui, &ctx, &in, 60, "Load the signer", SIGNER_PKG, PKG_KIND_OVERLAY, pin, pin, SIGNER_GROUP);
	sui.phase = SU_ERROR;
	for (int e = 0; e < 4; e++) {
		static const int CODES[4][2] = {{SU_ERR_CHANGED, 0}, {SU_ERR_CANCELLED, 0}, {LDR_ERR_PKG, PKG_ERR_PIN}, {LDR_ERR_CARD, CF_ERR_NOTFOUND}};
		sui.err_code = CODES[e][0]; sui.err_detail = CODES[e][1];
		shot("loader: error");
	}
	snprintf(sui.what, sizeof sui.what, "Group 1 of 2 (64206 bytes), slot 2");
	for (sui.pct = 0; sui.pct <= 100; sui.pct += 50) { draw_reading(&sui); flush("loader: reading"); }
	sui.phase = SU_SELECT;
}

/* a wallet from fixed entropy: BIP39 24 words and Monero, so that every page has its real content */
static void make_wallet(void)
{
	uint8_t ent[32], part[32];

	for (int i = 0; i < 32; i++) ent[i] = (uint8_t) (i * 91 + 5);
	wtype = W_BOTH_24;
	derive_part(part, "psx-wallet-bip39", ent);
	if (generate_bip39(part)) { printf("FAIL: the BIP39 wallet\n"); exit(1); }
	flush("status");
	derive_part(part, "psx-wallet-monero", ent);
	if (generate_monero(part)) { printf("FAIL: the Monero wallet\n"); exit(1); }
	flush("status");
}

static void wallet_screens(void)
{
	state = S_WORDS;
	for (int v = 0; v < 2; v++) {
		used_pass = v;
		for (words_idx = 0; words_idx < words_screens(); words_idx++)
			for (hold = 0; hold <= HOLD_FRAMES; hold += HOLD_FRAMES) shot("words");
	}
	hold = 0; words_idx = 0;
	state = S_VERIFY;
	for (vfail = 0; vfail < 2; vfail++) {
		vq = VQ - 1; vpos[vq] = 24; vwhy = vfail; vsane = 1;
		for (int i = 0; i < VOPTS; i++) snprintf(vopt[i], sizeof vopt[i], "%s", "abstract");
		for (vsel = 0; vsel < VOPTS; vsel++) shot(vfail ? "word check: mismatch" : "word check");
	}
	vfail = 0;
	state = S_ADDR;
	for (page = 0; page < page_count(); page++) {
		ensure_sub();
		flush("status");
		for (int v = 0; v < 2; v++) {
			hs_valid = v;
			qr_mode = 0; shot("address");
			hold = HOLD_FRAMES / 2; shot("address"); hold = 0;
			refresh_qr(); qr_mode = 1; shot("address: QR code"); qr_mode = 0;
		}
	}
	hs_valid = 1;
	page = monero_base() + XMR_SUB_PAGE;
	xmr_sub_idx = XMR_SUB_MAX; ensure_sub(); flush("status"); shot("address"); xmr_sub_idx = 1;
	kb_init(&kb, "Payment ID: 16 hex digits", xmr_pid_hex, 0, 0); kb_set(&kb, 16, 1); state = S_PID; shot("keyboard: payment ID");
	kb_init(&kb, "Payment ID: exactly 16 hex digits", "12ab", 0, 0); kb_set(&kb, 16, 1); shot("keyboard: payment ID");
	page = 0;
	state = S_XPUB;
	xp_have = 0;
	for (xp_sel = 0; xp_sel < XPUB_KINDS; xp_sel++) { msg[0] = 0; shot("watch-only menu"); snprintf(msg, sizeof msg, "%s", "Cannot derive the key"); shot("watch-only menu"); }
	msg[0] = 0; xp_sel = 0; xp_have = 1;
	if (xpub_export(xp_key, xp_desc, hs.seed, xp_sel) != 0) { printf("FAIL: xpub\n"); exit(1); }
	for (xp_page = 0; xp_page < 2; xp_page++) {
		xp_qr = 0; shot("watch-only key");
		qr_ok = qr_encode(&qr, (const uint8_t *) (xp_page ? xp_desc : xp_key), strlen(xp_page ? xp_desc : xp_key), QR_ECC_M) > 0;
		if (qr_ok) qr_scale = qr_view_scale(&qr);
		xp_qr = 1; shot("watch-only key: QR code");
	}
	xp_have = 0; xp_qr = 0; xp_page = 0;

	/* TON: the pages of its addresses (the phrase itself takes minutes to find; the addresses have their fixed length) */
	wtype = W_TON;
	for (int i = 0; i < TON_PAGES; i++) snprintf(ton_addr[i], sizeof ton_addr[i], "UQBvW8Z5huBkMJYdnfAEM5JqTNkuWX3diqYENkWsIL0XggGG");
	ton_seed_ok = 1;
	state = S_ADDR;
	for (page = 0; page < page_count(); page++) { shot("address"); refresh_qr(); qr_mode = 1; shot("address: QR code"); qr_mode = 0; }
	state = S_WORDS; words_idx = 0; shot("words");
	page = 0; wtype = W_BOTH_24;
}

static void chain_screens(void)
{
	state = S_CHAINS;
	for (cgroup = 0; cgroup < NCHAIN_GROUPS; cgroup++)
		for (csel = 0; csel < group_len(cgroup); csel++) { ctop = csel >= CHAIN_ROWS ? csel - CHAIN_ROWS + 1 : 0; shot("chains"); }
	cgroup = 0; csel = 0; ctop = 0;
	for (int g = 0; g < NCHAIN_GROUPS - 1; g++)
		for (int k = 0; k < group_len(g); k++) {
			const chain_def *c = group_item(g, k);
			if (c->curve == CV_ORCHARD) continue;                  /* its derivation takes seconds; its pages are the same as the others' */
			chain_select(c);
			flush("status");
			if (state == S_STYLE) {
				for (cstyle = 0; cstyle < 3; cstyle++) if (style_ok(cstyle)) shot(chain_has_view_keys(c) ? "style and count: MWEB" : "style and count");
				cstyle = 0; ccount = count_max(c) < 2 ? count_max(c) : 2;
				list_derive();
				flush("status");
			}
			for (cidx = 0; cidx < clist_n; cidx++) {
				msg[0] = 0; shot(chain_has_view_keys(c) ? "chain address: MWEB" : "chain address");
				snprintf(msg, sizeof msg, "%s", "Saved to card 2 as PSXXAD02"); shot("chain address");
			}
			cidx = 0; msg[0] = 0;
			chain_qr(); cqr = 1; shot("chain address: QR code"); cqr = 0;
			for (sview = 0; sview <= (chain_has_view_keys(c) ? 1 : 0); sview++)             /* the key that spends, and for a chain that has them the view-only keys */
			if (c->curve != CV_ORCHARD) {
				const char *nm = sview ? "view keys" : chain_has_view_keys(c) ? "secret key: MWEB" : "secret key";
				state = S_SECRET;
				for (sstage = 0; sstage < 2; sstage++) {
					if (sstage == 1) { secret_derive(); flush("status"); }
					for (hold = 0; hold <= HOLD_FRAMES; hold += HOLD_FRAMES) shot(nm);
				}
				hold = 0;
				secret_qr(); sstage = 2; shot("secret key: QR code");
				secret_wipe();
			}
			sview = 0;
			if (c->curve != CV_SR25519) {
				state = S_PATH;
				epath = cbase;
				for (cseg = 0; cseg < epath.n; cseg++) for (cexpert = 0; cexpert < 2; cexpert++) shot("path editor");
				epath.n = PATH_MAX_DEPTH; for (int i = 0; i < epath.n; i++) epath.idx[i] = 2147483647u | PATH_HARD;
				cseg = epath.n - 1; shot("path editor");
				cexpert = 0;
			}
		}
	state = S_CUSTOM;
	custom_init();
	for (ckind = 0; ckind < (int) (sizeof CK / sizeof CK[0]); ckind++)
		for (cfield = 0; cfield < 5; cfield++) { custom_kind_set(ckind); shot("custom coin"); }
	ckind = 0; cfield = 0;
}

int main(void)
{
	ui_range_clear(UI_R_B);                      /* the console has only the main card's texts in RAM here: a text of another range would show as nothing */
	ui_range_clear(UI_R_L);
	ui_reg_a();
	words_prepare();
	in.ps.buttons = 0;
	for (int lg = 0; lg < 2; lg++)                /* English, then Hungarian: the texts are longer, the layout has to hold */
	for (int y = 240; y <= 256; y += 16) {
		ui_lang_set(lg ? UI_LANG_HU : UI_LANG_EN);
		lc_snapshot(lg == 0);
		lc_tag = lg ? "[hu] " : "";
		screen_yres = ctx.yres = y;
		ctx.xres = 640;
		state = S_SPLASH;
		for (splash_pd = 0; splash_pd <= 256; splash_pd += 64) shot("splash");
		show_status("Deriving the TON key", "123 of 4096 candidates, about 8 minutes"); flush("status");
		menus();
		entropy_screens();
		keyboards();
		encryption_screens();
		keystore_screens();
		loader_screens();
		make_wallet();
		wallet_screens();
		chain_screens();
	}
	printf("main card screens: %d frames, %d layout problems\n", lc_frames, lc_bad);
	return lc_bad ? 1 : 0;
}
