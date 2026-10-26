/* The screens of the signer (hal/psx/signer_app.c with signer_vanity.h and signer_ms.h, the keyboard, the QR view) on the host, checked for their layout
 * (tests/layout_check.h): every screen in the states that change what it shows (the longest texts: titles, warnings, notes, addresses and amounts of the transaction
 * pages; every count of keys, requests, wallets), on a 240 and a 256 line picture. The signer is compiled into this file with stand-ins for the console
 * (tests/langui_stub, tests/screen_stubs.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "layout_check.h"
#include "coin/words.h"

#define main signer_main
#include "signer_app.c"

const lang_api *psxx_lang;
#undef main

extern int screen_yres;

int mcf_scan(int port, const char *tag, mcf_entry *out, int max, int *nfiles, int *next, int *free_block) { (void) port; (void) tag; (void) out; (void) max; *nfiles = 0; *next = 0; *free_block = 0; return MCF_NO_CARD; }
int mcf_invalidate(int port, int block) { (void) port; (void) block; return MCF_NO_CARD; }
int mcf_begin(int port, int block, const char *title, int icon) { (void) port; (void) block; (void) title; (void) icon; return MCF_NO_CARD; }
int mcf_write(int port, int block, int frame, const uint8_t *data) { (void) port; (void) block; (void) frame; (void) data; return MCF_NO_CARD; }
int mcf_read(int port, int block, int frame, uint8_t *data) { (void) port; (void) block; (void) frame; (void) data; return MCF_NO_CARD; }
int mcf_commit(int port, int block, const char *tag, int number) { (void) port; (void) block; (void) tag; (void) number; return MCF_NO_CARD; }
int ksd_del_marked(int port, ksd_state *s, uint8_t (*marks)[KS_SLOTS], int key_store, const uint8_t key[32], uint8_t work[KS_DATA], int *deleted, int *need_store)
{ (void) port; (void) s; (void) marks; (void) key_store; (void) key; (void) work; (void) deleted; (void) need_store; return KSD_ERR_ARG; }
int ksd_scan(int port, ksd_state *s, int clean) { (void) port; (void) clean; memset(s, 0, sizeof *s); return MCF_NO_CARD; }
int ksd_read(int port, const ksd_store *st, uint8_t img[KS_DATA]) { (void) port; (void) st; (void) img; return MCF_NO_CARD; }
int ksd_create(int port, ksd_state *s, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id_hint, uint8_t work[KS_DATA], int *store)
{ (void) port; (void) s; (void) label; (void) pw; (void) key; (void) id_hint; (void) work; (void) store; return MCF_NO_CARD; }
int ksd_add2(int port, ksd_state *s, int store, const uint8_t *entry, int replace_slot, const uint8_t key[32], uint8_t work[KS_DATA])
{ (void) port; (void) s; (void) store; (void) entry; (void) replace_slot; (void) key; (void) work; return MCF_NO_CARD; }
int ksd_del2(int port, ksd_state *s, int store, int slot, const uint8_t key[32], uint8_t work[KS_DATA])
{ (void) port; (void) s; (void) store; (void) slot; (void) key; (void) work; return MCF_NO_CARD; }
int ksd_remove_store(int port, ksd_state *s, int store) { (void) port; (void) s; (void) store; return MCF_NO_CARD; }
int ksd_make_block(int port, ksd_state *s, int single, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id, const uint8_t *entry, int nf, uint8_t work[KS_DATA], int *store)
{ (void) port; (void) s; (void) single; (void) label; (void) pw; (void) key; (void) id; (void) entry; (void) nf; (void) work; (void) store; return MCF_NO_CARD; }
uint16_t ksd_free_id(const ksd_state *s, uint16_t hint) { (void) s; return hint; }
int ksd_remove_singles(int port, ksd_state *s) { (void) port; (void) s; return MCF_NO_CARD; }
int ksd_new_single(int port, ksd_state *s, const uint8_t *entry, int nf, uint16_t id_hint, uint8_t work[KS_DATA], int *store) { (void) port; (void) s; (void) entry; (void) nf; (void) id_hint; (void) work; (void) store; return MCF_NO_CARD; }

static void shot(const char *name)
{
	draw();
	lc_frame(name, screen_yres);
}

static void fill(char *d, size_t cap, const char *pattern)
{
	size_t n = strlen(pattern);
	for (size_t i = 0; i + 1 < cap; i++) d[i] = pattern[i % n];
	d[cap - 1] = 0;
}

static void menus(void)
{
	state = S_EXTRAS;
	for (esel = 0; esel < 4; esel++) shot("extras");
	esel = 0;
	state = S_TE_MENU;
	for (tsel = 0; tsel < 3; tsel++) shot("text encoding menu");
	tsel = 0;
	state = S_TE_VIEW;
	{
		static const char SAMPLE[] = "Hello \xC3\xA1\xC5\x91 \xE2\xA0\x81\xE2\xA0\x83\xE2\xA0\x89 caf\xC3\xA9 and a longer text to scroll through the bytes";
		te_raw_len = (int) sizeof SAMPLE - 1;
		memcpy(te_raw, SAMPLE, (size_t) te_raw_len);
		te_from_text = 1;
		for (te_ascii = 0; te_ascii < 2; te_ascii++)
			for (te_top = 0; te_top <= 8; te_top += 4) shot("text and bytes");
		te_raw[0] = 0x0A; te_raw[1] = 0xFF; te_raw[2] = 0xE2; te_raw[3] = 0xA0; te_raw[4] = 0x81; te_raw_len = 5;
		te_from_text = 0; te_top = 0;
		for (te_ascii = 0; te_ascii < 2; te_ascii++) shot("bytes to text");
		te_ascii = 0;
	}
	state = S_TE_BRAILLE;
	shot("braille test");
	state = S_NOTES;
	for (nt_top = 0; nt_top <= NOTE_COUNT - NOTE_ROWS; nt_top += 5) shot("safety notes");
	nt_top = 0;
	state = S_CDP;
	shot("cd player");
	state = S_BOOT;
	for (boot_p = 0; boot_p <= 100; boot_p += 50) shot("boot");
	state = S_HOME;
	for (int v = 0; v < 3; v++) {
		hs_valid = v > 0; hs.xmr_ok = v == 2; hs.raw_curve = 0; hs.no_bip = 0;
		for (hsel = 0; hsel < HOME_N; hsel++) shot("home");
	}
	hsel = 0;
	state = S_SRC;
	for (ssel = 0; ssel < 2; ssel++) shot("request source");
	state = S_RESTOPT;
	for (rest_nw = 0; rest_nw < 6; rest_nw++)
		for (ropt_row = 0; ropt_row < 2; ropt_row++) shot("restore options");
	rest_nw = 0; ropt_row = 0;
	state = S_ERR;
	snprintf(msg, sizeof msg, "%s", "The request names a chain that this signer does not know of");
	shot("cannot continue");
	msg[0] = 0;
}

static void keyboards(void)
{
	static const char *const NOTES[] = {"", "Word 13 is not in the list", "Checksum wrong: a word is mistyped", "A word is wrong or the checksum fails"};
	for (rest_xmr = 0; rest_xmr < 2; rest_xmr++) {
		kb_init(&kb, rest_xmr ? "Monero words (25)" : "Recovery words", NULL, 0, 0);
		kb_set(&kb, 300, 0);
		kb_set_suggest(&kb, rest_xmr ? rest_suggest_xmr : rest_suggest);
		strcpy(kb.text, "abandon ability able about"); kb.len = (int) strlen(kb.text);
		state = S_REST;
		for (unsigned i = 0; i < sizeof NOTES / sizeof NOTES[0]; i++) { snprintf(msg, sizeof msg, "%s", NOTES[i]); rest_len = kb.len; shot("keyboard: restore"); }
	}
	msg[0] = 0; rest_xmr = 0;
	kb_init(&kb, "BIP39 passphrase (empty: none)", NULL, 1, 0); state = S_REST_PASS; shot("keyboard: passphrase");
	kb_init(&kb, "Request in hex", NULL, 0, 0); kb_set(&kb, 2000, 1); state = S_HEX; shot("keyboard: request in hex");
	kb_init(&kb, "Password of the key", NULL, 1, 0); state = S_KEY_PW; shot("keyboard: password");
}

static void request_screens(void)
{
	state = S_LIST;
	rrc = MCF_NO_CARD; rn = 0; shot("requests");
	rrc = 0; rn = 0; shot("requests");
	rn = 8;
	for (int i = 0; i < rn; i++) snprintf(rlist[i].name, sizeof rlist[i].name, "BESCES-00000PSXXRQ%02d", i + 1);
	for (rsel = 0; rsel < rn; rsel++) shot("requests");
	snprintf(msg, sizeof msg, "%s", "Not a request: the file is damaged"); shot("requests");
	msg[0] = 0; rsel = 0;
}

static void view_screens(void)
{
	static const char *const AMOUNTS[] = {"0.00012345 BTC", "115792089237316195423570985008687907853269984665640564039457.584007913129639935 ETH"};

	txv_clear(&view);
	snprintf(view.title, sizeof view.title, "%s", "Ethereum EIP-1559 transaction, chain 42161");
	snprintf(view.total, sizeof view.total, "%s", "1234567.123456789012345678 ETH");
	snprintf(view.fee, sizeof view.fee, "%s", "0.001234567890123456 ETH");
	view.warn = 0x7FF;                                                  /* every warning */
	view.nnote = TXV_NOTES;
	for (int i = 0; i < TXV_NOTES; i++) fill(view.note[i], sizeof view.note[i], "Nonce 12, gas limit 21000, max fee 30 gwei ");
	view.nout = TXV_OUTS; view.nmore = 3;
	for (int i = 0; i < TXV_OUTS; i++) {
		fill(view.out[i].to, i % 2 ? 43 : sizeof view.out[i].to, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq ");
		snprintf(view.out[i].amount, sizeof view.out[i].amount, "%s", AMOUNTS[i % 2]);
		view.out[i].mine = i == 3;
	}
	view_paginate();
	state = S_VIEW;
	for (int w = 0; w < 2; w++) {
		if (w) view.warn = 0;
		for (vpage = 0; vpage < vnpages; vpage++)
			for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL) shot("transaction");
	}
	hold = 0; vpage = 0;

	txv_clear(&view);                                                   /* a decrypted message of the greatest size: the text pages */
	snprintf(view.title, sizeof view.title, "%s", "Decrypted Nostr message (NIP-44)");
	snprintf(view.note[0], sizeof view.note[0], "%s", "With: npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg");
	snprintf(view.note[1], sizeof view.note[1], "%s", "Message: 4096 bytes");
	view.nnote = 2;
	fill(msg_text, sizeof msg_text, "lorem ipsum \xc3\xa9\xc3\xb6 dolor sit amet ");
	view.text_len = (int) strlen(msg_text);
	view_paginate();
	state = S_VIEW;
	for (vpage = 0; vpage < vnpages; vpage++)
		for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL) shot("message");
	view.text_len = 0; view.warn = 0;
	hold = 0; vpage = 0;
}

static void result_screens(void)
{
	static uint8_t buf[600];
	for (int i = 0; i < (int) sizeof buf; i++) buf[i] = (uint8_t) (i * 37 + 11);
	res.buf = buf; res.len = sizeof buf; res.label = "Signed Bitcoin transaction (PSBT)";
	b64_encode(buf, 180, b64txt, sizeof b64txt);
	qr_ok = qr_encode(&qr, (const uint8_t *) b64txt, strlen(b64txt), QR_ECC_M) > 0;
	if (qr_ok) qr_scale = qr_view_scale(&qr);
	ur_plan_make(&urp, buf, res.len, UR_FRAG);
	state = S_OUT;
	for (out_page = 0; out_page < 2; out_page++)
		for (out_ur = 0; out_ur < 2; out_ur++)
			for (int m = 0; m < 2; m++) {
				snprintf(msg, sizeof msg, "%s", m ? "Not saved: card not formatted" : "");
				for (out_scroll = 0; out_scroll < 2; out_scroll++) shot("result");
			}
	msg[0] = 0; out_page = 0; out_ur = 0; out_scroll = 0;
}

static void key_screens(void)
{
	state = S_KEY_LIST;
	ks_rc = MCF_NO_CARD; ks_total = 0; shot("keys");
	ks_rc = 0;
	memset(&ks_st, 0, sizeof ks_st);
	ks_total = 0; shot("keys");
	ks_st.nstores = KSD_MAX_STORES;
	for (int i = 0; i < KSD_MAX_STORES; i++) {
		ks_st.st[i].n = 3;
		if (i == 1) { ks_st.st[i].dir.flags = KS_DIR_PW; snprintf(ks_st.st[i].dir.label, sizeof ks_st.st[i].dir.label, "%s", "Family wallets, a long name of a store"); }
		if (i == 2) snprintf(ks_st.st[i].dir.label, sizeof ks_st.st[i].dir.label, "%s", "Work");
		for (int k = 0; k < 3; k++) if (i != 1 || k) snprintf(ks_pub[i][k], sizeof ks_pub[i][k], "%s", k == 1 ? "Holiday money" : "0123456789abcdef");   /* the open labels of the own entries */
	}
	ks_total = 3 * KSD_MAX_STORES;
	for (ks_sel = 0; ks_sel < ks_total; ks_sel++) { ks_top = ks_sel >= KEY_ROWS ? ks_sel - KEY_ROWS + 1 : 0; shot("keys"); }
	ks_st.corrupt = 2; shot("keys");
	ks_st.corrupt = 0; snprintf(msg, sizeof msg, "%s", "Wrong password, or the key is damaged"); shot("keys");
	msg[0] = 0; ks_sel = ks_top = 0;
	state = S_KEY_CONFIRM;
	snprintf(ks_label, sizeof ks_label, "%s", "Savings, the second store");
	for (ks_type = KS_TYPE_BIP39; ks_type <= KS_TYPE_RAW; ks_type++)
		for (int c = 0; c < 2; c++) {
			hs.raw_curve = c ? 1 : 2;
			snprintf(ck_fp, sizeof ck_fp, "d34db33f");
			fill(ck_addr, ks_type == KS_TYPE_MONERO ? 96 : ks_type == KS_TYPE_BIP39 ? 43 : 49, "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge ");
			shot("is this your key");
		}
	hs.raw_curve = 0;
	state = S_KEY_DEL;
	for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL / 2) shot("delete the key");
	hold = 0;
	/* the keys menu, the raw key import, the deletion of several keys, the erasing of stores */
	state = S_KM_MENU;
	for (kmsel = 0; kmsel < 4; kmsel++) shot("keys menu");
	kmsel = 0;
	state = S_RK_KIND;
	for (rksel = 0; rksel < RK_N; rksel++) shot("import a raw key");
	rksel = 0;
	state = S_RK_TEXT;
	for (rk_kind = 0; rk_kind < RK_N; rk_kind++) {
		static const char *const NOTES[] = {"", "The checksum is wrong: a character is mistyped", "Not a key: hex, nsec1 or WIF is needed"};
		static const char *const TITLE[RK_N] = {"Key: hex, nsec1 or WIF", "Key: hex, base58 keypair, S... or ed25519:", "Key: 64 hex digits", "Key: 64 hex digits", "Key: 64 hex digits", "Key: 128 hex digits or addr_xsk1..."};
		kb_init(&kb, TITLE[rk_kind], NULL, 1, 0);
		kb_set(&kb, rk_kind == RK_SECP ? 70 : rk_kind == RK_ED ? 100 : rk_kind == RK_ADA ? 200 : 64, rk_kind != RK_SECP && rk_kind != RK_ED && rk_kind != RK_ADA);
		strcpy(kb.text, "nsec1e2tczyk2rw7u47kzxxee5g7ufkncdmlcz37yuu4e"); kb.len = (int) strlen(kb.text);
		for (unsigned i = 0; i < sizeof NOTES / sizeof NOTES[0]; i++) { snprintf(msg, sizeof msg, "%s", NOTES[i]); rk_len = kb.len; shot("keyboard: raw key"); }
	}
	msg[0] = 0; rk_kind = 0;
	state = S_KEY_CONFIRM;
	rk_pending = 1;
	for (rk_kind = 0; rk_kind < RK_N; rk_kind++) {
		ks_type = rk_kind == RK_XMR ? KS_TYPE_MONERO : KS_TYPE_RAW;
		fill(ck_addr, rk_kind == RK_XMR ? 96 : rk_kind == RK_ORCHARD ? 141 : rk_kind == RK_ADA ? 58 : 42, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F ");
		fill(ck_npub, 63, "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m ");
		fill(ck_btc, 42, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq ");
		shot("imported key");
	}
	rk_kind = 0;
	rk_pending = 0; hs.raw_curve = 0; ck_npub[0] = ck_btc[0] = 0;
	state = S_KEY_LIST;
	kd_mode = 1;
	memset(kd_mark, 0, sizeof kd_mark);
	ks_rc = 0; ks_total = 3 * KSD_MAX_STORES;
	for (ks_sel = 0; ks_sel < ks_total; ks_sel += 4) {
		ks_top = ks_sel >= KEY_ROWS ? ks_sel - KEY_ROWS + 1 : 0;
		kd_mark[ks_sel / 3][ks_sel % 3] ^= 1;
		shot("delete keys: list");
	}
	snprintf(msg, sizeof msg, "%s", "Mark at least one key first"); shot("delete keys: list");
	snprintf(msg, sizeof msg, "%s", "Deleted 3 keys"); shot("delete keys: list");
	msg[0] = 0; ks_sel = ks_top = 0;
	state = S_KD_CONFIRM;
	for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL / 2) shot("delete keys: confirm");
	hold = 0; kd_mode = 0; memset(kd_mark, 0, sizeof kd_mark);
	state = S_KE_LIST;
	for (kesel = 0; kesel <= ks_st.nstores; kesel++) shot("erase a store");
	snprintf(msg, sizeof msg, "%s", "Erased"); shot("erase a store");
	msg[0] = 0;
	state = S_KE_CONFIRM;
	for (kesel = 0; kesel <= ks_st.nstores; kesel += 2) for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL) shot("erase a store: confirm");
	hold = 0; kesel = 0;
	memset(&ks_st, 0, sizeof ks_st);
	state = S_KE_LIST;
	shot("erase a store");
}

static void vanity_screens(void)
{
	state = S_VAN_KIND;
	for (vsel = 0; vsel < VAN_KINDS; vsel++) { vtop = vsel >= VAN_ROWS ? vsel - VAN_ROWS + 1 : 0; shot("vanity: kind"); }
	vsel = vtop = 0;
	for (vkind = 0; vkind < VAN_KINDS; vkind++) {
		snprintf(vcfg.prefix, sizeof vcfg.prefix, "%s", "abcdefghijklmnopqrstuvw");
		snprintf(vcfg.suffix, sizeof vcfg.suffix, "%s", "abcdefghijklmnopqrstuvw");
		vexpected = (uint64_t) 1 << 62;
		state = S_VAN_PLAN;
		vmsg[0] = 0; shot("vanity: plan");
		snprintf(vmsg, sizeof vmsg, "%s", "The letter l cannot be in a bech32 address: change the text"); shot("vanity: plan");
		vmsg[0] = 0;
	}
	vkind = 0;
	state = S_VAN_ENT;
	entropy_init(&vpool, 0); shot("vanity: entropy");
	vpool.credit = 300u << 8; shot("vanity: entropy");
	state = S_VAN_RUN;
	van.tried = 123456789012ull; van.expected = (uint64_t) 1 << 62;
	for (van.rejected = 0; van.rejected < 2; van.rejected++) shot("vanity: search");
	van.rejected = 0;
	state = S_VAN_DONE;
	for (int k = 0; k < 2; k++) {
		van.cfg.kind = k ? VK_CREATE2 : VK_NPUB;
		fill(van.addr, k ? 43 : 64, "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m ");
		memset(van.key, 0x5a, sizeof van.key);
		fill(vkey_text, 64, "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99 ");
		van.tried = 123456789012ull;
		for (int m = 0; m < 2; m++) { snprintf(vmsg, sizeof vmsg, "%s", m ? "Saved: key 2 of store 1" : ""); vqr_on = 0; shot("vanity: found"); }
		vmsg[0] = 0;
		qr_ok = qr_encode(&qr, (const uint8_t *) vkey_text, strlen(vkey_text), QR_ECC_M) > 0;
		if (qr_ok) qr_scale = qr_view_scale(&qr);
		vqr_on = 1; shot("vanity: QR code"); vqr_on = 0;
	}
}

static void multisig_screens(void)
{
	state = S_MS_LIST;
	ms_rc = MCF_NO_CARD; mse_n = 0; shot("multisig wallets");
	ms_rc = 0; mse_n = 0; shot("multisig wallets");
	mse_n = MS_ENTS;
	for (int i = 0; i < 4; i++) { ms_wal[i].type = (uint8_t) (i % 3); ms_wal[i].m = 2; ms_wal[i].n = 3; }
	for (int i = 0; i < MS_ENTS; i++) { mse[i].kind = i % 3; mse[i].widx = i % 4; mse[i].block = i + 1; snprintf(mse[i].name, sizeof mse[i].name, "BESCES-00000PSXXMS%02d", i); }
	for (mse_sel = 0; mse_sel < mse_n; mse_sel++) { mse_top = mse_sel >= 7 ? mse_sel - 6 : 0; shot("multisig wallets"); }
	snprintf(ms_msg, sizeof ms_msg, "%s", "Registered: wallet 1a2b3c4d, 2 of 3"); shot("multisig wallets");
	ms_msg[0] = 0; mse_sel = mse_top = 0;
	state = S_MS_CONFIRM;
	ms_new.type = 2; ms_new.m = 3; ms_new.n = MS_MAXKEYS; ms_new.sorted = 1;
	for (int i = 0; i < MS_MAXKEYS; i++) memset(ms_new.key[i].fp, 0x10 + i, 4);
	ms_ours_idx = 2;
	fill(ms_addr, 63, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 ");
	for (ms_cur = 0; ms_cur < 2; ms_cur++)
		for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL / 2) shot("multisig: register");
	hold = 0; ms_cur = 0;
	state = S_MS_DEL;
	for (int k = 0; k < 2; k++) { mse[0].kind = k ? 2 : 0; for (hold = 0; hold <= HOLD_NORMAL; hold += HOLD_NORMAL / 2) shot("multisig: remove"); }
	hold = 0;
}

int main(void)
{
	ui_range_clear(UI_R_L);                      /* the signer runs with the main card and its own texts, the language module is not loaded */
	ui_reg_a();
	ui_reg_b();
	words_prepare();
	for (int lg = 0; lg < 2; lg++)                /* English, then Hungarian: the texts are longer, the layout has to hold */
	for (int y = 240; y <= 256; y += 16) {
		ui_lang_set(lg ? UI_LANG_HU : UI_LANG_EN);
		lc_snapshot(lg == 0);
		lc_tag = lg ? "[hu] " : "";
		screen_yres = ctx.yres = y;
		ctx.xres = 640;
		show_status("Checking the transaction", "reading the shielded outputs: up to a minute");
		menus();
		keyboards();
		request_screens();
		view_screens();
		result_screens();
		key_screens();
		vanity_screens();
		multisig_screens();
	}
	printf("signer screens: %d frames, %d layout problems\n", lc_frames, lc_bad);
	return lc_bad ? 1 : 0;
}
