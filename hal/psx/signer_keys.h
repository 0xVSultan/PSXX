/*
 * Keys menu of the signer overlay (SIGNER_KEYS): the one place for the keys of the card in slot 2 and for raw keys.
 *
 * Included by signer_app.c, which provides the screen helpers, the card code and the state machine; this file adds its states.
 *   Home "Keys" -> S_KM_MENU         Load a key from the card (S_KEY_LIST) / Import a raw key / Delete keys / Erase a key store
 *   Import       -> S_RK_KIND        secp256k1 (Bitcoin, Ethereum, Nostr...: hex, nsec1 or WIF), ed25519 (TON, Solana...: hex), Monero spend key (hex)
 *                -> S_RK_TEXT        the key is typed; the checksum of an nsec or a WIF is checked (core/coin/keyparse.c)
 *                -> S_KEY_CONFIRM    the address of the key to compare; X uses it, square saves it on the card (the screens of the main card, ks_save_modal), O wipes
 *   Delete keys  -> S_KEY_LIST       the list of the keys, X marks, START goes on
 *                -> S_KD_CONFIRM     hold X: the marked keys are deleted (a store with every key marked is removed whole; a store with a password asks for it once)
 *   Erase a store-> S_KE_LIST        one store, or all the stores of the card
 *                -> S_KE_CONFIRM     hold X
 */
#include "coin/keyparse.h"
#include "hash/sha256.h"

static int      kmsel, rksel, rk_kind, rk_len, kesel;
static int      kd_mode;                                        /* the list of keys marks keys to delete instead of opening one */
static uint8_t  kd_mark[KSD_MAX_STORES][KS_SLOTS];             /* by store and key (the n-th live key of a store) */

static int kd_count(void)
{
	int n = 0;

	for (int s = 0; s < ks_st.nstores; s++) for (int k = 0; k < ks_st.st[s].n && k < KS_SLOTS; k++) n += kd_mark[s][k] != 0;
	return n;
}

/* ---- delete several keys ---- */

/* the marked keys (ksd_del_marked: a store with every key marked is removed, a store with a password that loses some of its keys needs its key: asked once, then this is called again) */
static void kd_run(void)
{
	int deleted = 0, need = 0, kidx = -1, r;

	show_status(T(TXT_DELETING_THE_KEY), T(TXT_KEEP_THE_CARD_IN_THE_SLOT));
	for (int s = 0; s < ks_st.nstores; s++) if (ks_kok && ks_kblock == ks_st.st[s].block && ks_kid == ks_st.st[s].id) kidx = s;
	r = ksd_del_marked(KS_PORT, &ks_st, kd_mark, kidx, kidx >= 0 ? ks_k : NULL, ks_img, &deleted, &need);
	if (r == KSD_ERR_PASSWORD) { ks_store = need; ks_pw_for = 3; ks_ask(T(TXT_PASSWORD_OF_THE_STORE)); return; }
	secure_zero(ks_img, sizeof ks_img);
	ks_forget_key();
	keys_scan();
	memset(kd_mark, 0, sizeof kd_mark);
	if (r == KSD_OK) sprintf(msg, T(TXT_DELETED_N_KEYS), deleted);
	else sprintf(msg, T(TXT_NOT_DELETED_N), key_error(r));
	state = S_KEY_LIST;
}

/* ---- erase vaults, the single keys, everything ---- */

static int ke_nvaults(void) { int n = 0; for (int i = 0; i < ks_st.nstores; i++) n += !ks_st.st[i].single; return n; }
static int ke_vault(int n) { for (int i = 0; i < ks_st.nstores; i++) if (!ks_st.st[i].single && n-- == 0) return i; return -1; }
static int ke_singles(void) { int n = 0; for (int i = 0; i < ks_st.nstores; i++) n += ks_st.st[i].single ? ks_st.st[i].n : 0; return n; }
static int ke_rows(void) { return ks_st.nstores ? ke_nvaults() + (ks_st.single_head ? 1 : 0) + 1 : 0; }

/* the rows: the vaults, the single keys (if there are any), then everything */
static void ke_run(void)
{
	int r = KSD_OK, nv = ke_nvaults(), all = kesel == ke_rows() - 1;

	show_status(T(TXT_DELETING_THE_KEY), T(TXT_KEEP_THE_CARD_IN_THE_SLOT));
	if (all) {
		for (int s = ks_st.nstores - 1; s >= 0 && r == KSD_OK; s--) if (!ks_st.st[s].single) r = ksd_remove_store(KS_PORT, &ks_st, s);
		if (r == KSD_OK) r = ksd_remove_singles(KS_PORT, &ks_st);
	}
	else if (kesel < nv) r = ksd_remove_store(KS_PORT, &ks_st, ke_vault(kesel));
	else r = ksd_remove_singles(KS_PORT, &ks_st);
	ks_forget_key();
	keys_scan();
	kesel = 0;
	if (r == KSD_OK) sprintf(msg, T(TXT_ERASED));
	else sprintf(msg, T(TXT_NOT_DELETED_N), key_error(r));
	state = S_KE_LIST;
}

/* ---- import a raw key ---- */

enum { RK_SECP, RK_ED, RK_XMR, RK_SR, RK_ORCHARD, RK_ADA, RK_N };   /* the kinds of the menu, in its order */

static int rk_raw_curve(int kind) { return kind == RK_SECP ? 2 : kind == RK_ED ? 1 : kind == RK_SR ? 3 : kind == RK_ORCHARD ? 4 : kind == RK_ADA ? 5 : 0; }
static int rk_kind_of(int raw_curve) { return raw_curve == 2 ? RK_SECP : raw_curve == 3 ? RK_SR : raw_curve == 4 ? RK_ORCHARD : raw_curve == 5 ? RK_ADA : RK_ED; }
static int rk_savable(int kind) { (void) kind; return 1; }          /* the card format (core/keyfile.c) holds every kind: the Cardano key (64 bytes) in an entry of two frames */
static int rk_curve_code(int kind) { return kind == RK_SECP ? KS_CURVE_SECP256K1 : kind == RK_SR ? KS_CURVE_SR25519 : kind == RK_ORCHARD ? KS_CURVE_ORCHARD : kind == RK_ADA ? KS_CURVE_CARDANO : KS_CURVE_ED25519; }

static void rk_addr(char *out, size_t cap, const char *id)
{
	hd_path none;

	memset(&none, 0, sizeof none);
	if (chain_address(out, cap, chain_find(id), &hs, &none) <= 0) out[0] = 0;
}

/* every address the key is good for: a key of a curve serves several chains (the address that the vanity search looked for comes first, if the entry names one) */
static void rk_addrs(void)
{
	switch (rk_kind) {
	case RK_SECP:
		if (!(ck_hint && van_hint_address(ck_hint, hs.raw, ck_addr, sizeof ck_addr) > 0)) { ck_hint = 0; rk_addr(ck_addr, sizeof ck_addr, "eth"); }
		rk_addr(ck_btc, sizeof ck_btc, "btc84");
		rk_addr(ck_npub, sizeof ck_npub, "nostr");
		break;
	case RK_ED: rk_addr(ck_addr, sizeof ck_addr, "ton"); rk_addr(ck_btc, sizeof ck_btc, "sol"); break;
	case RK_SR: rk_addr(ck_addr, sizeof ck_addr, "dotsr"); rk_addr(ck_btc, sizeof ck_btc, "ksm"); break;
	case RK_ORCHARD: rk_addr(ck_addr, sizeof ck_addr, "zecu"); break;
	default: rk_addr(ck_addr, sizeof ck_addr, "ada"); break;
	}
}

/* the key is typed and right: it is loaded like a key from the card and its addresses are shown to be compared (S_KEY_CONFIRM) */
static void rk_load(const uint8_t *k)
{
	ck_hint = 0;
	ks_label[0] = 0;
	ck_addr[0] = ck_npub[0] = ck_btc[0] = 0;
	from_card = 1;
	rk_pending = 1;
	if (rk_kind == RK_XMR) {
		ks_type = KS_TYPE_MONERO;
		if (!hs_valid) hs.no_bip = 1;
		memcpy(hs.xmr_seed, k, 32);
		hs.xmr_ok = 1;
		hs_valid = 1;
		confirm_prepare();                                                  /* the main address */
		return;
	}
	ks_type = KS_TYPE_RAW;
	memset(hs.seed, 0, sizeof hs.seed);
	memset(hs.entropy, 0, sizeof hs.entropy);
	hs.entlen = 0;
	hs.no_bip = 1;
	memset(hs.raw, 0, sizeof hs.raw);
	memcpy(hs.raw, k, rk_kind == RK_ADA ? 64 : 32);
	hs.raw_curve = rk_raw_curve(rk_kind);
	hs_valid = 1;
	rk_addrs();
	rk_show = 1;
	state = S_KEY_CONFIRM;
}

/* a raw key read from the card: the same screen as for a typed one, without the option to save it */
static void rk_show_prepare(void)
{
	rk_kind = rk_kind_of(hs.raw_curve);
	ck_addr[0] = ck_npub[0] = ck_btc[0] = 0;
	rk_addrs();
	rk_show = 1;
	state = S_KEY_CONFIRM;
}

static void rk_done(void)
{
	uint8_t k[64];
	int r;

	switch (rk_kind) {
	case RK_SECP: r = keyparse_secp256k1(kb.text, k); break;
	case RK_ED: r = keyparse_ed25519(kb.text, k); break;
	case RK_ADA: r = keyparse_cardano(kb.text, k); break;
	default: r = keyparse_hex32(kb.text, k); break;                        /* Monero, sr25519, Orchard: 64 hex digits */
	}
	rk_len = kb.len;
	if (r != KP_OK) {
		if (r == KP_ERR_CHECKSUM) sprintf(msg, T(TXT_THE_CHECKSUM_IS_WRONG_A_CHARACTER));
		else if (r == KP_ERR_RANGE) sprintf(msg, rk_kind == RK_ADA ? T(TXT_NOT_A_VALID_EXTENDED_KEY) : T(TXT_NOT_A_VALID_SECP256K1_KEY));
		else sprintf(msg, rk_kind == RK_SECP ? T(TXT_NOT_A_KEY_HEX_NSEC1_OR_WIF_IS) : rk_kind == RK_ED ? T(TXT_NOT_A_KEY_HEX_KEYPAIR_S_OR_ED25519_IS)
		                        : rk_kind == RK_ADA ? T(TXT_NOT_A_CARDANO_KEY_128_HEX_DIGITS_OR) : T(TXT_NEEDS_EXACTLY_64_HEX_DIGITS));
		return;
	}
	kb_wipe(&kb);
	kb_clip_wipe();
	msg[0] = 0;
	rk_load(k);
	secure_zero(k, sizeof k);
}

/* What the screens of the main card (ks_save_modal) chose for a key over 32 bytes, which they do not write themselves (they seal and write entries of one frame): the main card's variables,
 * named here with other C names so that they do not meet the statics of the signer. */
extern ksd_state a_ks_st __asm__("ks_st");
extern int       a_ks_target __asm__("ks_target"), a_ks_new_pw __asm__("ks_new_pw"), a_ks_use_store __asm__("ks_use_store");
extern uint8_t   a_ks_k[32] __asm__("ks_k"), a_ks_work[KS_DATA] __asm__("ks_work");
extern ks_dir    a_ks_pwd __asm__("ks_pwd");
extern char      a_ks_label[] __asm__("ks_label"), a_ks_plabel[] __asm__("ks_plabel"), a_ks_slabel[] __asm__("ks_slabel"), a_pass[] __asm__("ks_pass");
extern void ks_wipe(void);

/* the long key (64 bytes: the Cardano extended key) is sealed and written as an entry of two frames, the way do_keysave of the main card does it for one of one frame: the same inputs
 * make the same salt and nonce; a single key goes into a block of the single keys that has room for a pair, else into a new block; a new vault is made first and taken back when the key does
 * not go in. The text of the result is in msg. */
static void rk_commit_long(const uint8_t *key, int elen, int type, int flags)
{
	static const char DOMAIN[] = "psx-key-rnd", DOMAIN2[] = "psx-store-nonce";
	uint8_t frame[KS_ENTRY_MAX], rnd[32], lab[KS_LABEL_STORE], tf[2], nonce[32];
	sha256_ctx h;
	int n = KS_ERR_ARG, r = KSD_ERR_ARG, store = a_ks_target >= 0 ? a_ks_target : -1, singles = 0;

	show_status(T(TXT_SEALING_THE_KEY), a_ks_use_store ? NULL : T(TXT_ABOUT_15_SECONDS));
	memset(lab, 0, sizeof lab);
	memcpy(lab, a_ks_label, strlen(a_ks_label));
	tf[0] = (uint8_t) type;
	tf[1] = (uint8_t) flags;
	sha256_init(&h);
	sha256_update(&h, (const uint8_t *) DOMAIN, sizeof DOMAIN - 1);
	sha256_update(&h, tf, 2);
	sha256_update(&h, lab, sizeof lab);
	sha256_update(&h, key, (size_t) elen);
	sha256_final(&h, rnd);
	if (a_ks_target == -2) {
		n = ks_own_entry_seal2(frame, (const uint8_t *) a_pass, strlen(a_pass), BLOB_ITER_KEY, rnd, type, flags, key, elen, a_ks_label, a_ks_plabel[0] ? a_ks_plabel : NULL);
		store = -1;
		for (int i = 0; i < a_ks_st.nstores && store < 0; i++) if (a_ks_st.st[i].single && ks_next_pair(&a_ks_st.st[i].dir) >= 0) store = i;
		if (n == KS_OK) {
			show_status(T(TXT_SAVING_TO_THE_CARD), T(TXT_ABOUT_10_SECONDS));
			r = store >= 0 ? ksd_add2(KS_PORT, &a_ks_st, store, frame, -1, NULL, a_ks_work) : ksd_new_single(KS_PORT, &a_ks_st, frame, 2, (uint16_t) (rnd[28] << 8 | rnd[29]), a_ks_work, &store);
		}
	} else {                                                           /* a vault: a new one is made with the key in it (sealed for its id, slot 0 and seq 1) */
		uint16_t id = store < 0 ? ksd_free_id(&a_ks_st, (uint16_t) (rnd[28] << 8 | rnd[29])) : a_ks_st.st[store].id;
		uint32_t seq = store < 0 ? 0 : a_ks_st.st[store].seq;
		int slot = store < 0 ? 0 : ks_next_pair(&a_ks_st.st[store].dir);

		if (slot < 0) r = KSD_ERR_FULL;
		else {
			sha256_init(&h);
			sha256_update(&h, (const uint8_t *) DOMAIN2, sizeof DOMAIN2 - 1);
			sha256_update(&h, rnd, 32);
			sha256_update(&h, (const uint8_t *) &id, sizeof id);
			sha256_update(&h, (const uint8_t *) &seq, sizeof seq);
			sha256_update(&h, (const uint8_t *) &slot, sizeof slot);
			sha256_final(&h, nonce);
			n = ks_store_entry_seal2(frame, a_ks_k, id, slot, nonce, seq + 1, type, flags, key, elen, a_ks_label);
			if (n == KS_OK) {
				show_status(T(TXT_SAVING_TO_THE_CARD), T(TXT_ABOUT_10_SECONDS));
				if (store < 0) r = ksd_make_block(KS_PORT, &a_ks_st, 0, a_ks_slabel, &a_ks_pwd, a_ks_k, id, frame, 2, a_ks_work, &store);
				else r = ksd_add2(KS_PORT, &a_ks_st, store, frame, -1, a_ks_k, a_ks_work);
			}
		}
	}
	for (int i = 0; i < a_ks_st.nstores; i++) singles += a_ks_st.st[i].single ? a_ks_st.st[i].n : 0;
	if (r == KSD_OK && n == KS_OK) {
		if (a_ks_target == -2) sprintf(msg, T(TXT_SAVED_SINGLE_KEY_N), singles);
		else sprintf(msg, T(TXT_SAVED_KEY_N_OF_STORE_N), a_ks_st.st[store].n, a_ks_st.st[store].dir.label);
	}
	else if (r == KSD_ERR_FULL) sprintf(msg, T(TXT_NOT_SAVED_NO_FREE_BLOCK));
	else if (r == KSD_ERR_LIMIT) sprintf(msg, T(TXT_NOT_SAVED_STORE_OR_KEY_LIMIT));
	else if (r == KSD_ERR_VERIFY) sprintf(msg, T(TXT_NOT_SAVED_THE_CARD_DID_NOT));
	else if (r == KSD_ERR_CHANGED) sprintf(msg, T(TXT_NOT_SAVED_THE_CARD_WAS_CHANGED));
	else if (n != KS_OK || r == KSD_ERR_ARG || r == KSD_ERR_IMAGE || r == KSD_ERR_PASSWORD) sprintf(msg, T(TXT_NOT_SAVED_INTERNAL_ERROR));
	else sprintf(msg, T(TXT_NOT_SAVED_N), key_error(r));
	secure_zero(rnd, sizeof rnd);
	secure_zero(nonce, sizeof nonce);
	secure_zero(frame, sizeof frame);
	secure_zero(&h, sizeof h);
}

/* the typed key goes to the card through the screens of the main card (the store, the labels, the password); a key over 32 bytes is finished here */
static void rk_save(void)
{
	char label[KS_LABEL + 1];
	int flags = rk_kind == RK_XMR ? 0 : rk_curve_code(rk_kind) << KS_FLAG_CURVE_SHIFT, done;

	if (!rk_savable(rk_kind)) return;
	snprintf(label, sizeof label, "%s", T(TXT_IMPORTED_KEY));
	done = ks_save_modal(ks_type, rk_kind == RK_XMR ? hs.xmr_seed : hs.raw, rk_kind == RK_ADA ? 64 : 32, flags, label);
	gpu_init(&ctx, 20, 20, 60);
	if (rk_kind == RK_ADA) {
		if (done) rk_commit_long(hs.raw, 64, ks_type, flags);
		ks_wipe();
	}
}

/* the confirm screen of a typed key (below its title and the line of its name): what kind of key, and the addresses to compare */
static void rk_confirm_body(void)
{
	static const uint16_t KIND[RK_N] = {TXT_A_SECP256K1_KEY_ETHEREUM_BITCOIN_NOSTR, TXT_AN_ED25519_KEY_TON_SOLANA, TXT_MONERO_MAIN_ADDRESS, TXT_AN_SR25519_KEY_POLKADOT_KUSAMA,
	                                    TXT_A_ZCASH_ORCHARD_SPENDING_KEY_UNIFIED, TXT_A_CARDANO_PAYMENT_KEY_ENTERPRISE_ADDRESS};

	dim(16, 56, rk_kind == RK_SECP && ck_hint ? van_hint_name(ck_hint) : T(KIND[rk_kind]));
	wrapped(16, 76, ck_addr, 48, rk_kind == RK_ORCHARD ? 3 : 2, 255, 255, 255);
	if (rk_kind == RK_SECP || rk_kind == RK_ED || rk_kind == RK_SR) {
		if (ck_btc[0]) wrapped(16, 94, ck_btc, 48, 1, 255, 255, 255);
		if (rk_kind == RK_SECP && ck_npub[0]) { dim(16, 112, T(TXT_NOSTR_NPUB_2)); wrapped(16, 130, ck_npub, 48, 2, 255, 255, 255); }
	} else if (rk_kind == RK_ADA) {
		wrapped(16, 118, T(TXT_THE_STAKING_PART_IS_NOT_KNOWN_THIS), 48, 3, 255, 160, 80);
	}
}

/* ---- the screens ---- */

static void km_start_list(int del)
{
	kd_mode = del;
	memset(kd_mark, 0, sizeof kd_mark);
	ks_forget_key();
	keys_scan();
	state = S_KEY_LIST;
}

static void km_update(uint16_t pr)
{
	switch (state) {
	case S_KM_MENU:
		ui_nav(&kmsel, 4, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_HOME; break; }
		if (pr & PAD_CROSS) {
			if (kmsel == 0) km_start_list(0);
			else if (kmsel == 1) { rksel = 0; msg[0] = 0; state = S_RK_KIND; }
			else if (kmsel == 2) km_start_list(1);
			else { ks_forget_key(); keys_scan(); kesel = 0; state = S_KE_LIST; }
		}
		break;
	case S_RK_KIND:
		ui_nav(&rksel, RK_N, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_KM_MENU; break; }
		if (pr & PAD_CROSS) {
			rk_kind = rksel;
			kb_init(&kb, T(rk_kind == RK_SECP ? TXT_KEY_HEX_NSEC1_OR_WIF : rk_kind == RK_ED ? TXT_KEY_HEX_KEYPAIR_S_OR_ED25519 : rk_kind == RK_ADA ? TXT_KEY_128_HEX_DIGITS_OR_ADDR_XSK1 : TXT_KEY_64_HEX_DIGITS), NULL, 1, 0);
			kb_set(&kb, rk_kind == RK_SECP ? 70 : rk_kind == RK_ED ? 100 : rk_kind == RK_ADA ? 200 : 64, rk_kind != RK_SECP && rk_kind != RK_ED && rk_kind != RK_ADA);      /* the full keyboard for the forms with letters, the hex keypad for 64 hex digits */
			rk_len = -1;
			msg[0] = 0;
			state = S_RK_TEXT;
		}
		break;
	case S_RK_TEXT: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) { kb_wipe(&kb); kb_clip_wipe(); msg[0] = 0; state = S_RK_KIND; }
		else if (r == KB_DONE) rk_done();
		break;
	}
	case S_KD_CONFIRM:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { state = S_KEY_LIST; break; }
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= HOLD_NORMAL) { hold = 0; armed = 0; kd_run(); }
		break;
	case S_KE_LIST: {
		int rows = ke_rows();

		ui_wrap(&kesel, rows, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { msg[0] = 0; state = S_KM_MENU; break; }
		if ((pr & PAD_CROSS) && rows) { hold = 0; armed = 0; msg[0] = 0; state = S_KE_CONFIRM; }
		break;
	}
	case S_KE_CONFIRM:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { state = S_KE_LIST; break; }
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= HOLD_NORMAL) { hold = 0; armed = 0; ke_run(); }
		break;
	default:
		break;
	}
}

static void km_hold_bar(void)
{
	gpu_draw_rect(&ctx, 2, 16, 124, GPU_XRES - 32, 10, 30, 30, 50);
	gpu_draw_rect(&ctx, 1, 16, 124, (GPU_XRES - 32) * hold / HOLD_NORMAL, 10, 220, 60, 60);
}

static void km_draw(void)
{
	char line[100];

	switch (state) {
	case S_KM_MENU: {
		static const uint16_t M[] = {TXT_LOAD_A_KEY_FROM_THE_CARD, TXT_IMPORT_A_RAW_KEY, TXT_DELETE_KEYS, TXT_ERASE_A_KEY_STORE,
		                             TXT_OPEN_A_KEY_SAVED_ON_CARD_2, TXT_TYPE_A_SECRET_KEY_USE_IT_OR, TXT_MARK_KEYS_OF_THE_STORES_AND, TXT_DELETE_A_WHOLE_STORE_OR_ALL};

		ui_menu_ids(TXT_KEY_FROM_THE_CARD, M, 4, 1, kmsel, TXT_HINT_CHOOSE_SELECT_BACK_2);
		break;
	}
	case S_RK_KIND: {
		static const uint16_t M[] = {TXT_SECP256K1_KEY, TXT_ED25519_KEY, TXT_MONERO_SPEND_KEY, TXT_SR25519_KEY, TXT_ORCHARD_SPENDING_KEY, TXT_CARDANO_EXTENDED_KEY,
		                             TXT_BITCOIN_ETHEREUM_NOSTR_HEX_NSEC_WIF, TXT_TON_SOLANA_THE_32_BYTE_SEED_AS, TXT_THE_SECRET_SPEND_KEY_AS_64_HEX, TXT_POLKADOT_KUSAMA_THE_MINI_SECRET_AS,
		                             TXT_ZCASH_SHIELDED_THE_32_BYTE_KEY_AS, TXT_PAYMENT_KEY_128_HEX_DIGITS_OR_ADDR};

		ui_menu_ids(TXT_IMPORT_A_RAW_KEY, M, RK_N, 1, rksel, TXT_HINT_CHOOSE_SELECT_BACK_2);
		break;
	}
	case S_RK_TEXT:
		if (rk_len != kb.len) msg[0] = 0;
		kb.note = msg[0] ? msg : NULL;
		kb.warn = 2;
		kb_draw(&ctx, &kb);
		break;
	case S_KD_CONFIRM:
		text(16, UI_TOP, T(TXT_DELETE_THE_MARKED_KEYS));
		sprintf(line, T(TXT_N_KEYS_MARKED_A_STORE_WITH_ALL), kd_count());
		wrapped(16, 28, line, 48, 3, 255, 255, 255);
		dim(16, 84, T(TXT_IT_CANNOT_BE_RESTORED_FROM_THE));
		dim(16, 102, T(TXT_KEEP_THE_RECOVERY_WORDS));
		km_hold_bar();
		dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_DELETE_BACK));
		break;
	case S_KE_LIST: {
		int rows = ke_rows(), nv = ke_nvaults(), top = kesel >= KEY_ROWS ? kesel - KEY_ROWS + 1 : 0;

		text(16, UI_TOP, T(TXT_ERASE_A_KEY_STORE));
		if (ks_rc) { sprintf(line, T(TXT_CARD_N), key_error(ks_rc)); ctext(16, 34, line, 255, 100, 100); }
		else if (!rows) dim(16, 34, T(TXT_NO_KEY_STORES_ON_THE_CARD));
		for (int i = 0, e = top; i < KEY_ROWS && e < rows; i++, e++) {
			if (e == rows - 1) strcpy(line, e == kesel ? "> " : "  "), strcat(line, T(TXT_ALL_THE_STORES));
			else if (e < nv) {
				const ksd_store *v = &ks_st.st[ke_vault(e)];

				sprintf(line, T(TXT_N_STORE_N_N_KEYS), e == kesel ? '>' : ' ', e + 1, v->n);
				if (v->dir.label[0]) sprintf(line + strlen(line), "  %.14s", v->dir.label);
			}
			else sprintf(line, T(TXT_N_SINGLE_KEYS_N), e == kesel ? '>' : ' ', ke_singles());
			ui_hl(16, 34 + i * LINE, e == kesel, line);
		}
		if (msg[0]) ctext(16, 34 + KEY_ROWS * LINE + 4, msg, 255, 160, 80);
		dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_ERASE_BACK));
		break;
	}
	case S_KE_CONFIRM: {
		int nv = ke_nvaults(), all = kesel == ke_rows() - 1;

		text(16, UI_TOP, T(all ? TXT_ERASE_EVERY_KEY_STORE : TXT_ERASE_THIS_STORE));
		if (!all) {
			if (kesel < nv) sprintf(line, T(TXT_N_STORE_N_N_KEYS), ' ', kesel + 1, ks_st.st[ke_vault(kesel)].n);
			else sprintf(line, T(TXT_N_SINGLE_KEYS_N), ' ', ke_singles());
			text(16, 40, line);
		}
		dim(16, 70, T(TXT_IT_CANNOT_BE_RESTORED_FROM_THE));
		dim(16, 90, T(TXT_KEEP_THE_RECOVERY_WORDS));
		km_hold_bar();
		dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_DELETE_BACK));
		break;
	}
	default:
		break;
	}
}
