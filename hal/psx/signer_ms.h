/*
 * Registered multisig wallets in the signer (the overlay build, SIGNER_KEYS): the descriptors of the multisig wallets whose cosigners' extended keys the signer knows, kept as
 * files on the card in slot 2 (core/sign/mswallet.h). With them a PSBT's multisig inputs are named by their script and the change that comes back to the wallet is
 * recognised, instead of trusting what the PSBT says about its keys.
 *
 * Included by signer_app.c, which provides the screen helpers, the card code and the state machine; this file adds its states.
 *   Home "Multisig wallets" -> S_MS_LIST   the registered wallets (files PSXXMS.., checked against the seed) and the descriptors waiting on the card (files PSXXMD..,
 *                                          put there with tools/psxx_tx.py ms-add)
 *   X on a descriptor -> S_MS_CONFIRM      who the cosigners are, whether one key is ours, the first address to compare with the coordinator; hold X to register
 *   square on a wallet -> S_MS_DEL         hold X to remove it
 */
#include "sign/mswallet.h"
#include "sign/btc.h"

#define MS_ENTS 8
#define MS_TAG "PSXXMS"                    /* a registered wallet */
#define MS_DTAG "PSXXMD"                   /* a descriptor to register: its text, from frame 2 (u32 length first) */

typedef struct { int block, kind, widx; char name[MCF_NAME]; } ms_ent;     /* kind: 0 registered (widx: its place in ms_wal), 1 descriptor file, 2 not usable with this seed */

static ms_ent    mse[MS_ENTS];
static int       mse_n, mse_sel, mse_top, ms_rc;
static ms_policy ms_wal[4], ms_new;
static int       ms_cur, ms_ours_idx;                 /* ms_nwal: declared before open_request */
static char      ms_msg[88], ms_addr[100];

static int ms_master(bip32_node *m)
{
	return hs_valid && !hs.no_bip && hs.entlen > 0 ? bip32_master(m, hs.seed, 64) : -1;
}

/* a file: frame 2 starts with the length (u32 LE), then the data */
static int ms_read_file(int block, uint8_t *buf, size_t cap, size_t *len)
{
	uint8_t f[MC_FRAME];
	size_t n, got;
	int r, frame = 2;

	r = mcf_read(1, block, frame++, f);
	if (r) return r;
	n = (size_t) f[0] | (size_t) f[1] << 8 | (size_t) f[2] << 16 | (size_t) f[3] << 24;
	if (n < 8 || n > cap) return MCF_IO;
	memcpy(buf, f + 4, n < MC_FRAME - 4 ? n : MC_FRAME - 4);
	got = MC_FRAME - 4;
	while (got < n && frame < 64) {
		r = mcf_read(1, block, frame++, f);
		if (r) return r;
		memcpy(buf + got, f, n - got < MC_FRAME ? n - got : MC_FRAME);
		got += MC_FRAME;
	}
	if (got < n) return MCF_IO;
	*len = n;
	return MCF_OK;
}

static int ms_write_file(const char *tag, const uint8_t *data, size_t len, const char *title)
{
	uint8_t f[MC_FRAME];
	mcf_entry e[1];
	int nfiles, next, blk, r, frame = MCF_FIRST_DATA;
	size_t o = 0, total = len + 4;

	r = mcf_scan(1, tag, e, 0, &nfiles, &next, &blk);
	if (r == MCF_OK && !blk) r = MCF_FULL;
	if (r == MCF_OK && total > 62 * MC_FRAME) r = MCF_FULL;
	if (r == MCF_OK) r = mcf_begin(1, blk, title, MCF_ICON_LOCK);
	while (r == MCF_OK && o < total) {
		memset(f, 0, sizeof f);
		for (size_t k = 0; k < MC_FRAME && o + k < total; k++) {
			size_t at = o + k;
			f[k] = at < 4 ? (uint8_t) (len >> (8 * at)) : data[at - 4];
		}
		r = mcf_write(1, blk, frame++, f);
		o += MC_FRAME;
	}
	if (r == MCF_OK) r = mcf_commit(1, blk, tag, next);
	return r;
}

/* the registered wallets (and with `files` the descriptors waiting) of the card in slot 2; the usable wallets go to the summary of the PSBTs */
static void ms_scan(int files)
{
	mcf_entry l[MS_ENTS];
	bip32_node m;
	int nf, nx, blk, have = ms_master(&m) == 0;
	uint8_t rec[MS_REC_MAX + 8];

	mse_n = ms_nwal = 0;
	ms_rc = mcf_scan(1, MS_TAG, l, MS_ENTS, &nf, &nx, &blk);
	for (int i = 0; ms_rc == MCF_OK && i < nf && mse_n < MS_ENTS; i++) {
		size_t len = 0;
		ms_ent *e = &mse[mse_n++];

		e->block = l[i].block;
		memcpy(e->name, l[i].name, MCF_NAME);
		e->kind = 2;
		e->widx = -1;
		if (have && ms_nwal < 4 && !ms_read_file(e->block, rec, sizeof rec, &len) && !ms_load(&ms_wal[ms_nwal], rec, len, &m)) {
			e->kind = 0;
			e->widx = ms_nwal++;
		}
	}
	if (files && ms_rc == MCF_OK && mcf_scan(1, MS_DTAG, l, MS_ENTS, &nf, &nx, &blk) == MCF_OK) {
		for (int i = 0; i < nf && mse_n < MS_ENTS; i++) {
			ms_ent *e = &mse[mse_n++];
			e->block = l[i].block;
			memcpy(e->name, l[i].name, MCF_NAME);
			e->kind = 1;
		}
	}
	psbt_set_wallets(ms_wal, ms_nwal);
	secure_zero(&m, sizeof m);
	mse_sel = mse_top = 0;
}

static const char *ms_type_name(int t) { return t == MS_WSH ? T(TXT_NATIVE_SEGWIT) : t == MS_SH_WSH ? T(TXT_NESTED_SEGWIT) : T(TXT_LEGACY_P2SH); }

static const char *ms_error(int e)
{
	return e == MSE_SYNTAX ? T(TXT_NOT_A_MULTISIG_DESCRIPTOR_OF_A) : e == MSE_CHECKSUM ? T(TXT_THE_CHECKSUM_OF_THE_DESCRIPTOR)
	     : e == MSE_KEY ? T(TXT_AN_EXTENDED_KEY_CANNOT_BE_READ) : e == MSE_ORIGIN ? T(TXT_A_KEY_HAS_NO_ORIGIN)
	     : e == MSE_LIMIT ? T(TXT_MORE_THAN_8_KEYS_OR_M_IS_MORE) : e == MSE_NOTOURS ? T(TXT_NONE_OF_THE_KEYS_IS_YOURS) : T(TXT_CANNOT_READ_IT);
}

/* the first receiving address of the wallet, on the network its account path names (the coin type of the origin of our key) */
static void ms_first_address(const ms_policy *p, int ours)
{
	static const char *const IDS[] = {"btc84", "", "ltc84", "doge", "", "dash"};
	uint8_t sc[MS_SCRIPT_MAX], sp[34];
	size_t sl, pl;
	unsigned coin = ours >= 0 && p->key[ours].depth > 1 ? p->key[ours].path[1] & 0x7fffffffu : 0;
	const btc_net *net = btc_net_for(chain_find(coin < 6 && IDS[coin][0] ? IDS[coin] : "btc84"));

	ms_addr[0] = 0;
	if (!net || ms_script(p, NULL, 0, 0, sc, &sl, sp, &pl)) return;
	btc_spk_text(net, sp, pl, ms_addr, sizeof ms_addr);
}

/* a descriptor file is chosen: read, parse, and the screen that asks */
static void ms_open_file(void)
{
	uint8_t *buf = req_buf;                                              /* the menus have no request open: its buffer is free */
	char *ms_dtext = (char *) req_buf + 1600;
	bip32_node m;
	size_t len = 0;
	int r, e;

	ms_msg[0] = 0;
	show_status(T(TXT_READING_THE_DESCRIPTOR), NULL);
	r = ms_read_file(mse[mse_sel].block, buf, sizeof buf - 1, &len);
	if (r) { snprintf(ms_msg, sizeof ms_msg, T(TXT_CANNOT_READ_IT_N), card_error(r)); return; }
	if (len > 1500) { snprintf(ms_msg, sizeof ms_msg, T(TXT_THAT_FILE_IS_TOO_LONG_FOR_A)); return; }
	memcpy(ms_dtext, buf, len);
	ms_dtext[len] = 0;
	show_status(T(TXT_CHECKING_THE_WALLET), T(TXT_ABOUT_5_SECONDS));
	e = ms_parse(&ms_new, ms_dtext);
	if (!e && ms_master(&m)) e = MSE_NOTOURS;
	if (!e) { ms_ours_idx = ms_ours(&ms_new, &m); secure_zero(&m, sizeof m); if (ms_ours_idx < 0) e = MSE_NOTOURS; }
	if (e) { snprintf(ms_msg, sizeof ms_msg, "%s", ms_error(e)); return; }
	ms_first_address(&ms_new, ms_ours_idx);
	ms_cur = 1;
	hold = 0;
	armed = 0;
	state = S_MS_CONFIRM;
}

static void ms_register(void)
{
	uint8_t rec[MS_REC_MAX + 8];
	bip32_node m;
	size_t n;
	uint8_t id[4], oid[4];
	int r;

	if (ms_master(&m)) { snprintf(ms_msg, sizeof ms_msg, T(TXT_LOAD_YOUR_SEED_FIRST)); state = S_MS_LIST; return; }
	ms_id(&ms_new, id);
	for (int i = 0; i < mse_n; i++) {                                    /* the same wallet again */
		if (mse[i].kind != 0) continue;
		ms_id(&ms_wal[mse[i].widx], oid);
		if (!memcmp(oid, id, 4)) { snprintf(ms_msg, sizeof ms_msg, T(TXT_THAT_WALLET_IS_REGISTERED)); secure_zero(&m, sizeof m); state = S_MS_LIST; return; }
	}
	if (ms_nwal >= 4) { snprintf(ms_msg, sizeof ms_msg, T(TXT_FOUR_WALLETS_ARE_THE_MOST)); secure_zero(&m, sizeof m); state = S_MS_LIST; return; }
	n = ms_save(&ms_new, &m, rec, sizeof rec);
	secure_zero(&m, sizeof m);
	show_status(T(TXT_SAVING_TO_THE_CARD), T(TXT_KEEP_THE_CARD_IN_THE_SLOT));
	r = n ? ms_write_file(MS_TAG, rec, n, "PSXX multisig") : MCF_IO;
	ms_scan(1);
	if (r == MCF_OK) snprintf(ms_msg, sizeof ms_msg, T(TXT_REGISTERED_WALLET_N), id[0], id[1], id[2], id[3]);
	else snprintf(ms_msg, sizeof ms_msg, T(TXT_NOT_SAVED_N), card_error(r));
	state = S_MS_LIST;
}

/* ---- the frame ---- */

static void ms_update(uint16_t pr)
{
	switch (state) {
	case S_MS_LIST:
		if (mse_n > 0 && (pr & PAD_DOWN)) mse_sel = (mse_sel + 1) % mse_n;
		if (mse_n > 0 && (pr & PAD_UP)) mse_sel = (mse_sel + mse_n - 1) % mse_n;
		if (mse_sel < mse_top) mse_top = mse_sel;
		if (mse_sel >= mse_top + 7) mse_top = mse_sel - 6;
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_HOME; break; }
		if ((pr & PAD_CROSS) && mse_n > 0) {
			if (mse[mse_sel].kind == 1) ms_open_file();
			else if (mse[mse_sel].kind == 0) { ms_new = ms_wal[mse[mse_sel].widx]; ms_cur = 0; ms_ours_idx = -1; { bip32_node m; if (!ms_master(&m)) { ms_ours_idx = ms_ours(&ms_new, &m); secure_zero(&m, sizeof m); } } ms_first_address(&ms_new, ms_ours_idx); state = S_MS_CONFIRM; }
		}
		if ((pr & PAD_SQUARE) && mse_n > 0 && mse[mse_sel].kind != 1) { hold = 0; armed = 0; state = S_MS_DEL; }
		break;
	case S_MS_CONFIRM:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { state = S_MS_LIST; break; }
		if (!ms_cur) break;
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= HOLD_NORMAL) { hold = 0; armed = 0; ms_register(); }
		break;
	case S_MS_DEL:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { state = S_MS_LIST; break; }
		if (!(in.ps.buttons & PAD_CROSS)) { armed = 1; hold = 0; }
		else if (armed && ++hold >= HOLD_NORMAL) {
			int r;
			hold = 0; armed = 0;
			show_status(T(TXT_REMOVING_IT), T(TXT_KEEP_THE_CARD_IN_THE_SLOT));
			r = mcf_invalidate(1, mse[mse_sel].block);
			ms_scan(1);
			if (r == MCF_OK) snprintf(ms_msg, sizeof ms_msg, T(TXT_REMOVED));
			else snprintf(ms_msg, sizeof ms_msg, T(TXT_NOT_REMOVED_N), card_error(r));
			state = S_MS_LIST;
		}
		break;
	default:
		break;
	}
}

static void ms_draw_keys(int y)
{
	char line[96];
	size_t o = 0;

	line[0] = 0;
	for (int k = 0; k < ms_new.n && o + 12 < sizeof line; k++) {
		if (k == ms_ours_idx) o += (size_t) snprintf(line + o, sizeof line - o, T(TXT_YOU_2));
		else o += (size_t) snprintf(line + o, sizeof line - o, "%02x%02x%02x%02x ", ms_new.key[k].fp[0], ms_new.key[k].fp[1], ms_new.key[k].fp[2], ms_new.key[k].fp[3]);
	}
	wrapped(16, y, line, 45, 2, 255, 255, 255);
}

static void ms_draw(void)
{
	char line[100];
	uint8_t id[4];

	switch (state) {
	case S_MS_LIST:
		text(16, UI_TOP, T(TXT_MULTISIG_WALLETS));
		if (ms_rc) { sprintf(line, T(TXT_CARD_N), card_error(ms_rc)); ctext(16, 34, line, 255, 100, 100); }
		else if (!mse_n) dim(16, 34, T(TXT_NONE_REGISTERED_NO_DESCRIPTORS));
		for (int i = 0, e = mse_top; i < 7 && e < mse_n; i++, e++) {
			const ms_ent *x = &mse[e];
			if (x->kind == 0) { const ms_policy *w = &ms_wal[x->widx]; ms_id(w, id); sprintf(line, T(TXT_N_WALLET_N_OF_N), e == mse_sel ? '>' : ' ', id[0], id[1], id[2], id[3], w->m, w->n, ms_type_name(w->type)); }
			else if (x->kind == 1) sprintf(line, T(TXT_N_TO_REGISTER_N), e == mse_sel ? '>' : ' ', x->name + 12);
			else sprintf(line, T(TXT_N_NOT_MADE_WITH_THIS_SEED), e == mse_sel ? '>' : ' ', x->block);
			if (e == mse_sel) ctext(16, 34 + i * LINE, line, 255, 220, 80); else text(16, 34 + i * LINE, line);
		}
		if (ms_msg[0]) ctext(16, 34 + 7 * LINE + 4, ms_msg, 255, 160, 80);
		dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_OPEN_REMOVE_BACK));
		break;
	case S_MS_CONFIRM:
		ms_id(&ms_new, id);
		text(16, UI_TOP, ms_cur ? T(TXT_REGISTER_THIS_WALLET) : T(TXT_REGISTERED_WALLET));
		sprintf(line, T(TXT_WALLET_N_OF_N_2), id[0], id[1], id[2], id[3], ms_new.m, ms_new.n, ms_type_name(ms_new.type));
		text(16, UI_TOP + LINE + 4, line);
		dim(16, UI_TOP + 2 * LINE + 4, ms_new.sorted ? T(TXT_KEYS_SORTED_WHEN_THE_SCRIPT_IS) : T(TXT_KEYS_IN_THIS_ORDER));
		ms_draw_keys(UI_TOP + 3 * LINE + 4);
		dim(16, UI_TOP + 5 * LINE + 8, T(TXT_FIRST_RECEIVING_ADDRESS_TO));
		wrapped(16, UI_TOP + 6 * LINE + 8, ms_addr, 46, 2, 255, 255, 255);    /* two lines: an address of 92 characters at most */
		if (ms_cur) {
			dim(16, 176, T(TXT_COMPARE_THE_COSIGNERS_AND_THE));
			gpu_draw_rect(&ctx, 2, 16, 196, GPU_XRES - 32, 8, 30, 30, 50);
			gpu_draw_rect(&ctx, 1, 16, 196, (GPU_XRES - 32) * hold / HOLD_NORMAL, 8, 90, 220, 90);
			dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_REGISTER_BACK));
		} else dim(16, UI_HINT2, T(TXT_HINT_BACK));
		break;
	case S_MS_DEL:
		text(16, UI_TOP, T(TXT_REMOVE_THIS_WALLET));
		if (mse[mse_sel].kind == 0) { ms_id(&ms_wal[mse[mse_sel].widx], id); sprintf(line, T(TXT_WALLET_N), id[0], id[1], id[2], id[3]); text(16, 40, line); }
		else text(16, 40, T(TXT_A_FILE_THAT_IS_NOT_USABLE_WITH));
		dim(16, 70, T(TXT_PSBTS_OF_THE_WALLET_ARE_THEN));
		dim(16, 90, T(TXT_THE_WALLET_ITSELF_IS_NOT));
		gpu_draw_rect(&ctx, 2, 16, 124, GPU_XRES - 32, 10, 30, 30, 50);
		gpu_draw_rect(&ctx, 1, 16, 124, (GPU_XRES - 32) * hold / HOLD_NORMAL, 10, 220, 60, 60);
		dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_REMOVE_BACK));
		break;
	default:
		break;
	}
}
