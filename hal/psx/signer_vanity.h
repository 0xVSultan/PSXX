/*
 * Vanity addresses in the signer (the overlay build, SIGNER_KEYS): looks for a private key whose address starts and/or ends with a text, or for a CREATE2 salt.
 * Included by signer_app.c, which provides the screen helpers, the keyboard, the card code and the state machine; this file adds its states.
 *
 * Flow:  HOME -> kind -> [CREATE2: deployer, init code hash] -> prefix -> suffix -> PLAN (what is asked, how long) -> entropy -> RUN -> DONE
 * RUN works in the idle time of the main loop (core/vanity/vanity.c), a few candidates at a time, and can be left with O at any moment. DONE shows the address and the
 * key (hex and, where there is one, WIF / nsec), as a QR code on request, and can save the key as a raw secp256k1 key to the key store of the card in slot 2.
 */
#include "vanity/vanity.h"
#include "coin/addr.h"

#define VAN_KINDS 11

typedef struct { uint16_t name; int kind; uint8_t version; const char *hrp; unsigned rate; } van_kind;

/* rate: candidates a second measured with tools/vbench (hal/psx/vbench.c) in no$psx; the real console may differ */
static const van_kind VKT[VAN_KINDS] = {
	{TXT_ETHEREUM_EVM_CHAINS_0X, VK_ETH, 0, NULL, 650},
	{TXT_BITCOIN_SEGWIT_BC1Q_2, VK_BECH32, 0, "bc", 780},
	{TXT_LITECOIN_SEGWIT_LTC1Q, VK_BECH32, 0, "ltc", 780},
	{TXT_BITCOIN_LEGACY_1, VK_P2PKH, 0x00, NULL, 780},
	{TXT_BITCOIN_NESTED_SEGWIT_3, VK_P2SH, 0x05, NULL, 460},
	{TXT_LITECOIN_LEGACY_L_2, VK_P2PKH, 0x30, NULL, 780},
	{TXT_DOGECOIN_D, VK_P2PKH, 0x1e, NULL, 780},
	{TXT_DASH_X, VK_P2PKH, 0x4c, NULL, 780},
	{TXT_NOSTR_PUBLIC_KEY_NPUB1, VK_NPUB, 0, NULL, 3300},
	{TXT_KASPA_KASPA_Q, VK_KASPA, 0, "kaspa", 3300},
	{TXT_CONTRACT_ADDRESS_CREATE2_0X, VK_CREATE2, 0, NULL, 880},
};

#define VAN_ROWS 7

static van_ctx       vctx;                               /* the tables of the kernel: 64 KB */
static vanity        van;
static vanity_cfg    vcfg;
static entropy_pool  vpool;
static int           vsel, vtop, vkind, vstart_frame, vqr_on, vstep_cnt;
static int           vwin_frame;                                  /* the rate is that of the last 10 seconds: the frame and the count at the start of that window */
static uint64_t      vwin_tried, vrate;
static char          vtitle[72], vhead[24], vtyped[24], vmsg[72], vtext[72], vpw[PW_MAX + 1], vkey_text[100], vlabel[KS_LABEL + 1];
static uint64_t      vexpected;
static uint8_t       vdep[20], vinit[32];
static int           vhave_dep;

static void van_wipe(void)
{
	secure_zero(&van, sizeof van);
	secure_zero(&vpool, sizeof vpool);
	secure_zero(vkey_text, sizeof vkey_text);
	secure_zero(vpw, sizeof vpw);
	secure_zero(vtext, sizeof vtext);
	secure_zero(&vctx, sizeof vctx);
	kb_wipe(&kb);
	kb_clip_wipe();
	qr_view_clear();
	qr_ok = 0;
	vqr_on = 0;
	vmsg[0] = 0;
}

static void van_fmt_count(char *o, uint64_t n)
{
	if (n < 10000) sprintf(o, "%u", (unsigned) n);
	else if (n < 10000000) sprintf(o, T(TXT_N_THOUSAND), (unsigned) (n / 1000));
	else if (n < 10000000000ULL) sprintf(o, T(TXT_N_MILLION), (unsigned) (n / 1000000));
	else if (n < 10000000000000ULL) sprintf(o, T(TXT_N_BILLION), (unsigned) (n / 1000000000ULL));
	else sprintf(o, T(TXT_MORE_THAN_10_TRILLION));
}

static void van_fmt_time(char *o, uint64_t s)
{
	if (s < 120) sprintf(o, "%u s", (unsigned) s);
	else if (s < 7200) sprintf(o, T(TXT_N_MIN), (unsigned) (s / 60));
	else if (s < 172800) sprintf(o, "%u.%u h", (unsigned) (s / 3600), (unsigned) (s % 3600 / 360));
	else if (s < 86400ULL * 3650) sprintf(o, T(TXT_N_DAYS), (unsigned) (s / 86400));
	else sprintf(o, T(TXT_NEVER_REALLY));
}

static uint64_t van_seconds(uint64_t cands, unsigned rate) { return cands / (rate ? rate : 1); }

/* the heading of a typing screen and the keyboard: hex digits only for the EVM kinds */
static void van_kb(const char *what, int hexpad, int limit)
{
	snprintf(vtitle, sizeof vtitle, "%s", what);
	kb_init(&kb, vtitle, NULL, 0, 0);
	kb_set(&kb, limit, hexpad);
}

static int van_hexpad(void) { return vcfg.kind == VK_ETH || vcfg.kind == VK_CREATE2; }

static void van_ask_prefix(void)
{
	char t[72];
	vanity_head(&vcfg, vhead, sizeof vhead);
	snprintf(t, sizeof t, T(TXT_AFTER_N_IT_STARTS_WITH_EMPTY), vhead);
	van_kb(t, van_hexpad(), 20);
	state = S_VAN_PRE;
}

static void van_ask_suffix(void)
{
	van_kb(T(TXT_IT_ENDS_WITH_EMPTY_ANYTHING), van_hexpad(), 20);
	state = S_VAN_SUF;
}

static int hexval_c(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

/* hex text -> bytes (exactly 2 * n digits) */
static int van_unhex(uint8_t *o, int n, const char *s, int len)
{
	if (len != 2 * n) return -1;
	for (int i = 0; i < n; i++) {
		int a = hexval_c(s[2 * i]), b = hexval_c(s[2 * i + 1]);
		if (a < 0 || b < 0) return -1;
		o[i] = (uint8_t) (a * 16 + b);
	}
	return 0;
}

static void van_check_plan(void)
{
	int e = vanity_check(&vcfg, &vexpected);
	vmsg[0] = 0;
	if (e == VE_HEAD) sprintf(vmsg, T(TXT_THE_TEXT_MUST_START_WITH_N), vhead);
	else if (e == VE_CHAR) sprintf(vmsg, T(TXT_A_CHARACTER_CANNOT_OCCUR_IN));
	else if (e == VE_LONG) sprintf(vmsg, T(TXT_TOO_LONG));
	else if (e == VE_RANGE) sprintf(vmsg, T(vcfg.kind == VK_KASPA ? TXT_NO_KASPA_ADDRESS_STARTS_LIKE_THAT : TXT_NO_ADDRESS_OF_THIS_KIND_LOOKS));   /* a Kaspa address has q p z or r as its second character */
	else if (e) sprintf(vmsg, T(TXT_NOT_POSSIBLE_N), e);
	state = S_VAN_PLAN;
}

static void van_start(void)
{
	uint8_t seed[32];
	int e;

	if (vcfg.kind == VK_CREATE2) {                                   /* nothing secret: any start will do */
		entropy_add_context(&vpool, ticks_cycles());
		entropy_digest(&vpool, seed);
	} else if (entropy_ready(&vpool)) entropy_extract(&vpool, seed);
	else entropy_digest(&vpool, seed);                               /* an emulator run: marked on the screen */
	show_status(T(TXT_PREPARING_THE_SEARCH), T(TXT_ABOUT_A_SECOND));
	e = vanity_start(&van, &vcfg, &vctx, seed);
	if (e == VE_SEED) {                                              /* one in 2^240: another start */
		sha256(seed, 32, seed);
		e = vanity_start(&van, &vcfg, &vctx, seed);
	}
	secure_zero(seed, sizeof seed);
	if (e) { sprintf(vmsg, T(TXT_CANNOT_START_N), e); state = S_VAN_PLAN; return; }
	vstart_frame = VSync(-1);
	vstep_cnt = 0;
	vwin_frame = vstart_frame; vwin_tried = 0; vrate = 0;
	vmsg[0] = 0;
	state = S_VAN_RUN;
}

/* the key as text for the screen and the QR code: WIF where wallets take one, nsec for Nostr, hex for the rest */
static void van_key_text(void)
{
	static const struct { uint8_t addr_ver, wif; } W[] = {{0x00, 0x80}, {0x05, 0x80}, {0x30, 0xb0}, {0x1e, 0x9e}, {0x4c, 0xcc}};
	vkey_text[0] = 0;
	if (van.cfg.kind == VK_NPUB) { addr_nsec(vkey_text, sizeof vkey_text, van.key); return; }
	if (van.cfg.kind == VK_P2PKH || van.cfg.kind == VK_P2SH) {
		for (unsigned i = 0; i < sizeof W / sizeof W[0]; i++)
			if (W[i].addr_ver == van.cfg.version) { addr_wif(vkey_text, sizeof vkey_text, W[i].wif, van.key); return; }
	}
	if (van.cfg.kind == VK_BECH32) { addr_wif(vkey_text, sizeof vkey_text, van.cfg.hrp[0] == 'l' ? 0xb0 : 0x80, van.key); return; }
	{
		static const char D[] = "0123456789abcdef";
		for (int i = 0; i < 32; i++) { vkey_text[2 * i] = D[van.key[i] >> 4]; vkey_text[2 * i + 1] = D[van.key[i] & 15]; }
		vkey_text[64] = 0;
	}
}

/* The kind of the address that the key was made for goes into the entry (the language bits of the flags, which a raw key does not use): the row of the table of the kinds plus one.
 * The key is the same secp256k1 key whatever the address, but the screen that shows it after the loading has to name the address that it was looked for. */
static const char *van_hint_name(int hint) { return hint >= 1 && hint <= VAN_KINDS ? T(VKT[hint - 1].name) : NULL; }

static int van_hint_address(int hint, const uint8_t key[32], char *out, size_t cap)
{
	vanity_cfg c;

	if (hint < 1 || hint > VAN_KINDS) return -1;
	memset(&c, 0, sizeof c);
	c.kind = VKT[hint - 1].kind; c.version = VKT[hint - 1].version; c.hrp = VKT[hint - 1].hrp;
	return vanity_address(&c, key, out, cap);
}

/* The save of the key goes through the screens of the main card (A): the choice of the store, a new store with its name and password, the password of an old one, the key of the store
 * or a password of its own, the label, the open label, the chooser of a random password - the same code, so the overlay has none of it. ks_save_modal (wallet_app.c) runs them until the
 * user is done; the key and a first guess for its label (the text that was looked for) go in, the kind of the address in the flags of the entry. */
extern int ks_save_modal(int type, const uint8_t *ent, int elen, int flags, const char *label);

static void van_save(void)
{
	int flags = (KS_CURVE_SECP256K1 << KS_FLAG_CURVE_SHIFT) | ((vkind + 1) << KS_FLAG_LANG_SHIFT);

	snprintf(vlabel, sizeof vlabel, T(TXT_VANITY_N), vtyped);
	ks_save_modal(KS_TYPE_RAW, van.key, 32, flags, vlabel);
	gpu_init(&ctx, 20, 20, 60);                                      /* the main card used the screen with its own state: ours starts again */
	secure_zero(vlabel, sizeof vlabel);
	vmsg[0] = 0;
	state = S_VAN_DONE;
}

/* ---- the frame ---- */

static void van_update(uint16_t pr)
{
	switch (state) {
	case S_VAN_KIND:
		if ((pr & PAD_DOWN) && vsel < VAN_KINDS - 1) vsel++;
		if ((pr & PAD_UP) && vsel > 0) vsel--;
		if (vsel < vtop) vtop = vsel;
		if (vsel >= vtop + VAN_ROWS) vtop = vsel - VAN_ROWS + 1;
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_HOME; break; }
		if (pr & PAD_CROSS) {
			memset(&vcfg, 0, sizeof vcfg);
			vkind = vsel;
			vcfg.kind = VKT[vsel].kind;
			vcfg.version = VKT[vsel].version;
			vcfg.hrp = VKT[vsel].hrp;
			vhave_dep = 0;
			if (vcfg.kind == VK_CREATE2) { van_kb(T(TXT_ADDRESS_OF_THE_DEPLOYER_40_HEX), 1, 40); state = S_VAN_DEP; }
			else van_ask_prefix();
		}
		break;
	case S_VAN_DEP: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_VAN_KIND; }
		else if (r == KB_DONE) {
			if (van_unhex(vdep, 20, kb.text, kb.len)) { kb.note = T(TXT_T_40_HEX_DIGITS); break; }
			memcpy(vcfg.deployer, vdep, 20);
			kb_wipe(&kb);
			van_kb(T(TXT_HASH_OF_THE_INIT_CODE_64_HEX), 1, 64);
			state = S_VAN_INIT;
		}
		break;
	}
	case S_VAN_INIT: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_VAN_KIND; }
		else if (r == KB_DONE) {
			if (van_unhex(vinit, 32, kb.text, kb.len)) { kb.note = T(TXT_T_64_HEX_DIGITS); break; }
			memcpy(vcfg.init_hash, vinit, 32);
			kb_wipe(&kb);
			van_ask_prefix();
		}
		break;
	}
	case S_VAN_PRE: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); state = S_VAN_KIND; }
		else if (r == KB_DONE) {
			snprintf(vtyped, sizeof vtyped, "%s", kb.text);
			if (kb.len) snprintf(vcfg.prefix, sizeof vcfg.prefix, "%s%s", vhead, vtyped); else vcfg.prefix[0] = 0;
			kb_wipe(&kb);
			van_ask_suffix();
		}
		break;
	}
	case S_VAN_SUF: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) { kb_wipe(&kb); van_ask_prefix(); }
		else if (r == KB_DONE) {
			snprintf(vcfg.suffix, sizeof vcfg.suffix, "%s", kb.text);
			kb_wipe(&kb);
			van_check_plan();
		}
		break;
	}
	case S_VAN_PLAN:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { van_ask_prefix(); break; }
		if ((pr & PAD_CROSS) && !vmsg[0]) {
			if (vcfg.kind == VK_CREATE2) van_start();
			else { entropy_init(&vpool, PSXX_EMULATED ? ENTROPY_EMULATED : 0); state = S_VAN_ENT; }
		}
		break;
	case S_VAN_ENT:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { entropy_wipe(&vpool); state = S_VAN_PLAN; break; }
		if ((pr & PAD_START) && (entropy_ready(&vpool) || (PSXX_EMULATED && vpool.events >= 40))) van_start();
		break;
	case S_VAN_RUN:
		if (pr & PAD_CIRCLE) { van_wipe(); state = S_HOME; break; }
		if (van.found) {
			van_key_text();
			vmsg[0] = 0;
			state = S_VAN_DONE;
		}
		break;
	case S_VAN_DONE:
		if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { van_wipe(); state = S_HOME; break; }
		if ((pr & PAD_CROSS) && van.cfg.kind != VK_CREATE2) {
			vqr_on = !vqr_on;
			qr_ok = 0;
			if (vqr_on && qr_encode(&qr, (const uint8_t *) vkey_text, strlen(vkey_text), QR_ECC_M) > 0) {
				qr_ok = 1;
				qr_scale = qr_view_scale(&qr);
				qr_view_upload(&qr, qr_scale);
			} else vqr_on = 0;
		}
		if ((pr & PAD_SQUARE) && van.cfg.kind != VK_CREATE2 && !vqr_on) van_save();
		break;
	default:
		break;
	}
}

/* the work of the idle time while RUN: a few candidates a go, short enough for the frame */
static void van_idle(void)
{
	if (state == S_VAN_RUN && !van.found) {
		vanity_step(&van, 3);
		vstep_cnt++;
	}
}

static void van_draw(void)
{
	char line[100];

	switch (state) {
	case S_VAN_KIND:
		text(16, UI_TOP, T(TXT_VANITY_ADDRESS));
		dim(16, UI_TOP + LINE, T(TXT_WHICH_ADDRESSES));
		for (int i = 0, e = vtop; i < VAN_ROWS && e < VAN_KINDS; i++, e++) {
			sprintf(line, "%c %s", e == vsel ? '>' : ' ', T(VKT[e].name));
			if (e == vsel) ctext(16, 46 + i * LINE, line, 255, 220, 80); else text(16, 46 + i * LINE, line);
		}
		dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_SELECT_BACK));
		break;
	case S_VAN_DEP: case S_VAN_INIT: case S_VAN_PRE: case S_VAN_SUF:
		kb_draw(&ctx, &kb);
		break;
	case S_VAN_PLAN: {
		char cnt[40], tm[24];
		int y = UI_TOP;

		text(16, y, T(TXT_VANITY_ADDRESS)); y += LINE;
		sprintf(line, "%.50s", T(VKT[vkind].name)); dim(16, y, line); y += LINE + 4;
		sprintf(line, T(TXT_STARTS_WITH_N), vcfg.prefix[0] ? vcfg.prefix : "anything"); text(16, y, line); y += LINE;
		sprintf(line, T(TXT_ENDS_WITH_N), vcfg.suffix[0] ? vcfg.suffix : "anything"); text(16, y, line); y += LINE + 4;
		if (vmsg[0]) {
			ctext(16, y, vmsg, 255, 100, 100);
			dim(16, UI_HINT2, T(TXT_HINT_CHANGE_THE_TEXT));
			break;
		}
		van_fmt_count(cnt, vexpected);
		sprintf(line, T(TXT_ABOUT_N_TRIES_TO_FIND_ONE), cnt); text(16, y, line); y += LINE;
		van_fmt_time(tm, van_seconds(vexpected, VKT[vkind].rate));
		sprintf(line, T(TXT_AT_N_A_SECOND_N), VKT[vkind].rate, tm);
		if (van_seconds(vexpected, VKT[vkind].rate) > 86400) ctext(16, y, line, 255, 160, 80); else text(16, y, line);
		y += LINE;
		dim(16, y, T(TXT_HALF_OF_THE_SEARCHES_END));
		dim(16, UI_HINT2, T(TXT_HINT_START_CHANGE_THE_TEXT));
		break;
	}
	case S_VAN_ENT: {
		uint32_t bits = entropy_bits(&vpool);
		int ready = entropy_ready(&vpool) || (PSXX_EMULATED && vpool.events >= 40);

		text(16, UI_TOP, T(TXT_ENTROPY_FOR_THE_START_KEY));
		dim(16, 28, ready ? T(TXT_HINT_ENOUGH_STARTS_THE_SEARCH) : T(TXT_PRESS_BUTTONS_MOVE_THE_STICKS));     /* its icon reaches 24 .. 50 */
		gpu_draw_rect(&ctx, 2, 16, 58, GPU_XRES - 32, 16, 30, 30, 50);
		gpu_draw_rect(&ctx, 1, 16, 58, (GPU_XRES - 32) * (bits > ENTROPY_MIN_BITS ? ENTROPY_MIN_BITS : bits) / ENTROPY_MIN_BITS, 16, ready ? 60 : 220, ready ? 220 : 160, 60);
		sprintf(line, T(TXT_BITS_N), (unsigned) bits, ENTROPY_MIN_BITS); text(16, 88, line);
		sprintf(line, T(TXT_EVENTS_N), (unsigned) vpool.events); text(16, 88 + LINE, line);
		dim(16, 170, T(TXT_EVERY_KEY_THE_SEARCH_FINDS));
		dim(16, UI_HINT2, T(TXT_HINT_START_BACK));
		if (PSXX_EMULATED) ctext(16, 140, T(TXT_EMULATED_TIMING_IGNORED_NOT), 255, 160, 80);
		break;
	}
	case S_VAN_RUN: {
		char cnt[40], tm[24];
		int hz = GetVideoMode() == MODE_PAL ? 50 : 60, fr = VSync(-1) - vstart_frame, y = UI_TOP;
		uint64_t secs = (uint64_t) (fr > 0 ? fr : 1) / (uint64_t) hz;

		text(16, y, T(TXT_SEARCHING)); y += LINE;
		sprintf(line, "%.50s", T(VKT[vkind].name)); dim(16, y, line); y += LINE;
		sprintf(line, "%.46s", vcfg.prefix[0] ? vcfg.prefix : "anything"); text(16, y, line); y += LINE;
		sprintf(line, "... %.40s", vcfg.suffix[0] ? vcfg.suffix : "anything"); text(16, y, line); y += LINE + 6;
		van_fmt_count(cnt, van.tried);
		sprintf(line, T(TXT_TRIED_N), cnt); text(16, y, line); y += LINE;
		{   /* the candidates a second over the last 10 seconds (the average since the start hides a change of the speed, and the first seconds weigh on it for ever) */
			int wf = VSync(-1) - vwin_frame;

			if (wf >= 10 * hz) { vrate = (van.tried - vwin_tried) * (uint64_t) hz / (uint64_t) wf; vwin_frame += wf; vwin_tried = van.tried; }
			sprintf(line, T(TXT_RATE_N_A_SECOND), (unsigned) (vrate ? vrate : van.tried * (uint64_t) hz / (uint64_t) (fr > 0 ? fr : 1)));   /* the first 10 seconds: the average so far */
			text(16, y, line); y += LINE;
		}
		van_fmt_time(tm, secs); sprintf(line, T(TXT_ELAPSED_N), tm); text(16, y, line); y += LINE;
		van_fmt_count(cnt, van.expected);
		sprintf(line, T(TXT_HALF_OF_THE_SEARCHES_ARE_DONE), cnt); dim(16, y, line); y += LINE;
		{
			uint64_t pct = van.expected ? van.tried * 50 / van.expected : 0;     /* 50 % at the median */
			gpu_draw_rect(&ctx, 2, 16, y + 2, GPU_XRES - 32, 10, 30, 30, 50);
			gpu_draw_rect(&ctx, 1, 16, y + 2, (int) ((GPU_XRES - 32) * (pct > 100 ? 100 : pct) / 100), 10, 90, 160, 255);
		}
		if (van.rejected) { sprintf(line, T(TXT_N_HITS_REJECTED_BY_THE_CHECK), van.rejected); ctext(16, 186, line, 255, 100, 100); }
		dim(16, UI_HINT2, T(TXT_HINT_STOP));
		break;
	}
	case S_VAN_DONE: {
		int y = UI_TOP;

		if (vqr_on) {
			text(16, UI_TOP, T(TXT_PRIVATE_KEY_SCAN_IT_THEN_LEAVE));
			if (qr_ok) qr_view_draw(&ctx, 12, 16, 26, &qr, qr_scale);           /* 360 pixels wide at most: 16 .. 376 */
			dim(400, UI_HINT2, T(TXT_HINT_BACK_3));
			break;
		}
		text(16, y, van.cfg.kind == VK_CREATE2 ? T(TXT_FOUND_THE_SALT) : T(TXT_FOUND)); y += LINE;
		y += wrapped(16, y, van.addr, 46, 3, 255, 255, 255) * LINE + 4;
		if (van.cfg.kind == VK_CREATE2) {
			char hx[72];
			static const char D[] = "0123456789abcdef";
			dim(16, y, T(TXT_SALT_32_BYTES_HEX)); y += LINE;
			for (int i = 0; i < 32; i++) { hx[2 * i] = D[van.key[i] >> 4]; hx[2 * i + 1] = D[van.key[i] & 15]; }
			hx[64] = 0;
			y += wrapped(16, y, hx, 34, 2, 255, 220, 80) * LINE;
			sprintf(line, T(TXT_AFTER_N_TRIES), (unsigned long long) van.tried);
			dim(16, y + 4, line);
		} else {
			sprintf(line, T(TXT_PRIVATE_KEY_AFTER_N_TRIES), (unsigned long long) van.tried);
			dim(16, y, line); y += LINE;
			wrapped(16, y, vkey_text, 46, 3, 255, 220, 80);                     /* three lines at most: down to 166 */
		}
		if (vmsg[0]) ctext(16, UI_HINT1, vmsg, 255, 220, 80);
		if (van.cfg.kind == VK_CREATE2) dim(16, UI_HINT2, T(TXT_HINT_WIPE_AND_LEAVE));
		else dim(16, UI_HINT2, T(TXT_HINT_QR_SAVE_TO_CARD_2_WIPE_AND));
		break;
	}
	default:
		break;
	}
}
