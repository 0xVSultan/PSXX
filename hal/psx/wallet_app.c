/*
 * Offline wallet generator: collect entropy from the controller, choose what to create, show the recovery words,
 * then the addresses.
 *
 *   BIP39 12 or 24 words  -> Bitcoin (legacy + segwit), Ethereum/ETC, Dogecoin, Nostr
 *   Monero 25 words       -> Monero main address
 *   12 + 25 / 24 + 25     -> both from the same entropy, with independent keys; two sets of words to write down,
 *                            one address list to page through
 *
 * Flow:  COLLECT (buttons -> entropy pool) -> TYPE -> [derive] -> WORDS (one screen per word set, paged) -> ADDRESSES
 *
 * Secrets (entropy, seed, mnemonic, keys) live in RAM only, never on the memory card, and are wiped as soon as they
 * are no longer needed: entropy, seed and keys right after derivation, each word set when the user confirms it.
 * All text is drawn with the mixed case bitmap font (font.h); lines are at most 28 characters (10 pixels each).
 * Build with -DPSXX_EMULATED=1 to not credit timing events (use it for emulator runs; timing is deterministic there).
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
#include "coin.h"
#include "dice.h"
#include "cdrom.h"
#include "cdlog.h"
#include "cdview.h"
#include "mcfile.h"
#include "keystore.h"
#include "pwtools.h"
#include "blob.h"
#include "b64.h"
#include "ur.h"
#include "timer.h"
#include "entropy.h"
#include "util.h"
#include "hash/sha256.h"
#include "ec/ed25519.h"
#include "ec/secp256k1.h"
#include "ec/pallas.h"
#include "coin/bip39.h"
#include "coin/words.h"
#include "coin/wallet.h"
#include "coin/xmr.h"
#include "coin/xpub.h"
#include "hash/keccak.h"
#include "coin/xmr_seed.h"
#include "qr.h"
#include "coin/chains.h"
#include "coin/path.h"
#include "coin/substrate.h"
#include "coin/ton.h"
#include "hash/sha512.h"
#include "qr_view.h"
#ifdef WITH_LOADER
#include "loader.h"
#include "release.h"
#include "source_ui.h"
#include "lang_api.h"
#include "handoff.h"
#endif

#ifndef PSXX_EMULATED
#define PSXX_EMULATED 0
#endif

enum state { S_SPLASH, S_HOME, S_ENCMENU, S_RESTOPT, S_REST, S_REST_PASS, S_SOURCE, S_COLLECT, S_COIN, S_DICE, S_CD, S_TYPE, S_TYPE2, S_STYLE, S_CUSTOM, S_PASS, S_WORDS, S_VERIFY, S_ADDR,
             S_CHAINS, S_CHAIN, S_SECRET, S_PATH, S_PATHTXT, S_ENC_KIND, S_ENC_TEXT, S_ENC_PASS, S_ENC_OUT, S_ENC_NAME, S_DEC_LIST, S_DEC_HEX, S_DEC_PASS, S_DEC_OUT,
             S_KS_STORE, S_KS_SLABEL, S_KS_SPW, S_KS_LABEL, S_KS_PLABEL, S_KS_PASS, S_KS_DONE, S_PW_CHOOSE, S_PW_SHOW, S_RAW_KEY, S_RAW_CURVE, S_SIGNER, S_XPUB, S_PID };
#define S_MODAL_END ((enum state) 0x7f)                 /* where the key save that the overlay asked for (ks_save_modal) is over: not a screen */
enum wtype { W_BIP39_12, W_BIP39_24, W_MONERO, W_BOTH_12, W_BOTH_24, W_TON, W_ENCRYPT, W_COUNT };

#define HOLD_FRAMES 75              /* ~1.5 s at 50 Hz */
#define LINE 20                     /* line height of the menus (the font cell is 18 pixels high) */
#define WORDS_PER_PAGE 25           /* every word set fits on one screen (3 columns) */
#define VQ 4                        /* words asked in the check after each word set */
#define VOPTS 5                     /* choices per question */
#define XMR_SUB_MAX 999             /* the subaddresses of account 0 that can be shown, one at a time (L1 / R1, L2 / R2 by ten), derived on demand */
#define XMR_SUB_PAGE 2
#define XMR_INT_PAGE 3              /* the integrated address: the main address with a payment ID (R2 types another one) */
#define XMR_PAGES 4                 /* main address, view key, a subaddress, integrated address */
#define COIN_STEPS (26 + COIN_BOUNCE_STEPS)              /* frames of the flip animation */
#define MAX_FLIPS ENTROPY_MIN_BITS
#define MAX_ROLLS 100               /* a d6 is credited 661/256 = 2.58 bits: 100 rolls reach 256 bits */
#define UNITS(bits) ((uint32_t) (bits) * 256u)
#define NSOURCES 4
#define MARGIN 16
#define RIGHT (GPU_XRES - MARGIN)

static RenderContext ctx;
static input_state   in;
static entropy_pool  pool;
static entropy_pool  bgpool;                         /* runs along all the time: every button of every screen goes in; only ever mixed into other secrets (pwtools.h) */
static enum state    state;
static enum wtype    wtype;
static char          mnemonic[768];                  /* BIP39 words; in another language the NFKD sentence (a Korean one of 24 words is up to 746 bytes) */
static char          xmr_mnemonic[XMR_MAX_MNEMONIC]; /* Monero 25 words */
static wallet_addrs  addrs;
static char          xmr_addr[100];
static int           vq, vsel, vcorrect, vfail, vattempt, vpos[VQ];   /* word check */
static char          vopt[VOPTS][13];
static char          vword[13];                       /* the word asked for, to tell a program error from a mismatch */
static int           vsane, vwhy;                     /* vsane: the right choice is the word on the paper; vwhy: 1 chose wrong, 2 none match */
static uint8_t       flips[MAX_FLIPS];                /* coin flips entered but not yet in the pool (1 = heads) */
#define COIN_HOLD_MAX 8             /* frames of holding a button that give the highest toss; then the coin is thrown by itself */
static int           nflips, coin_step = -1, coin_start, coin_height = 30, coin_hold, coin_face;   /* coin_face: the button being held (0: none) */
static uint8_t       rolls[MAX_ROLLS];                /* dice rolls entered but not yet in the pool (1..6) */
static int           nrolls, dsel = 1, srcsel;
static uint32_t      coin_units, dice_units;          /* credit of the manual sources so far, 1/256 bit units */
static cd_disc        disc;                            /* CD seek test (test mode, nothing is credited) */
static cd_seek_result cd_last;
static int            cd_rc, log_rc, cd_pending, cd_have_pos, nseek;
static uint32_t       cd_pos, cd_target, cd_tpress;
static uint16_t       cd_r, cd_a;
static entropy_pool  jsaved;                         /* pool as it was when the joystick screen was opened */
#define TXT_TAG "PSXXTX"
#define TXT_MAX 1024                /* bytes that can be encrypted (text, or hex digits / 2) */
#define BLOB_BUF (TXT_MAX + BLOB_OVERHEAD + 54)
#define QR_CAP 271                  /* bytes of one QR code (version 10, level L) */
#define QR_WARN_PCT 85              /* the meter warns from here */
#define UR_FRAG 50                  /* message bytes per animated UR part (a part is about 140 characters) */
static uint8_t       enc_blob[BLOB_BUF];             /* encrypted text (public data): made here or read from the card */
static int           enc_len, dec_rc, dn, dsel_i, enc_hex, txt_len, dec_len, dec_hexview, dec_scroll;
static char          enc_b64[4 * ((BLOB_BUF + 2) / 3) + 1];
static char          enc_hexs[2 * BLOB_BUF * 9 / 8 + 4];   /* the blob in hex, groups of 8 digits */
static uint8_t       txt[KB_MAX / 2 + 1];             /* data to encrypt (secret) */
static char          dec_text[BLOB_BUF + 1];          /* decrypted data (secret) */
static char          dec_hexs[2 * BLOB_BUF * 9 / 8 + 4];   /* the same in hex (secret) */
static char          note[48];
#define NAME_MAX_BYTES 24            /* name of a saved text (public: it is stored in plain text next to the ciphertext) */
static char          dnames[8][NAME_MAX_BYTES + 1];
#define NAME_MARK 0xFE              /* first byte of a file that starts with a name: 0xFE, length, name, then the length of the blob */                        /* the capacity meter of the keyboard */
static ur_plan       urp;                             /* the animated UR of the blob */
static char          urtxt[400];
static int           out_ur, ur_seq, ur_tick, ur_fpp = 12, out_page, out_scroll;
static char          msg[48];
static int           splash_stage, splash_cur, splash_p, splash_pd, splash_hold, splash_out, fade_in;   /* the start screen */
static int           ropt_row, rest_nw, rest_kind, rest_goal;   /* restore options: row, index of the word count, what is restored (0 BIP39 words, 1 TON phrase, 2 a raw key), words wanted */
static int           raw_sel;                          /* the curve of an imported raw key */
/* Watch-only export (L1 on an address page): the extended public key of the account and its descriptor, as text and QR code, for BlueWallet, Sparrow, Electrum. All public. */
static int           xp_sel, xp_have, xp_page, xp_qr;
static char          xp_key[XPUB_KEY_MAX], xp_desc[XPUB_DESC_MAX];
static uint8_t       ton_seed[32];                     /* the ed25519 seed of the TON wallet (the 100000 PBKDF2 rounds are not repeated), for saving it to a card; restart() wipes it */
static int           ton_seed_ok;
static int           hsel, esel, rest_len;             /* start menu, encryption menu, text length when an error was shown */
static int           addr_modal_on;                    /* the address pages are asked for by the signer (addr_modal): no signing from them, holding SELECT gives them back */
#ifdef WITH_LOADER
/* M4: the signer is a package on the B card (its slot of memmap.h). The screens that choose the source, read and check it are source_ui.c; when the
 * overlay is in place it is called and does not come back (the signer is the program from then on). Both overlays stay in memory once they are loaded (loader.h): the Home item runs
 * them straight away the next time, without the card; holding L1 while choosing it wipes the overlay and reads it again. */
#define SIGNER_PKG "BESCES-00000PSXXPK01"
#define SIGNER_GROUP LDR_GROUP_SIGNER
#define LANG_GROUP LDR_GROUP_LANG                    /* the language module, in the same package */
static su            sui;
psxx_handoff_t       psxx_handoff;                     /* the seed for the signer (handoff.h) */
static int           sframe;
static char          sig_msg[56];
static enum state    sig_back = S_HOME;                 /* where cancelling the loading of the signer goes: the home menu, or the address page it was started from */
static int           release_filled(void)
{
	for (int i = 0; i < 32; i++) if (psxx_release_info.key[i] || psxx_release_info.base_id[i]) return 1;
	return 0;
}
/* the resident signer runs; it does not come back (if it ever does, its bss is wiped and it stays in memory) */
static void run_signer(void);
static void run_lang(void);
#define HOME_N 5
#else
#define HOME_N 3
#endif
static enum state    src_next = S_TYPE;                /* where the entropy screen goes on: the seed types or the encryption */
static mcf_entry     dlist[8];
static kb_state      kb;                              /* BIP39 passphrase entry */
char                 pass[KB_MAX + 1] __asm__("ks_pass");   /* the first entry, kept to compare with the repeat (the signer reads it as ks_pass for a key over 32 bytes) */
static int           use_pass, pass_stage, pass_err, used_pass;
static int           tsel, t2sel, w24, wxmr;           /* the "What to create" menu and the BIP39 options */
static hd_secret     hs;                              /* the BIP39 secret, kept while the address pages are open (wiped by restart) */
static char          hs_pass[KB_DEFAULT_LIMIT + 1];
#ifdef WITH_LOADER
static int           bip_loc, xmr_loc;                 /* the BIP39 / Monero words of this seed are kept by the language module (it shows them) */
#endif
static int           hs_valid, hs_loc;                 /* hs_loc: the language id of the words the seed was made from, 0 for English (saved with the entropy: the signer needs that language to make the same seed) */
/* Key save: the BIP39 entropy of the wallet on the address pages, or the Monero seed on its words page, goes into a password-protected key
 * store of the card in slot 2. The secret is copied here for the few screens it takes and wiped when they end. */
#define KS_PORT 1
/* What the signer overlay reads when it finishes a save of its own (a key over 32 bytes: ks_save_modal returns 1 and these hold the choices): the store list, the chosen row, the way
 * of sealing, the keys and passwords, the labels, the scratch block. They are not static; the rest is. */
ksd_state            ks_st;
static uint8_t       ks_ent[32];
uint8_t              ks_work[KS_DATA];
static int           ks_elen, ks_type, ks_flags, ks_rc, ks_back, ks_dry, ks_dry_go;
int                  ks_target, ks_new_pw, ks_use_store;      /* ks_target: -2 a single key, -1 a new vault, else the index in ks_st of the vault */
static int           ks_sel;                           /* the row of the choice: the single key, the vaults, a new vault */
char                 ks_label[KS_LABEL_STORE + 1], ks_plabel[KS_PUBLIC + 1], ks_slabel[KS_STORE_LABEL + 1];
static char          ks_msg[64];
uint8_t              ks_k[32];                          /* the key of the store password, for the few screens of a save */
ks_dir               ks_pwd;                            /* flags, rounds, salt and check value of the password of a new store */
static int           ks_kok;
/* Choosing a password for an encrypted text or a key file: typed by hand (the entropy is estimated and a weak one is warned about), or suggested (15 random characters, or 8
 * random words of the BIP39 list), see core/pwtools.h. A suggestion comes from secret entropy: the pool for a text, the key itself for a key file. */
enum { PW_FOR_TEXT = 0, PW_FOR_KEY = 1, PW_FOR_STORE = 2 };
static int           pw_for, pw_sel, pw_kind, pw_count, pw_sug_bits, pw_warned, pw_armed;
static char          pw_sug[PW_MAX + 1], pw_again[PW_MAX + 1];
static uint8_t       xmr_view[32], xmr_spend_pub[32], xmr_view_pub[32];   /* private view key (no spending power) + public spend key */
static char          xmr_view_hex[65];
static char          xmr_sub[100], xmr_int[110], xmr_pid_hex[17];
static int           xmr_sub_idx = 1, xmr_sub_have;   /* the subaddress the page shows, the one in xmr_sub (0: none yet) */
static int           page, hold, failed, words_idx, words_page;
static qr_code       qr;                           /* address QR code (public data) */
static int           qr_mode, qr_dirty, qr_scale, qr_ok;

static int has_bip39(void)  { return wtype != W_MONERO && wtype != W_ENCRYPT && wtype != W_TON; }
static int has_ton(void)    { return wtype == W_TON; }
#define TON_PAGES 4
static int has_monero(void) { return wtype == W_MONERO || wtype == W_BOTH_12 || wtype == W_BOTH_24; }
static int bip39_count(void) { return (wtype == W_BIP39_24 || wtype == W_BOTH_24 || wtype == W_TON) ? 24 : 12; }
/* address pages: the five BIP39 coins first (if any), then Monero (if any) */
static int page_count(void) { return has_ton() ? TON_PAGES : (has_bip39() ? WALLET_STEPS : 0) + (has_monero() ? XMR_PAGES : 0); }
static int monero_base(void) { return has_bip39() ? WALLET_STEPS : 0; }
static int page_is_monero(int p) { return has_monero() && p >= monero_base(); }
static int monero_page(void) { return page - monero_base(); }   /* 0 main, 1 view key, 2.. subaddress 1.. */
/* word screens: BIP39 first (if any), then Monero */
static int words_screens(void) { return (has_bip39() || has_ton() ? 1 : 0) + (has_monero() ? 1 : 0); }
static int words_is_monero(int idx) { return has_monero() && idx == (has_bip39() || has_ton() ? 1 : 0); }
static int words_total(void) { return words_is_monero(words_idx) ? 25 : bip39_count(); }
static int words_pages(void) { return (words_total() + WORDS_PER_PAGE - 1) / WORDS_PER_PAGE; }

#include "ui_draw.h"

/* `s` in lines of at most `width` pixels, broken at spaces (a word that is too long is cut), at most `maxlines`; returns the y under the last line. */
static int wrap_text(int x, int y, int width, int maxlines, const char *s, int r, int g, int b)
{
	char line[100];

	for (int lines = 0; lines < maxlines; lines++) {
		size_t len = 0, brk = 0;                      /* the bytes that fit, the last place where a line may end */

		while (*s == ' ') s++;
		if (!*s) break;
		for (;;) {
			size_t k = len + 1;
			if (s[len] == 0) { brk = len; break; }
			while (((uint8_t) s[k] & 0xC0) == 0x80) k++;                 /* a whole UTF-8 character */
			if (k >= sizeof line) break;
			memcpy(line, s, k);
			line[k] = 0;
			if (font_width(line) > width) break;
			len = k;
			if (s[len] == ' ') brk = len;
		}
		if (!brk) brk = len ? len : 1;
		memcpy(line, s, brk);
		line[brk] = 0;
		ctext(x, y, line, r, g, b);
		y += font_cell_h() + 2;
		s += brk;
	}
	return y;
}

static void qr_warn(void)                                  /* in the title line, right of the title: every QR code on a screen */
{
	const char *const w = T(TXT_QR_WARN);

	dim(GPU_XRES - 16 - font_width(w), UI_TOP, w);
}

/* Long strings that must be read exactly (addresses), split into lines that fill the screen width. */
static void wrapped(int x, int y, const char *s, int chunk)
{
	char buf[72];
	if (chunk <= 0) chunk = (GPU_XRES - 2 * x) / font_cell_w();
	int line_h = font_cell_h() + 2;
	size_t n = strlen(s);
	if (chunk > (int) sizeof buf - 1) chunk = (int) sizeof buf - 1;
	for (size_t o = 0; o < n; o += (size_t) chunk, y += line_h) {
		size_t l = n - o < (size_t) chunk ? n - o : (size_t) chunk;
		memcpy(buf, s + o, l);
		buf[l] = 0;
		font_draw(&ctx, 6, x, y, buf, 255, 255, 255);          /* slots 6..11: the hint lines (z 0) use 0..5 for their icons */
	}
}

/* A string of two values with a space between them (the keys of MWEB): each is wrapped on its own, with an empty line between them, so that where one ends and the other begins is clear. */
static void wrapped2(int x, int y, const char *s)
{
	char a[72];
	const char *sp = strchr(s, ' ');
	int per = (GPU_XRES - 2 * x) / font_cell_w(), n, lines;

	if (!sp || (size_t) (sp - s) >= sizeof a) { wrapped(x, y, s, 0); return; }
	n = (int) (sp - s);
	memcpy(a, s, (size_t) n);
	a[n] = 0;
	lines = (n + per - 1) / per;
	{                                                       /* a value that needs two lines is split into two lines of the same length */
		int m = (int) strlen(sp + 1), c1 = n > per ? (n + 1) / 2 : 0, c2 = m > per ? (m + 1) / 2 : 0;
		lines = n > per ? 2 : 1;
		wrapped(x, y, a, c1);
		wrapped(x, y + (lines + 1) * (font_cell_h() + 2), sp + 1, c2);
	}
}

static void bar(int x, int y, int w, int h, uint32_t value, uint32_t max, int r, int g, int b)
{
	gpu_draw_rect(&ctx, 3, x - 2, y - 2, w + 4, h + 4, 200, 200, 200);
	gpu_draw_rect(&ctx, 2, x, y, w, h, 30, 30, 50);
	if (value > max) value = max;
	if (value) gpu_draw_rect(&ctx, 1, x, y, (int) ((uint32_t) w * value / max), h, r, g, b);
}

static void show_status(const char *l1, const char *l2)
{
	text(16, 90, l1);
	if (l2) dim(16, 90 + LINE + 4, l2);
	gpu_present(&ctx);
}

#ifdef WITH_LOADER
static void run_signer(void)
{
	const ldr_overlay *sg = ldr_resident(LDR_SLOT_SIGNER);

	show_status(T(TXT_STARTING_THE_SIGNER), T(TXT_THE_B_CARD_STAYS_IN_ITS_SLOT));
	LOG("[ldr] the signer: code %08x..%08x, bss %08x..%08x; the language module is %s%s\n", (unsigned) sg->load, (unsigned) (sg->load + sg->size), (unsigned) sg->bss,
	       (unsigned) (sg->bss + sg->bss_size), ldr_resident(LDR_SLOT_LANG) ? "in memory" : "not loaded", psxx_lang ? " and on" : "");
	ldr_call(sg);                                       /* the signer runs from here on; it returns only if it was stopped */
	gpu_init(&ctx, 20, 20, 60);                          /* the signer used the screen with its own state */
	sig_msg[0] = 0;
	state = S_HOME;
}

static void run_lang(void)
{
	LOG("[ldr] the language module: entered (%s)\n", psxx_lang ? "a language is on" : "no language is on");
	ldr_call_args(ldr_resident(LDR_SLOT_LANG), &ctx, &in, GetVideoMode() == MODE_PAL ? 50 : 60);   /* the module draws and reads on its own, then returns; it stays in memory */
	LOG("[ldr] the language module: returned (%s)\n", psxx_lang ? "a language is on" : "no language is on");
	state = S_HOME;
}

/* The signer and the language module come from the B card in one reading (the screens of source_ui.c); what is wanted starts at once if it is in memory already. back: where cancelling goes. */
enum { B_SIGNER, B_LANG };
static int b_next;

static void b_open(int what, enum state back)
{
	b_next = what;
	if (ldr_resident(what == B_LANG ? LDR_SLOT_LANG : LDR_SLOT_SIGNER)) {
		if (what == B_LANG) run_lang(); else run_signer();
		return;
	}
	sui.title = T(TXT_B_CARD);
	su_enter(&sui, sframe);
	sig_back = back;
	state = S_SIGNER;
}
#endif

static void progress_cb(int step, int total, void *user)
{
	char b[32];
	(void) user;
	sprintf(b, "%d / %d", step + 1, total);
	show_status(T(TXT_DERIVING_ADDRESSES), b);
}

/* BIP39: entropy -> words -> seed -> five addresses. */
static int generate_bip39(const uint8_t ent[32])
{
	uint8_t seed[64];
	int r = -1, nw = -1;

#ifdef WITH_LOADER
	if (psxx_lang) nw = psxx_lang->mnemonic(ent, bip39_count() == 24 ? 32 : 16, mnemonic, sizeof mnemonic);       /* the sentence in the language that is on, NFKD */
#endif
	hs_loc = 0;
#ifdef WITH_LOADER
	if (nw > 0) hs_loc = psxx_lang->id;
	bip_loc = nw > 0;
#endif
	if (nw > 0 || bip39_entropy_to_mnemonic(ent, bip39_count() == 24 ? 32 : 16, mnemonic, sizeof mnemonic) > 0) {
		show_status(T(TXT_HASHING_SEED), T(TXT_ABOUT_5_SECONDS));
		bip39_seed(mnemonic, used_pass ? kb.text : "", seed);
		memcpy(hs.seed, seed, 64);                              /* kept for the other chains and custom paths */
		hs.entlen = bip39_count() == 24 ? 32 : 16;
		memcpy(hs.entropy, ent, (size_t) hs.entlen);
		snprintf(hs_pass, sizeof hs_pass, "%s", used_pass ? kb.text : "");
		hs.passphrase = hs_pass;
		hs_valid = 1;
		r = wallet_derive(&addrs, seed, progress_cb, NULL);
	}
	secure_zero(seed, sizeof seed);
	return r;
}

/* Monero: the 32 entropy bytes become the (reduced) spend key; the 25 words encode it. */
static int generate_monero(const uint8_t ent[32])
{
	xmr_keys keys;
	uint8_t spend[32];
	static const char HEX[] = "0123456789abcdef";
	int r = -1;

	memcpy(spend, ent, 32);
	ed25519_sc_reduce32(spend);
	if (xmr_seed_encode(spend, xmr_mnemonic, sizeof xmr_mnemonic) > 0) {
		memcpy(hs.xmr_seed, spend, 32);                                      /* kept for the signer ("sign with this seed"), wiped by restart() */
		hs.xmr_ok = 1;
#ifdef WITH_LOADER
		if (psxx_lang) xmr_loc = psxx_lang->monero(xmr_mnemonic) == 0;       /* the same key in the words of the language that is on (kept there for the screen) */
#endif
		show_status(T(TXT_DERIVING_KEYS), T(TXT_ABOUT_2_SECONDS));
		xmr_keys_from_seed(&keys, spend);
		r = xmr_address(xmr_addr, sizeof xmr_addr, 0x12, keys.spend_pub, keys.view_pub) > 0 ? 0 : -1;
		/* the view key and the public spend key stay (view key page, subaddresses); the spend secret does not */
		memcpy(xmr_view, keys.view_sec, 32);
		memcpy(xmr_spend_pub, keys.spend_pub, 32);
		memcpy(xmr_view_pub, keys.view_pub, 32);
		for (int i = 0; i < 32; i++) {
			xmr_view_hex[2 * i] = HEX[xmr_view[i] >> 4];
			xmr_view_hex[2 * i + 1] = HEX[xmr_view[i] & 15];
		}
		xmr_view_hex[64] = 0;
	}
	secure_zero(spend, sizeof spend);
	secure_zero(&keys, sizeof keys);
	return r;
}

/* domain separated key: SHA-256(tag || entropy) */
static void derive_part(uint8_t out[32], const char *tag, const uint8_t ent[32])
{
	sha256_ctx c;
	sha256_init(&c);
	sha256_update(&c, (const uint8_t *) tag, strlen(tag));
	sha256_update(&c, ent, 32);
	sha256_final(&c, out);
	secure_zero(&c, sizeof c);
}

/* TON: its own 24 word phrase (BIP39 words, no BIP39 checksum), accepted when it is a "basic seed" (1 in 256), then the key
 * from 100000 PBKDF2 rounds. Takes minutes; hold SELECT to cancel. The wallet addresses are public, the key is wiped. */
static char ton_addr[TON_PAGES][50];

static int ton_progress(uint32_t done, uint32_t total, void *user)
{
	char b[56];
	(void) user;
	input_poll(&in, NULL);
	sprintf(b, T(TXT_N_HOLD_SELECT_TO_CANCEL), (unsigned long) (done * 100u / total));
	show_status(T(TXT_DERIVING_THE_TON_KEY), b);
	return (in.ps.buttons & PAD_SELECT) != 0;
}

static int generate_ton(const uint8_t ent[32])
{
	uint8_t h[64], e[64], seed[64], pub[32];
	int found = 0, r = -1;

	for (uint32_t trial = 0; trial < 4000 && !found; trial++) {
		sha512_ctx c;
		size_t o = 0;
		char b[56];
		uint8_t tb[4] = {(uint8_t) trial, (uint8_t) (trial >> 8), (uint8_t) (trial >> 16), (uint8_t) (trial >> 24)};

		sha512_init(&c);
		sha512_update(&c, (const uint8_t *) "psx-ton-words", 13);
		sha512_update(&c, ent, 32);
		sha512_update(&c, tb, 4);
		sha512_final(&c, h);
		for (int w = 0; w < 24; w++) {                          /* 24 indexes of 11 bits */
			unsigned idx = 0;
			char wd[BIP39_MAX_WORD + 1];
			int l;
			for (int bit = 0; bit < 11; bit++) {
				int k = w * 11 + bit;
				idx = (idx << 1) | (unsigned) ((h[k >> 3] >> (7 - (k & 7))) & 1);
			}
			l = bip39_word(idx, wd);
			memcpy(mnemonic + o, wd, (size_t) l);
			o += (size_t) l;
			mnemonic[o++] = w < 23 ? ' ' : 0;
		}
		input_poll(&in, NULL);
		if (in.ps.buttons & PAD_SELECT) break;
		sprintf(b, T(TXT_ATTEMPT_N_OF_ABOUT_256_HOLD), (unsigned long) trial + 1);
		show_status(T(TXT_LOOKING_FOR_A_VALID_TON_PHRASE), b);
		ton_entropy(e, mnemonic, "");
		found = ton_entropy_is_basic(e);
	}
	if (found && ton_private_seed_cb(seed, e, ton_progress, NULL) == 0) {
		ed25519_pubkey_from_seed(pub, seed);
		memcpy(ton_seed, seed, 32);
		ton_seed_ok = 1;
		ton_address(ton_addr[0], sizeof ton_addr[0], TON_V5R1, 0, pub);
		ton_address(ton_addr[1], sizeof ton_addr[1], TON_V5R1, 1, pub);
		ton_address(ton_addr[2], sizeof ton_addr[2], TON_V4R2, 0, pub);
		ton_address(ton_addr[3], sizeof ton_addr[3], TON_V4R2, 1, pub);
		r = 0;
	}
	secure_zero(h, sizeof h);
	secure_zero(e, sizeof e);
	secure_zero(seed, sizeof seed);
	if (r) secure_zero(mnemonic, sizeof mnemonic);
	return r;
}

/* The entropy and every derived secret are wiped before returning; only the words (needed on screen) and the
 * public addresses remain. */
static int generate(void)
{
	uint8_t ent[32], part[32];
	int r = -1;

#ifdef WITH_LOADER
	if (psxx_lang) psxx_lang->wipe();                                       /* no words of an earlier seed stay for the screen (a TON phrase has none of its own there) */
	bip_loc = xmr_loc = 0;
#endif
	show_status(T(TXT_GENERATING), T(TXT_EXTRACTING_ENTROPY));
	if (entropy_extract(&pool, ent) == 0) {
		if (wtype == W_TON) {
			r = generate_ton(ent);
		} else if (has_bip39() && has_monero()) {
			/* both wallets from one pool, with independent keys */
			derive_part(part, "psx-wallet-bip39", ent);
			r = generate_bip39(part);
			if (!r) {
				derive_part(part, "psx-wallet-monero", ent);
				r = generate_monero(part);
			}
		} else {
			r = has_monero() ? generate_monero(ent) : generate_bip39(ent);
		}
	}
	secure_zero(ent, sizeof ent);
	secure_zero(part, sizeof part);
	entropy_wipe(&pool);
	kb_wipe(&kb);
	secure_zero(pass, sizeof pass);
	if (r) {
		secure_zero(mnemonic, sizeof mnemonic);
		secure_zero(xmr_mnemonic, sizeof xmr_mnemonic);
		secure_zero(xmr_view, sizeof xmr_view);
		secure_zero(xmr_view_hex, sizeof xmr_view_hex);
	}
	return r;
}

static void custom_init(void);
static void secret_wipe(void);

static void restart(void)
{
	tsel = t2sel = w24 = wxmr = 0;
	custom_init();
	secure_zero(&hs, sizeof hs);
	secure_zero(hs_pass, sizeof hs_pass);
	secret_wipe();
	hs_valid = hs_loc = 0;
#ifdef WITH_LOADER
	if (psxx_lang) psxx_lang->wipe();
	bip_loc = xmr_loc = 0;
	secure_zero(&psxx_handoff, sizeof psxx_handoff);
#endif
	kb_clip_wipe();
	secure_zero(mnemonic, sizeof mnemonic);
	secure_zero(xmr_mnemonic, sizeof xmr_mnemonic);
	secure_zero(ton_seed, sizeof ton_seed);
	ton_seed_ok = 0;
	rest_kind = raw_sel = 0;
	memset(&addrs, 0, sizeof addrs);
	memset(xmr_addr, 0, sizeof xmr_addr);
	secure_zero(xmr_view, sizeof xmr_view);
	secure_zero(xmr_view_hex, sizeof xmr_view_hex);
	memset(xmr_spend_pub, 0, sizeof xmr_spend_pub);
	memset(xmr_view_pub, 0, sizeof xmr_view_pub);
	memset(xmr_sub, 0, sizeof xmr_sub);
	xmr_sub_idx = 1;
	xmr_sub_have = 0;
	memset(xmr_int, 0, sizeof xmr_int);
	memset(xmr_pid_hex, 0, sizeof xmr_pid_hex);
	memset(xp_key, 0, sizeof xp_key);
	memset(xp_desc, 0, sizeof xp_desc);
	xp_have = xp_qr = 0;
	entropy_init(&pool, PSXX_EMULATED ? ENTROPY_EMULATED : 0);
	wtype = W_BIP39_12;
	page = 0;
	hold = 0;
	failed = 0;
	words_idx = 0;
	words_page = 0;
	secure_zero(flips, sizeof flips);
	nflips = 0;
	coin_step = -1;
	secure_zero(rolls, sizeof rolls);
	nrolls = 0;
	dsel = 1;
	srcsel = 0;
	coin_units = dice_units = 0;
	secure_zero(&jsaved, sizeof jsaved);
	cd_pending = cd_have_pos = nseek = 0;
	use_pass = used_pass = pass_stage = pass_err = 0;
	kb_wipe(&kb);
	secure_zero(pass, sizeof pass);
	secure_zero(txt, sizeof txt);
	secure_zero(dec_text, sizeof dec_text);
	enc_len = dn = dsel_i = 0;
	msg[0] = 0;
	qr_mode = qr_dirty = qr_ok = 0;
	hsel = esel = rest_len = 0;
	src_next = S_TYPE;
	state = S_HOME;
}

/* ---- screens ---- */

static void draw_collect(void)
{
	char line[48];
	uint32_t bits = entropy_bits(&pool);
	int ready = entropy_ready(&pool);

	text(16, 6, T(TXT_ENTROPY));
	dim(16, 6 + LINE, ready ? T(TXT_HINT_ENOUGH_KEEPS_IT) : T(TXT_PRESS_BUTTONS_MOVE_THE_STICKS));
	bar(16, 58, GPU_XRES - 32, 16, bits, ENTROPY_MIN_BITS, ready ? 60 : 220, ready ? 220 : 160, 60);
	sprintf(line, T(TXT_BITS_N), (unsigned) bits, ENTROPY_MIN_BITS);
	text(16, 88, line);
	sprintf(line, T(TXT_EVENTS_N), (unsigned) pool.events);
	text(16, 88 + LINE, line);
	sprintf(line, T(TXT_PAD_N), input_present(&in) ? (in.ps.id == 0x41 ? "digital" : "analog") : "none");
	text(16, 88 + 2 * LINE, line);
	dim(16, UI_HINT1, T(TXT_HINT_KEEP_DISCARD_AND_GO_BACK));
	if (PSXX_EMULATED)
		ctext(16, UI_HINT2, T(TXT_EMULATED_TIMING_IGNORED), 255, 160, 80);
}

/* credit still missing for 256 bits, in 1/256 bit units */
static uint32_t units_missing(void)
{
	return pool.credit >= UNITS(ENTROPY_MIN_BITS) ? 0 : UNITS(ENTROPY_MIN_BITS) - pool.credit;
}

/* how many more rolls of a fair device with nsym outcomes are useful */
static int symbols_needed(unsigned nsym)
{
	unsigned c = entropy_symbol_credit(nsym);
	return (int) ((units_missing() + c - 1) / c);
}

static int flips_needed(void)
{
	return symbols_needed(2);
}

/* Coin flips entered by hand: triangle = heads (crown), X = tails (XMR). They are kept in a list so that the last one can
 * be taken back (L1); START puts them into the pool (1 bit each), SELECT throws them away. */
#define FLIP_HEADS_RGB 235, 190, 60
#define FLIP_TAILS_RGB 110, 150, 235
static void draw_coin(void)
{
	char line[48];
	int total = (int) entropy_bits(&pool) + nflips;
	int w = COIN_DRAW_W, dy = 0, side = nflips ? (flips[nflips - 1] ? COIN_HEADS_SIDE : COIN_TAILS_SIDE) : COIN_HEADS_SIDE;
	int bright = nflips ? 128 : 70;

	text(MARGIN, UI_TOP, T(TXT_COIN_FLIPS));
	if (coin_step >= 0 && coin_step <= COIN_STEPS)
		coin_flip_frame(coin_step, COIN_STEPS, coin_start, coin_height, &w, &dy, &side);
	coin_shadow(&ctx, 9, 136, 108 + 64, -dy);
	coin_draw(&ctx, 8, 136, 108 + dy, w, side, bright);

	sprintf(line, T(TXT_FLIPS_N), nflips);
	text(270, 30, line);
	sprintf(line, T(TXT_BITS_N_2), total, ENTROPY_MIN_BITS);
	text(270, 50, line);
	bar(270, 78, GPU_XRES - 16 - 270, 12, (uint32_t) total, ENTROPY_MIN_BITS, total >= ENTROPY_MIN_BITS ? 60 : 220,
	    total >= ENTROPY_MIN_BITS ? 220 : 160, 60);
	for (int i = 0; i < nflips; i++) {                /* one small square per flip: gold = heads, blue = tails */
		int r = flips[i] ? 235 : 110, g = flips[i] ? 190 : 150, b = flips[i] ? 60 : 235, pad = 0;
		const int age = coin_step;                    /* the newest square flashes when it is recorded: bigger and whiter, settling in 8 frames */
		if (i == nflips - 1 && age >= 0 && age < 8) {
			const int k = 8 - age;
			pad = k * 3 / 8;
			r += (255 - r) * k / 8; g += (255 - g) * k / 8; b += (255 - b) * k / 8;
		}
		gpu_draw_rect(&ctx, 4, 270 + (i % 43) * 8 - pad, 104 + (i / 43) * 8 - pad, 6 + 2 * pad, 6 + 2 * pad, r, g, b);
	}
	if (flips_needed() == 0 || nflips >= flips_needed())
		ctext(270, 164, T(TXT_HINT_ENOUGH_PRESS), 60, 220, 60);
	{   /* the hint is cut at each button icon (a byte below 0x20): the first two parts, heads and tails, take the colours of their squares */
		const char *s = T(TXT_HINT_HEADS_TAILS_UNDO_DONE_CANCEL), *e;
		char part[48];
		int x = MARGIN;

		for (int k = 0; *s; k++, s = e) {
			size_t n;
			for (e = s + 1; *e && (uint8_t) *e >= 0x20; e++) {}
			n = (size_t) (e - s) < sizeof part - 1 ? (size_t) (e - s) : sizeof part - 1;
			memcpy(part, s, n);
			part[n] = 0;
			if (k == 0) ctext(x, UI_HINT2, part, FLIP_HEADS_RGB);
			else if (k == 1) ctext(x, UI_HINT2, part, FLIP_TAILS_RGB);
			else ctext(x, UI_HINT2, part, 150, 160, 200);
			x += font_width(part);
		}
	}
}

/* ---- entropy source menu and the dice screen ---- */

static void draw_source(void)
{
	const char *const NAME[NSOURCES] = {T(TXT_JOYSTICK), T(TXT_COIN), T(TXT_DICE), "CD"};
	const char *const DESC[NSOURCES] = {T(TXT_BUTTON_TIMING), T(TXT_HEADS_TAILS_1_BIT_EACH), T(TXT_D6_2_58_BITS_EACH),
	                                           T(TXT_SEEK_TIMING_TEST_ONLY)};
	char line[64];
	int bits = (int) entropy_bits(&pool);
	int joy = (int) ((pool.credit - coin_units - dice_units) >> 8);

	if (joy < 0) joy = 0;
	text(MARGIN, UI_TOP, T(TXT_ENTROPY_SOURCES));
	for (int i = 0; i < NSOURCES; i++) {
		int y = 28 + i * 24, sel = i == srcsel;
		ui_row(MARGIN, y, sel, NAME[i]);
		dim(250, y, DESC[i]);
	}
	bar(MARGIN, 126, GPU_XRES - 32, 6, (uint32_t) bits, ENTROPY_MIN_BITS, bits >= ENTROPY_MIN_BITS ? 60 : 220,
	    bits >= ENTROPY_MIN_BITS ? 220 : 160, 60);
	sprintf(line, T(TXT_BITS_N_JOYSTICK_N_COIN_N_DICE), bits, ENTROPY_MIN_BITS, joy, (unsigned) (coin_units >> 8),
	        (unsigned) (dice_units >> 8));
	text(MARGIN, 136, line);
	if (entropy_ready(&pool)) ctext(MARGIN, 160, T(TXT_HINT_ENOUGH_PRESS), 60, 220, 60);
	else if (failed) ctext(MARGIN, 160, T(TXT_GENERATION_FAILED_COLLECT), 255, 100, 100);
	else if (srcsel < 3) wrap_text(MARGIN, 158, GPU_XRES - 2 * MARGIN, 2, T(TXT_SRC_NOTE_JOY + srcsel), 150, 160, 200);
	if (hold) bar(MARGIN, 196, GPU_XRES - 32, 4, (uint32_t) hold, HOLD_FRAMES, 220, 60, 60);              /* SELECT held: the reset */
	dim(MARGIN, UI_HINT2, T(TXT_HINT_CHOOSE_USE_CONTINUE_RESET_HOLD));
}

/* A filled rectangle with rounded corners (the corner is a quarter ellipse of 10 x 5 pixels: the pixels of the 640 wide mode are twice as tall as wide), in the slot z. */
static void rounded_rect(int z, int x, int y, int w, int h, int rows, int r, int g, int b)
{
	static const uint8_t INSET5[5] = {6, 3, 1, 0, 0}, INSET2[2] = {1, 0};     /* the rows of a corner of 5 or 2 rows, from the outside */
	const uint8_t *in_ = rows == 5 ? INSET5 : INSET2;

	for (int k = 0; k < rows; k++) {
		gpu_draw_rect(&ctx, z, x + in_[k], y + k, w - 2 * in_[k], 1, r, g, b);
		gpu_draw_rect(&ctx, z, x + in_[k], y + h - 1 - k, w - 2 * in_[k], 1, r, g, b);
	}
	gpu_draw_rect(&ctx, z, x, y + rows, w, h - 2 * rows, r, g, b);
}

/* Dice rolls entered by hand: left / right pick the face, X enters it, L1 takes the last one back, START puts the rolls
 * into the pool (2.58 bits each), SELECT throws them away. */
static void draw_dice(void)
{
	char line[64], digits[64];
	int total = (int) ((pool.credit + (uint32_t) nrolls * entropy_symbol_credit(6)) >> 8);
	int need = symbols_needed(6);
	int shown = nrolls < 120 ? nrolls : 120;

	text(MARGIN, UI_TOP, T(TXT_DICE_ROLLS));
	dice_draw(&ctx, 8, 24, 28, 128, 64, dsel);                  /* the face that X will enter */

	sprintf(line, T(TXT_ROLLS_N), nrolls);
	text(270, 24, line);
	sprintf(line, T(TXT_BITS_N_2), total, ENTROPY_MIN_BITS);
	text(270, 44, line);
	bar(270, 70, GPU_XRES - 16 - 270, 12, (uint32_t) total, ENTROPY_MIN_BITS, total >= ENTROPY_MIN_BITS ? 60 : 220,
	    total >= ENTROPY_MIN_BITS ? 220 : 160, 60);
	if (nrolls >= need) ctext(270, 92, T(TXT_HINT_ENOUGH_PRESS), 60, 220, 60);

	for (int i = 0; i < 6; i++) {                              /* the six faces with wide gaps, centred; the selected one in a rounded frame */
		int x = (GPU_XRES - (5 * 92 + 64)) / 2 + i * 92;
		if (i + 1 == dsel) {                                   /* a ring 3 pixels thick, 2 pixels of background between it and the die on every side */
			rounded_rect(10, x - 5, 113, 74, 42, 5, 255, 210, 60);
			rounded_rect(9, x - 2, 116, 68, 36, 2, 20, 20, 60);
		}
		dice_draw(&ctx, 8, x, 118, 64, 32, i + 1);
	}
	for (int r = 0; r < 2; r++) {                              /* the last 120 rolls, 60 per row */
		int n = 0;
		for (int i = nrolls - shown + r * 60; i < nrolls - shown + (r + 1) * 60 && i < nrolls; i++) digits[n++] = (char) ('0' + rolls[i]);
		digits[n] = 0;
		dim(MARGIN, 162 + r * 20, digits);
	}
	dim(MARGIN, UI_HINT2, T(TXT_HINT_FACE_ENTER_UNDO_DONE_CANCEL));
}

/* ---- CD seek timing: test mode ----
 * The seek times are hashed into the pool but earn no credit until the estimator has been tuned on real hardware, and
 * every seek is written to a file on the memory card in slot 2 for the analysis. */

static void enter_cd(void)
{
	show_status(T(TXT_READING_THE_DISC), T(TXT_SPINNING_UP_UP_TO_10_SECONDS));
	cd_rc = cd_open(&disc);
	nseek = 0;
	cd_have_pos = cd_pending = 0;
	log_rc = CDLOG_NO_CARD;
	if (cd_rc == CD_OK) {
		cdview_init(disc.leadout);
		log_rc = cdlog_open(&disc, PSXX_EMULATED ? 1u : 0u, cdview_capacity() + 150);
	}
	state = S_CD;
}

static void do_seek(void)
{
	cd_seek_result sr;
	cdlog_rec rec;
	int rc = cd_seek(cd_target, &sr);

	memset(&rec, 0, sizeof rec);
	rec.seq = (uint16_t) nseek;
	rec.flags = (uint8_t) (sr.flags | (cd_have_pos ? 0 : CDL_FROM_UNKNOWN));
	rec.stat = sr.stat;
	rec.target = cd_target;
	rec.from = cd_have_pos ? cd_pos : 0;
	rec.landed = sr.landed;
	rec.seek = sr.seek;
	rec.ack = sr.ack;
	rec.t_press = cd_tpress >> 3;
	rec.r = cd_r;
	rec.a = cd_a;
	if (log_rc == CDLOG_OK) log_rc = cdlog_add(&rec);

	entropy_add_context(&pool, cd_target);              /* hashed, never credited */
	entropy_add_context(&pool, rec.from);
	entropy_add_context(&pool, sr.seek);
	entropy_add_context(&pool, sr.ack);
	entropy_add_context(&pool, sr.landed);
	entropy_add_context(&pool, ((uint32_t) sr.stat << 8) | sr.err);
	entropy_add_context(&pool, rec.t_press);
	entropy_add_context(&pool, ((uint32_t) cd_r << 16) | cd_a);

	cd_last = sr;
	cd_have_pos = rc == CD_OK;
	cd_pos = sr.landed != 0xFFFFFFFFu ? sr.landed : cd_target;
	nseek++;
	cd_pending = 0;
}

static void ms10(char *out, uint32_t ticks)               /* "183.4" */
{
	uint32_t t = ticks / (CD_TICKS_PER_MS / 10);
	sprintf(out, "%u.%u", (unsigned) (t / 10), (unsigned) (t % 10));
}

static void draw_cd(void)
{
	char line[64], a[16], b[16];
	const int px = 352;
	int y = 44;

	text(MARGIN, UI_TOP, T(TXT_CD_SEEK_TIMING));
	ctext(MARGIN, 22, T(TXT_TEST_MODE_NO_ENTROPY_CREDIT), 255, 90, 90);

	if (cd_rc != CD_OK) {
		const char *m = cd_rc == CD_NO_DISC ? T(TXT_NO_DISC_IN_THE_DRIVE) : cd_rc == CD_TIMEOUT ? T(TXT_THE_DRIVE_DID_NOT_ANSWER) : T(TXT_DRIVE_ERROR);
		ctext(MARGIN, 70, m, UI_SEL_RGB);
		if (cd_rc == CD_NO_DISC) dim(MARGIN, 94, T(TXT_INSERT_A_DISC_AND_CLOSE_THE));
		sprintf(line, T(TXT_COMMAND_N_STATUS_N_ERROR_N), (unsigned) (uint8_t) disc.fail_cmd, disc.fail_stat, disc.fail_err);
		dim(MARGIN, 118, line);
		dim(MARGIN, UI_HINT2, T(TXT_HINT_RETRY_BACK));
		return;
	}

	cdview_draw(&ctx, 20, 44);
	{
		uint32_t used = cdview_used(), cap = cdview_capacity();
		unsigned mb_used = (unsigned) (used / 1000 * CDV_SECTOR_BYTES / 1000), mb_cap = (unsigned) (cap / 1000 * CDV_SECTOR_BYTES / 1000);

		sprintf(line, T(TXT_WRITTEN_N_OF_N_MB), mb_used, mb_cap);
		ctext(px, y, line, 255, 200, 60);
		y += 18;
		sprintf(line, T(TXT_EMPTY_N_MB), mb_cap - mb_used);
		ctext(px, y, line, 120, 140, 200);
		y += 18;
		sprintf(line, T(TXT_N_TRACKS), (unsigned) (disc.leadout / 4500), (unsigned) ((disc.leadout / 75) % 60), (int) disc.last - disc.first + 1);
		dim(px, y, line);
		y += 18;
		dim(px, y, T(TXT_T_1_RING_50_MB));
		y += 26;
	}
	sprintf(line, T(TXT_SEEKS_N), nseek);
	text(px, y, line);
	y += 18;
	if (nseek) {
		ms10(a, cd_last.seek);
		ms10(b, cd_last.ack);
		sprintf(line, T(TXT_SEEK_N_MS_ACK_N_MS), a, b);
		if (cd_last.flags & (CDS_FAIL | CDS_TIMEOUT)) ctext(px, y, T(TXT_LAST_SEEK_FAILED), 255, 100, 100);
		else text(px, y, line);
	}
	y += 18;
	if (log_rc == CDLOG_OK) {
		sprintf(line, T(TXT_SLOT_2_N_SAVED), cdlog_count(), CDLOG_MAX);
		ctext(px, y, line, 60, 220, 60);
	} else {
		const char *const E[] = {"", T(TXT_NO_CARD_NOT_SAVED), T(TXT_NOT_FORMATTED_NOT_SAVED), T(TXT_CARD_FULL_NOT_SAVED),
		                                T(TXT_WRITE_ERROR_STOPPED), T(TXT_LOG_IS_FULL)};
		sprintf(line, T(TXT_SLOT_2_N), E[-log_rc]);
		ctext(px, y, line, 255, 100, 100);
	}
	y += 18;
	dim(px, y, T(TXT_CREDIT_0_BITS_TEST));
	if (PSXX_EMULATED) dim(px, y + 18, T(TXT_EMULATOR_BUILD));
	if (cd_pending) ctext(200, UI_HINT2, T(TXT_SEEKING), UI_SEL_RGB);
	dim(MARGIN, UI_HINT2, T(TXT_HINT_SEEK_BACK));
}

/* ---- encrypted texts (core/blob.c): the same blob format the Token2 key backup will use ----
 * Encrypt: text, password (twice), fresh randomness from the pool -> AES-256-GCM blob; shown as a QR code and as base64,
 * saved as a file on the card in slot 2. Decrypt: pick the file on that card, password. Nothing secret is ever written. */

/* Draws s in lines of at most `chunk` bytes (never cutting a UTF-8 character), skipping the first `skip` lines and
 * drawing at most `maxl`. Returns the number of lines the whole text has. */
static int utf8_lines(int x, int y, const char *s, int chunk, int skip, int maxl)
{
	char buf[72];
	size_t n = strlen(s);
	int line = 0;

	for (size_t o = 0; o < n; line++) {
		size_t l = n - o < (size_t) chunk ? n - o : (size_t) chunk;
		while (o + l < n && l > 1 && ((uint8_t) s[o + l] & 0xC0) == 0x80) l--;      /* do not cut a character */
		if (line >= skip && line - skip < maxl) {
			memcpy(buf, s + o, l);
			buf[l] = 0;
			font_draw(&ctx, 6, x, y + (line - skip) * LINE, buf, 255, 255, 255);   /* slots 6..11: the hint line (z 0) uses 0..5 */
		}
		o += l;
	}
	return line;
}

static int hex_val(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* hex digits (even count) -> bytes; returns the number of bytes or -1 */
static int hex_decode(const char *h, uint8_t *out, int cap)
{
	int n = (int) strlen(h);
	if (n & 1 || n / 2 > cap) return -1;
	for (int i = 0; i < n / 2; i++) {
		int a = hex_val(h[2 * i]), b = hex_val(h[2 * i + 1]);
		if (a < 0 || b < 0) return -1;
		out[i] = (uint8_t) (a << 4 | b);
	}
	return n / 2;
}

/* bytes -> hex text in groups of 8 digits (4 bytes) separated by a space */
static void hex_fmt(char *out, const uint8_t *in, int n)
{
	static const char D[] = "0123456789abcdef";
	int o = 0;
	for (int i = 0; i < n; i++) {
		if (i && i % 4 == 0) out[o++] = ' ';
		out[o++] = D[in[i] >> 4];
		out[o++] = D[in[i] & 15];
	}
	out[o] = 0;
}

/* Printable UTF-8 text (tab, line feed and carriage return allowed)? Anything else is shown as hex. */
static int is_text(const uint8_t *p, int n)
{
	for (int i = 0; i < n;) {
		uint8_t c = p[i];
		int k = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 && c >= 0xC2 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : -1;
		if (k < 0 || (c < 0x20 && c != 9 && c != 10 && c != 13) || c == 0x7F || i + k >= n + (k == 0)) return 0;
		for (int j = 1; j <= k; j++) if ((p[i + j] & 0xC0) != 0x80) return 0;
		i += k + 1;
	}
	return 1;
}

/* the capacity meter next to the keyboard title: size, share of a single QR code, number of UR frames */
static int ur_frames(int len) { return (len + (len < 24 ? 1 : len < 256 ? 2 : 3) + UR_FRAG - 1) / UR_FRAG; }

static int kb_step(uint16_t pr)
{
	kb.held = in.ps.buttons;
	return kb_update(&kb, pr);
}

static void enc_note(void)
{
	int pt = enc_hex ? kb.len / 2 : kb.len, blob = pt + BLOB_OVERHEAD, b64 = 4 * ((blob + 2) / 3), pct = b64 * 100 / QR_CAP;

	/* "<bytes> | QR <share of one QR code> | UR <number of animated QR codes>" */
	if (pct > 100) sprintf(note, T(TXT_N_B_QR_N_OVER_UR_N_CODES), pt, pct, ur_frames(blob));
	else if (pct >= QR_WARN_PCT) sprintf(note, T(TXT_N_B_QR_N_NEAR_LIMIT_UR_N), pt, pct, ur_frames(blob));
	else sprintf(note, "%d B | QR %d%% | UR %d", pt, pct, ur_frames(blob));
	kb.note = note;
	kb.warn = pct > 100 ? 2 : pct >= QR_WARN_PCT ? 1 : 0;
}

static const char *card_error(int r)
{
	return r == MCF_NO_CARD ? T(TXT_NO_CARD_IN_SLOT_2) : r == MCF_BAD_CARD ? T(TXT_CARD_NOT_FORMATTED) : r == MCF_FULL ? T(TXT_CARD_IS_FULL)
	     : r == MCF_NOT_FOUND ? T(TXT_FILE_NOT_FOUND) : T(TXT_CARD_ERROR);
}

static void enc_kb(const char *title)
{
	kb_init(&kb, title, NULL, 0, !enc_hex);
	kb.multiline = !enc_hex;                                  /* the text to encrypt may have lines */
	kb_set(&kb, enc_hex ? 2 * TXT_MAX : TXT_MAX, enc_hex);
}

/* the QR picture of the current UR part */
static void show_part(void)
{
	qr_ok = 0;
	if (ur_part(&urp, enc_blob, (unsigned) ur_seq, urtxt, sizeof urtxt) > 0 &&
	    qr_encode(&qr, (const uint8_t *) urtxt, strlen(urtxt), QR_ECC_L) > 0) {
		qr_ok = 1;
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	}
}

/* ur = 0: the whole base64 text in one QR code (if it fits), ur = 1: UR animation of the blob */
static void set_out_mode(int ur)
{
	msg[0] = 0;
	if (!ur) {
		if (qr_encode(&qr, (const uint8_t *) enc_b64, strlen(enc_b64), QR_ECC_L) > 0) {
			qr_ok = 1;
			qr_scale = qr_view_scale(&qr);
			qr_view_upload(&qr, qr_scale);
			out_ur = 0;
			return;
		}
		sprintf(msg, T(TXT_TOO_LONG_FOR_ONE_QR_CODE));
	}
	out_ur = 1;
	ur_seq = 1;
	ur_tick = 0;
	show_part();
}

/* ---- passwords: the keyboard, the entropy note, the suggestions ---- */

/* a password keyboard: long enough for a phrase of words */
static void pw_kb(const char *title, const char *initial)
{
	kb_init(&kb, title, initial, 1, 0);
	kb_set(&kb, PW_MAX, 0);
}

/* the note of the first entry: the estimated entropy and what it means */
static void pw_note(void)
{
	int b = pw_entropy_bits(kb.text);

	if (kb.len == 0) { kb.note = NULL; return; }
	sprintf(note, T(TXT_N_BITS_N), b, b < 48 ? T(TXT_VERY_WEAK) : b < PW_WEAK_BITS ? "weak" : b < PW_STRONG_BITS ? "ok" : "strong");
	kb.note = note;
	kb.warn = b < 48 ? 2 : b < PW_WEAK_BITS ? 1 : 0;
}

/* the first entry is done: 0 = take it, 1 = it is weak and was not accepted yet (the keyboard asks again with the same text) */
static int pw_first_entry_weak(void)
{
	int b = pw_entropy_bits(kb.text);

	if (b >= PW_WEAK_BITS || (pw_warned && strcmp(kb.text, pw_again) == 0)) return 0;
	static char title[80];                                    /* the keyboard keeps the pointer */

	snprintf(pw_again, sizeof pw_again, "%s", kb.text);
	pw_warned = 1;
	sprintf(title, T(TXT_WEAK_ABOUT_N_BITS_N_WANTED_OK), b, PW_WEAK_BITS);
	pw_kb(title, pw_again);
	return 1;
}

static int pw_seed(uint8_t seed[32])
{
	uint8_t salt[32], ent[32];
	int r = 0;

	entropy_digest(&bgpool, salt);                                               /* everything the buttons did since the program started */
	if (pw_for == PW_FOR_TEXT) {
		r = entropy_extract(&pool, ent);                                         /* does not use the pool up */
		if (!r) pw_seed_make(seed, salt, ent, sizeof ent, PW_SEED_TEXT, 0);
		secure_zero(ent, sizeof ent);
	} else {
		pw_seed_make(seed, salt, ks_ent, (size_t) ks_elen, PW_SEED_KEY, ks_type);
	}
	secure_zero(salt, sizeof salt);
	return r;
}

static void pw_make(void)
{
	uint8_t seed[32];

	pw_sug[0] = 0;
	pw_sug_bits = 0;
	if (pw_seed(seed) == 0) pw_sug_bits = pw_generate(pw_kind, seed, (uint32_t) pw_count, pw_sug, sizeof pw_sug);
	secure_zero(seed, sizeof seed);
}

static void pw_cancel(void)
{
	kb_wipe(&kb);
	secure_zero(pass, sizeof pass);
	secure_zero(pw_sug, sizeof pw_sug);
	secure_zero(pw_again, sizeof pw_again);
	pw_warned = 0;
	if (pw_for == PW_FOR_TEXT) { secure_zero(txt, sizeof txt); state = S_ENCMENU; }
	else state = S_KS_STORE;
}

static void pw_enter(int for_what)
{
	pw_for = for_what;
	pw_sel = 0;
	pw_warned = 0;
	state = S_PW_CHOOSE;
}

static void do_encrypt(void)
{
	static const char DOMAIN[] = "psx-blob-rnd";
	uint8_t ent[32], rnd[32];
	sha256_ctx h;
	int n = -1;

	show_status(T(TXT_ENCRYPTING), T(TXT_ABOUT_8_SECONDS));
	enc_len = -1;
	if (entropy_extract(&pool, ent) == 0) {              /* the pool is spent after this, like after a wallet */
		sha256_init(&h);
		sha256_update(&h, (const uint8_t *) DOMAIN, sizeof DOMAIN - 1);
		sha256_update(&h, ent, 32);
		sha256_final(&h, rnd);
		n = blob_seal((const uint8_t *) pass, strlen(pass), NULL, 0, BLOB_ITER_TEXT, rnd, txt, (size_t) txt_len,
		              enc_blob, sizeof enc_blob);
		if (n > 0 && b64_encode(enc_blob, (size_t) n, enc_b64, sizeof enc_b64) > 0) enc_len = n;
	}
	secure_zero(ent, sizeof ent);
	secure_zero(rnd, sizeof rnd);
	secure_zero(&h, sizeof h);
	entropy_wipe(&pool);
	kb_wipe(&kb);
	kb_clip_wipe();
	secure_zero(pass, sizeof pass);
	secure_zero(txt, sizeof txt);
	txt_len = 0;
	msg[0] = 0;
	if (enc_len > 0) {
		hex_fmt(enc_hexs, enc_blob, enc_len);
		out_page = 0;
		out_scroll = 0;
		ur_plan_make(&urp, enc_blob, (size_t) enc_len, UR_FRAG);
		set_out_mode(strlen(enc_b64) > QR_CAP);              /* one QR code if the text fits it, else the animated UR */
		state = S_ENC_OUT;
	} else {
		restart();
		failed = 1;
	}
}

static void save_text_file(const char *nm)
{
	mcf_entry e[1];
	uint8_t f[MC_FRAME];
	int nfiles, next, blk, r;
	char name[MCF_NAME];
	int nl = (int) strlen(nm), hdr = nl ? 2 + nl : 0;       /* a name goes first: 0xFE, its length, the name */

	r = mcf_scan(1, TXT_TAG, e, 0, &nfiles, &next, &blk);
	if (!r && !blk) r = MCF_FULL;
	if (!r) r = mcf_begin(1, blk, "PSXX encrypted text", MCF_ICON_LOCK);
	for (int fr = 0; !r && fr * MC_FRAME < hdr + 2 + enc_len; fr++) {     /* the file: [name,] length (2 bytes), the blob */
		memset(f, 0, sizeof f);
		for (int i = 0; i < MC_FRAME; i++) {
			int p = fr * MC_FRAME + i;
			if (p < hdr) f[i] = p == 0 ? NAME_MARK : p == 1 ? (uint8_t) nl : (uint8_t) nm[p - 2];
			else if (p == hdr) f[i] = (uint8_t) (enc_len >> 8);
			else if (p == hdr + 1) f[i] = (uint8_t) enc_len;
			else if (p - hdr - 2 < enc_len) f[i] = enc_blob[p - hdr - 2];
		}
		r = mcf_write(1, blk, MCF_FIRST_DATA + fr, f);
	}
	if (!r) r = mcf_commit(1, blk, TXT_TAG, next);
	if (!r) { mcf_name(name, TXT_TAG, next); sprintf(msg, T(TXT_SAVED_N), name + 12); }
	else sprintf(msg, T(TXT_NOT_SAVED_N), card_error(r));
}

static void dec_scan(void)
{
	int next, blk;

	uint8_t f[MC_FRAME];

	dec_rc = mcf_scan(1, TXT_TAG, dlist, 7, &dn, &next, &blk);
	dsel_i = 0;
	memset(dnames, 0, sizeof dnames);
	for (int i = 0; !dec_rc && i < dn; i++) {              /* the name, if the file has one */
		if (mcf_read(1, dlist[i].block, MCF_FIRST_DATA, f) == MCF_OK && f[0] == NAME_MARK && f[1] <= NAME_MAX_BYTES)
			memcpy(dnames[i], f + 2, f[1]);
	}
}

static int dec_load(void)
{
	uint8_t f[MC_FRAME];
	int r = mcf_read(1, dlist[dsel_i].block, MCF_FIRST_DATA, f), len, got = 0, off = 0;

	if (r) return r;
	if (f[0] == NAME_MARK) off = 2 + f[1];
	if (off > NAME_MAX_BYTES + 2) return MCF_NOT_FOUND;
	len = (f[off] << 8) | f[off + 1];
	off += 2;
	if (len < BLOB_OVERHEAD || len > BLOB_BUF) return MCF_NOT_FOUND;
	for (int fr = 0; got < len; fr++) {
		if (fr) { r = mcf_read(1, dlist[dsel_i].block, MCF_FIRST_DATA + fr, f); if (r) return r; }
		for (int i = (fr ? 0 : off); i < MC_FRAME && got < len; i++) enc_blob[got++] = f[i];
	}
	enc_len = len;
	return MCF_OK;
}

static void do_decrypt(void)
{
	char when[32];
	int r;

	sprintf(when, T(TXT_ABOUT_N_SECONDS), (unsigned) (blob_iterations(enc_blob, (size_t) enc_len) * 9 / 10000 + 1));
	show_status(T(TXT_DECRYPTING), when);
	r = blob_open((const uint8_t *) kb.text, strlen(kb.text), NULL, 0, enc_blob, (size_t) enc_len, (uint8_t *) dec_text,
	              sizeof dec_text - 1);
	kb_wipe(&kb);
	if (r >= 0) {
		dec_text[r] = 0;
		dec_len = r;
		dec_hexview = !is_text((const uint8_t *) dec_text, r);     /* binary data is shown as hex */
		dec_scroll = 0;
		hex_fmt(dec_hexs, (const uint8_t *) dec_text, r);
		state = S_DEC_OUT;
	} else {
		pw_kb(r == -2 ? T(TXT_WRONG_PASSWORD_OR_DAMAGED_FILE) : T(TXT_NOT_A_VALID_FILE_PASSWORD), NULL);
	}
}

/* ---- key save: the screens are S_KS_STORE (which store), S_KS_LABEL, S_KS_PASS (twice), S_KS_DONE ---- */

void ks_wipe(void)
{
	secure_zero(ks_ent, sizeof ks_ent);
	secure_zero(ks_label, sizeof ks_label);
	secure_zero(ks_k, sizeof ks_k);
	secure_zero(&ks_pwd, sizeof ks_pwd);
	ks_kok = 0;
	secure_zero(pass, sizeof pass);
	ks_elen = 0;
	kb_wipe(&kb);
	kb_clip_wipe();
}

/* the rows of the choice of where the key goes: the single keys (their blocks are the card's business, the person sees one row), the vaults, a new vault */
static int ks_nvaults(void) { int n = 0; for (int i = 0; i < ks_st.nstores; i++) n += !ks_st.st[i].single; return n; }
static int ks_vault(int n) { for (int i = 0; i < ks_st.nstores; i++) if (!ks_st.st[i].single && n-- == 0) return i; return -1; }
static int ks_singles(void) { int n = 0; for (int i = 0; i < ks_st.nstores; i++) n += ks_st.st[i].single ? ks_st.st[i].n : 0; return n; }
static int ks_room_vault(void) { return ks_st.free_count >= 1 && ks_st.nstores < KSD_MAX_STORES && ks_nvaults() < KSD_MAX_VAULTS; }
static int ks_room_single(void)
{
	for (int i = 0; i < ks_st.nstores; i++) if (ks_st.st[i].single && ks_st.st[i].next_slot >= 0) return 1;
	return ks_room_vault();
}
#define KS_ROWS (ks_nvaults() + 2)

static void ks_scan(void)
{
	ks_rc = ksd_scan(KS_PORT, &ks_st, 1);
	if (ks_sel >= KS_ROWS) ks_sel = 0;
	ks_msg[0] = 0;
}

static void ks_begin(int type, const uint8_t *ent, int elen, int flags, int back)
{
	memcpy(ks_ent, ent, (size_t) elen);
	ks_elen = elen;
	ks_type = type;
	ks_flags = flags;
	ks_back = back;
	ks_sel = 0;
	ks_scan();
	state = S_KS_STORE;
}

/* the password of a new store is typed (or made): its key, from a salt that depends on the button history, the password and the name */
static void ks_make_store_key(void)
{
	static const char DOMAIN[] = "psx-store-salt";
	uint8_t dig[32], d[32];
	sha256_ctx h;

	show_status(T(TXT_MAKING_THE_STORE_KEY), T(TXT_ABOUT_15_SECONDS));
	entropy_digest(&bgpool, dig);
	sha256_init(&h);
	sha256_update(&h, (const uint8_t *) DOMAIN, sizeof DOMAIN - 1);
	sha256_update(&h, dig, 32);
	sha256_update(&h, (const uint8_t *) pass, strlen(pass));
	sha256_update(&h, (const uint8_t *) ks_slabel, strlen(ks_slabel));
	sha256_final(&h, d);
	memset(&ks_pwd, 0, sizeof ks_pwd);
	ks_pwd.flags = KS_DIR_PW;
	ks_pwd.iter = KS_ITER_STORE;
	memcpy(ks_pwd.salt, d, 16);
	ks_store_key(ks_k, ks_pwd.check, (const uint8_t *) pass, strlen(pass), KS_ITER_STORE, ks_pwd.salt);
	ks_kok = ks_new_pw = 1;
	secure_zero(pass, sizeof pass);
	secure_zero(dig, sizeof dig);
	secure_zero(d, sizeof d);
	secure_zero(&h, sizeof h);
}

/* after the name of the store: the label of the key */
static void ks_ask_label(void)
{
	ks_msg[0] = 0;
	kb_init(&kb, T(TXT_LABEL_SHOWN_WITH_THE_PASSWORD), ks_label[0] ? ks_label : NULL, 0, 1);       /* ks_label: a first guess of the caller (ks_save_modal), else empty */
	kb_set(&kb, ks_use_store ? KS_LABEL_STORE : KS_LABEL, 0);
	state = S_KS_LABEL;
}

/* the key of an existing store: its password is typed and checked against the store (the check value, then the mac of its directory) */
static int ks_unlock(const ks_dir *d)
{
	uint8_t k[32], chk[16];
	char when[32];
	int ok;

	sprintf(when, T(TXT_ABOUT_N_SECONDS), (unsigned) (d->iter * 9 / 10000 + 1));
	show_status(T(TXT_OPENING_THE_STORE), when);
	ks_store_key(k, chk, (const uint8_t *) kb.text, (size_t) kb.len, d->iter, d->salt);
	kb_wipe(&kb);
	kb_clip_wipe();
	ok = !memcmp(chk, d->check, 16) && ks_dir_mac_ok(d, k);
	if (ok) { memcpy(ks_k, k, 32); ks_kok = 1; }
	secure_zero(k, sizeof k);
	return ok;
}

static void do_keysave(void)
{
	if (ks_dry) { ks_dry_go = 1; state = S_MODAL_END; return; }                  /* a key over 32 bytes: the signer seals and writes it, from what was chosen here */
	static const char DOMAIN[] = "psx-key-rnd", DOMAIN2[] = "psx-store-nonce";
	uint8_t frame[KS_FRAME], rnd[32], lab[KS_LABEL_STORE], tf[2], nonce[32];
	sha256_ctx h;
	int n = KS_ERR_ARG, r = KSD_ERR_ARG, store = ks_target >= 0 ? ks_target : -1;

	show_status(T(TXT_SEALING_THE_KEY), ks_use_store ? NULL : T(TXT_ABOUT_15_SECONDS));
	memset(lab, 0, sizeof lab);
	memcpy(lab, ks_label, strlen(ks_label));
	tf[0] = (uint8_t) ks_type;
	tf[1] = (uint8_t) ks_flags;
	/* Salt and nonce come from the key itself, its label and its kind: once a wallet has been made there is no entropy left to draw. The same inputs make the same plain text,
	 * so a repeat leaks nothing, and a different key or label gets different ones. */
	sha256_init(&h);
	sha256_update(&h, (const uint8_t *) DOMAIN, sizeof DOMAIN - 1);
	sha256_update(&h, tf, 2);
	sha256_update(&h, lab, sizeof lab);
	sha256_update(&h, ks_ent, (size_t) ks_elen);
	sha256_final(&h, rnd);
	if (ks_target == -2) {                                             /* a single key: sealed with its own password, into a block of the single keys that has room, else a new one */
		n = ks_own_entry_seal(frame, (const uint8_t *) pass, strlen(pass), BLOB_ITER_KEY, rnd, ks_type, ks_flags, ks_ent, ks_elen, ks_label, ks_plabel[0] ? ks_plabel : NULL);
		store = -1;
		for (int i = 0; i < ks_st.nstores && store < 0; i++) if (ks_st.st[i].single && ks_st.st[i].next_slot >= 0) store = i;
		if (n == KS_OK) {
			show_status(T(TXT_SAVING_TO_THE_CARD), T(TXT_ABOUT_10_SECONDS));
			if (store >= 0) {
				r = ksd_add(KS_PORT, &ks_st, store, frame, NULL, ks_work);
				if (r == KSD_OK) ksd_single_title(KS_PORT, &ks_st);                                                      /* (a new block makes its own) */
			} else r = ksd_new_single(KS_PORT, &ks_st, frame, 1, (uint16_t) (rnd[28] << 8 | rnd[29]), ks_work, &store);
		}
	} else {                                                           /* a vault: sealed with its key, for its place; a new one is made with the key in it */
		uint16_t id = store < 0 ? ksd_free_id(&ks_st, (uint16_t) (rnd[28] << 8 | rnd[29])) : ks_st.st[store].id;
		uint32_t seq = store < 0 ? 0 : ks_st.st[store].seq;
		int slot = store < 0 ? 0 : ks_st.st[store].next_slot;

		sha256_init(&h);
		sha256_update(&h, (const uint8_t *) DOMAIN2, sizeof DOMAIN2 - 1);
		sha256_update(&h, rnd, 32);
		sha256_update(&h, (const uint8_t *) &id, sizeof id);
		sha256_update(&h, (const uint8_t *) &seq, sizeof seq);
		sha256_update(&h, (const uint8_t *) &slot, sizeof slot);
		sha256_final(&h, nonce);
		n = ks_store_entry_seal(frame, ks_k, id, slot, nonce, seq + 1, ks_type, ks_flags, ks_ent, ks_elen, ks_label);
		if (n == KS_OK) {
			show_status(T(TXT_SAVING_TO_THE_CARD), T(TXT_ABOUT_10_SECONDS));
			if (store < 0) r = ksd_make_block(KS_PORT, &ks_st, 0, ks_slabel, &ks_pwd, ks_k, id, frame, 1, ks_work, &store);
			else r = ksd_add(KS_PORT, &ks_st, store, frame, ks_k, ks_work);
		}
	}
	if (r == KSD_OK && n == KS_OK) {
		if (ks_target == -2) sprintf(ks_msg, T(TXT_SAVED_SINGLE_KEY_N), ks_singles());
		else sprintf(ks_msg, T(TXT_SAVED_KEY_N_OF_STORE_N), ks_st.st[store].n, ks_st.st[store].dir.label);
	}
	else if (r == KSD_ERR_FULL) sprintf(ks_msg, T(TXT_NOT_SAVED_NO_FREE_BLOCK));
	else if (r == KSD_ERR_LIMIT) sprintf(ks_msg, T(TXT_NOT_SAVED_STORE_OR_KEY_LIMIT));
	else if (r == KSD_ERR_VERIFY) sprintf(ks_msg, T(TXT_NOT_SAVED_THE_CARD_DID_NOT));
	else if (r == KSD_ERR_CHANGED) sprintf(ks_msg, T(TXT_NOT_SAVED_THE_CARD_WAS_CHANGED));
	else if (n != KS_OK || r == KSD_ERR_ARG || r == KSD_ERR_IMAGE || r == KSD_ERR_PASSWORD) sprintf(ks_msg, T(TXT_NOT_SAVED_INTERNAL_ERROR));
	else sprintf(ks_msg, T(TXT_NOT_SAVED_N), card_error(r));
	secure_zero(rnd, sizeof rnd);
	secure_zero(nonce, sizeof nonce);
	secure_zero(frame, sizeof frame);
	secure_zero(&h, sizeof h);
	secure_zero(pass, sizeof pass);
	secure_zero(ks_ent, sizeof ks_ent);
	secure_zero(ks_k, sizeof ks_k);
	ks_kok = 0;
	ks_elen = 0;
	kb_wipe(&kb);
	kb_clip_wipe();
	state = S_KS_DONE;
}

static void draw_ks_store(void)
{
	char line[64];
	int nv = ks_nvaults(), rows = nv + 2, pitch = rows > 5 ? 18 : LINE;

	text(16, UI_TOP, T(TXT_SAVE_THE_KEY_TO_THE_CARD));
	if (ks_type == KS_TYPE_RAW) {
		static const uint16_t KINDS[] = {TXT_SR25519_KEY, TXT_ORCHARD_SPENDING_KEY, TXT_CARDANO_EXTENDED_KEY};      /* (texts of the signer: these kinds come from it only) */
		int c = KS_CURVE(ks_flags);

		sprintf(line, "%s", c == KS_CURVE_ED25519 ? T(TXT_RAW_ED25519_KEY_TON_NO) : c == KS_CURVE_SECP256K1 ? T(TXT_RAW_SECP256K1_KEY_NO) : T(KINDS[c - KS_CURVE_SR25519]));
	}
	else sprintf(line, "%s%s", ks_type == KS_TYPE_MONERO ? T(TXT_MONERO_SEED) : ks_elen >= 32 ? T(TXT_BIP39_24_WORDS) : T(TXT_BIP39_12_WORDS), (ks_flags & KS_FLAG_PASSPHRASE) ? T(TXT_PASSPHRASE_USED) : "");
	dim(16, UI_TOP + LINE, line);
	if (ks_rc) {
		ctext(16, 60, card_error(ks_rc), 255, 120, 120);
		dim(16, 90, T(TXT_CARD_2_HOLDS_THE_KEY_STORES));
	} else {
		for (int i = 0; i < rows; i++) {                                         /* up to 5 rows: 44 .. 142 */
			const char c = i == ks_sel ? '>' : ' ';

			if (i == 0) sprintf(line, T(TXT_N_SINGLE_KEY), c, ks_singles());
			else if (i <= nv) {
				const ksd_store *v = &ks_st.st[ks_vault(i - 1)];

				sprintf(line, TN(v->n, TXT_STORE_KEYS_ONE, TXT_STORE_KEYS_MANY), c, i, v->n);
				if (v->dir.label[0]) sprintf(line + strlen(line), "  %.24s", v->dir.label);
			}
			else sprintf(line, T(ks_room_vault() ? TXT_N_NEW_STORE : TXT_N_NEW_VAULT_NO_ROOM), c);
			if (i == ks_sel) ctext(16, 44 + i * pitch, line, UI_SEL_RGB);
			else text(16, 44 + i * pitch, line);
		}
		if (ks_st.corrupt) { sprintf(line, TN(ks_st.corrupt, TXT_DAMAGED_STORE_BLOCK_NOT_TOUCHED_ONE, TXT_DAMAGED_STORE_BLOCK_NOT_TOUCHED_MANY), ks_st.corrupt); ctext(16, 44 + rows * pitch + 4, line, 255, 160, 80); }
	}
	if (ks_msg[0]) ctext(16, UI_MSG, ks_msg, 255, 160, 80);
	dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_SELECT_LOOK_AGAIN_BACK));
}

static void draw_ks_done(void)
{
	text(16, UI_TOP, T(TXT_SAVE_THE_KEY_TO_THE_CARD));
	if (strncmp(ks_msg, "Saved", 5) == 0) ctext(16, 50, ks_msg, 120, 255, 120);
	else ctext(16, 50, ks_msg, 255, 120, 120);
	dim(16, 100, T(TXT_KEEP_THE_RECOVERY_WORDS_AS));
	dim(16, 100 + LINE, T(TXT_A_CARD_CAN_BE_LOST_OR_DAMAGED));
	dim(16, UI_HINT2, T(TXT_HINT_CONTINUE));
}


static void draw_pw_choose(void)
{
	static const uint16_t M[] = {TXT_TYPE_MY_OWN_PASSWORD, TXT_RANDOM_PASSWORD_15_CHARACTERS, TXT_RANDOM_WORDS_8_WORDS,
	                             TXT_A_WEAK_ONE_IS_WARNED_ABOUT, TXT_LETTERS_AND_DIGITS_LIKE_A, TXT_WORDS_OF_THE_BIP39_LIST_EASY};

	ui_menu_ids(pw_for == PW_FOR_KEY ? TXT_PASSWORD_OF_THE_KEY : pw_for == PW_FOR_STORE ? TXT_PASSWORD_FOR_THE_STORE : TXT_PASSWORD_OF_THE_TEXT, M, 3, 1, pw_sel, TXT_HINT_CHOOSE_SELECT_BACK_2);
}

static void draw_pw_show(void)
{
	char line[64];
	int y = 62;

	text(16, UI_TOP, pw_kind == PW_WORDS ? T(TXT_RANDOM_WORDS) : T(TXT_RANDOM_PASSWORD));
	sprintf(line, T(TXT_ABOUT_N_BITS_LINE), pw_kind == PW_WORDS ? T(TXT_T_8_WORDS) : T(TXT_T_15_CHARACTERS), pw_sug_bits);
	dim(16, UI_TOP + LINE, line);
	sprintf(line, T(TXT_MIXED_IN_N_BITS_OF_BUTTON), (unsigned) entropy_bits(&bgpool));
	dim(16, UI_TOP + 2 * LINE, line);
	if (pw_kind == PW_CHARS) {
		ctext(16, y, pw_sug, UI_SEL_RGB);
	} else {
		const char *p = pw_sug;

		while (*p) {                                                           /* up to 28 characters a line, whole words */
			int n = 0, l = 0;

			while (p[n]) {
				int w = 0;

				while (p[n + w] && p[n + w] != ' ') w++;
				if (l + w + (l ? 1 : 0) > 28 && l) break;
				l += w + (l ? 1 : 0);
				n += w;
				if (p[n] == ' ') n++;
				if (!p[n]) break;
			}
			memcpy(line, p, (size_t) l);
			line[l] = 0;
			ctext(16, y, line, UI_SEL_RGB);
			y += LINE;
			p += n;
			if (!n) break;
		}
	}
	dim(16, 130, T(TXT_WRITE_IT_DOWN_EXACTLY_IT_IS));
	dim(16, 150, T(TXT_WITHOUT_IT_THE_FILE_CANNOT_BE));
	dim(16, UI_HINT1, T(TXT_HINT_ANOTHER_BACK));
	dim(16, UI_HINT2, T(TXT_HINT_HOLD_WHEN_YOU_HAVE_WRITTEN_IT));
	if (hold) bar(420, UI_HINT2 + 6, GPU_XRES - 16 - 420, 6, (uint32_t) hold, HOLD_FRAMES, 220, 160, 60);
}

static void draw_enc_kind(void)
{
	const char *const K[2] = {T(TXT_TEXT_UTF_8_UP_TO_1024_BYTES), T(TXT_HEX_BYTES_UP_TO_1024_BYTES)};
	char line[48];

	text(16, UI_TOP, T(TXT_ENCRYPT_WHAT_IS_THE_INPUT));
	for (int i = 0; i < 2; i++) {
		ui_row(16, 34 + i * LINE, i == enc_hex, K[i]);
	}
	dim(16, 34 + 3 * LINE, T(TXT_AES_256_GCM_PASSWORD_KEY_FROM));
	dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_SELECT_BACK_2));
}

static void draw_enc_out(void)
{
	const char *const PAGE[3] = {"", T(TXT_BASE64), T(TXT_HEX)};
	const int tx = 16 + 2 * 190 + 12;
	char line[64];
	int b64 = (int) strlen(enc_b64), pct = b64 * 100 / QR_CAP, y = 26;

	if (out_page == 0) {
		int warn = pct >= QR_WARN_PCT;
		text(16, UI_TOP, T(TXT_ENCRYPTED_TEXT));
		if (!msg[0]) qr_warn();
		if (qr_ok) qr_view_draw(&ctx, 12, 16, 26, &qr, qr_scale);
		if (out_ur && urp.parts > 1) sprintf(line, T(TXT_UR_CODE_N_OF_N), ur_seq, urp.parts);
		else if (out_ur) sprintf(line, T(TXT_UR_ONE_CODE));
		else sprintf(line, T(TXT_ONE_QR_CODE));
		ctext(tx, y, line, UI_SEL_RGB);
		sprintf(line, T(TXT_DATA_N_BYTES), enc_len);
		dim(tx, y += LINE, line);
		sprintf(line, T(TXT_ONE_QR_N), pct);
		if (pct > 100) ctext(tx, y += LINE, line, 255, 100, 100);
		else if (warn) ctext(tx, y += LINE, line, 255, 190, 80);
		else dim(tx, y += LINE, line);
		y += LINE;
		if (msg[0]) ctext(180, UI_TOP, msg, UI_SEL_RGB);                     /* "Not saved: card not formatted" is wider than the column */
		if (pct > 100) ctext(tx, y, T(TXT_TOO_BIG_FOR_ONE_QR), 255, 100, 100);
		else if (warn) ctext(tx, y, T(TXT_NEAR_THE_QR_LIMIT), 255, 190, 80);
		if (out_ur && urp.parts > 1) sprintf(line, T(TXT_UR_N_CODES_N_S), urp.parts, 60 / ur_fpp, (600 / ur_fpp) % 10);
		else sprintf(line, TN(urp.parts, TXT_UR_CODE_ONE, TXT_UR_CODE_MANY), urp.parts);
		dim(tx, y += LINE, line);
		dim(tx, 130, T(TXT_HINT_SAVE_TO_CARD_2));
		dim(tx, 152, ICO_SQUARE " QR / UR");
		if (out_ur && urp.parts > 1) dim(tx, UI_HINT1, T(TXT_HINT_SPEED));
		dim(tx, UI_HINT2, T(TXT_HINT_R2_TEXT_DONE));
	} else {
		const char *body = out_page == 1 ? enc_b64 : enc_hexs;
		int chunk = out_page == 1 ? 58 : 54, maxl = (UI_HINT1 - 4 - 26) / LINE, total;        /* the lines end above the message line */
		sprintf(line, T(TXT_ENCRYPTED_TEXT_N_BYTES), PAGE[out_page], enc_len);
		text(16, UI_TOP, line);
		total = utf8_lines(16, 26, body, chunk, out_scroll, maxl);
		if (out_scroll > total - maxl) out_scroll = total > maxl ? total - maxl : 0;
		if (msg[0]) ctext(16, UI_HINT1, msg, UI_SEL_RGB);
		dim(16, UI_HINT2, T(TXT_HINT_SCROLL_R2_NEXT_SAVE_DONE));
	}
}

static void draw_dec_list(void)
{
	char line[64];

	text(16, UI_TOP, T(TXT_DECRYPT_A_TEXT));
	if (dec_rc) {
		sprintf(line, T(TXT_CARD_IN_SLOT_2_N), card_error(dec_rc));
		ctext(16, 34, line, 255, 100, 100);
	} else if (dn == 0) {
		dim(16, 34, T(TXT_NO_ENCRYPTED_TEXTS_ON_THE_CARD));
	} else {
		for (int i = 0; i < dn && i < 7; i++) {
			if (dnames[i][0]) snprintf(line, sizeof line, "%c %s (%s)", i == dsel_i ? '>' : ' ', dnames[i], dlist[i].name + 12);
			else snprintf(line, sizeof line, "%c %s", i == dsel_i ? '>' : ' ', dlist[i].name + 12);
			if (i == dsel_i) ctext(16, 28 + i * LINE, line, UI_SEL_RGB);
			else text(16, 28 + i * LINE, line);
		}
	}
	if (msg[0]) ctext(16, UI_MSG, msg, 255, 100, 100);             /* below the 8th row, where the icons of the hints begin */
	dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_OPEN_BACK));
	dim(330, UI_HINT2, T(TXT_HINT_HEX_INPUT));
}

static void draw_dec_out(void)
{
	char line[48];
	int chunk = dec_hexview ? 54 : 58, maxl = (UI_HINT2 - 4 - 30) / LINE, total;

	sprintf(line, T(TXT_DECRYPTED_N_BYTES), dec_hexview ? "hex" : "text", dec_len);
	text(16, UI_TOP, line);
	total = utf8_lines(16, 30, dec_hexview ? dec_hexs : dec_text, chunk, dec_scroll, maxl);
	if (dec_scroll > total - maxl) dec_scroll = total > maxl ? total - maxl : 0;
	dim(16, UI_HINT2, T(TXT_HINT_SCROLL_TEXT_HEX_BACK));
}

static void draw_type(void)
{
	const char *const NAME[3] = {T(TXT_BIP39_WORDS_BITCOIN_ETHEREUM), T(TXT_MONERO_25_WORDS), T(TXT_TON_24_WORDS_SLOW)};
	const char *const DESC[3] = {T(TXT_MANY_COINS_FROM_ONE_SEED_MORE), T(TXT_MAIN_ADDRESS_VIEW_KEY),
	                                    T(TXT_TON_S_OWN_PHRASE_ABOUT_8)};
	char line[64];

	text(16, UI_TOP, T(TXT_WHAT_TO_CREATE));
	for (int i = 0; i < 3; i++) {
		ui_row(16, 30 + i * 26, i == tsel, NAME[i]);
	}
	if (failed) ctext(16, 140, T(TXT_ERROR_TRY_AGAIN), 255, 100, 100);
	else dim(16, 140, DESC[tsel]);
	dim(16, UI_HINT2, T(TXT_HINT_CHOOSE_SELECT_BACK_2));
}

static void draw_type2(void)
{
	char line[64];
	const char *val[3] = {w24 ? "24" : "12", wxmr ? "yes" : "no", use_pass ? "on" : "off"};
	const char *const ROW[3] = {T(TXT_WORDS), T(TXT_MONERO_TOO), T(TXT_PASSPHRASE)};

	text(16, UI_TOP, T(TXT_BIP39_WALLET));
	for (int i = 0; i < 3; i++) {
		sprintf(line, "%s: %s", ROW[i], val[i]);
		ui_row(16, 30 + i * 28, i == t2sel, line);
	}
	dim(16, 126, t2sel == 1 ? T(TXT_A_SECOND_INDEPENDENT_WALLET) : t2sel == 2 ? T(TXT_AN_EXTRA_SECRET_WORD_ASKED)
	                                                                                              : T(TXT_T_12_WORDS_ARE_ENOUGH_24_WORDS));
	dim(16, UI_HINT1, T(TXT_HINT_ROW_CHANGE));
	dim(16, UI_HINT2, T(TXT_HINT_CREATE_BACK));
}

static void draw_words(void)
{
	char line[32];
	int is_xmr = words_is_monero(words_idx);
	int n = words_total();
	int rows = (n + 2) / 3;                      /* 3 columns: 8 rows for 24 words, 9 for 25 */
	const char *p = is_xmr ? xmr_mnemonic : mnemonic;

	sprintf(line, T(TXT_SOURCE_WORDS_LINE), is_xmr ? T(TXT_MONERO) : (words_screens() > 1 ? T(TXT_BIP39) : T(TXT_RECOVERY)));
	text(MARGIN, UI_TOP + 2, line);                                              /* its icons reach 2 pixels higher than the text */
	dim(MARGIN + 17 * font_cell_w(), UI_TOP + 2, is_xmr || has_ton() ? T(TXT_WRITE_THEM_DOWN) : (used_pass ? T(TXT_KEEP_PASSPHRASE) : T(TXT_NO_PASSPHRASE)));
	if (is_xmr || (has_ton() && ton_seed_ok)) {
		const char *const SAVE = T(TXT_HINT_SAVE_THE_KEY_TO_THE_CARD);
		dim(RIGHT - font_width(SAVE), UI_TOP + 2, SAVE);
	}

	for (int i = 0; *p && i < n; i++) {
		const char *e = p;
		char w[13];
		int l = 0;
		while (*e && *e != ' ') { if (l < 12) w[l++] = *e; e++; }
		w[l] = 0;
		sprintf(line, "%2d %s", i + 1, w);
		text(40 + (i / rows) * 200, 26 + (i % rows) * LINE, line);               /* 9 rows: 26 .. 204, above the icons of the hint line */
		p = *e ? e + 1 : e;
	}
	{
		const char *const HINT = T(TXT_HINT_HOLD_TO_CHECK);
		int bx = MARGIN + font_width(HINT) + 16;

		dim(MARGIN, UI_HINT2, HINT);
		if (hold) bar(bx, UI_HINT2 + 6, RIGHT - bx, 6, (uint32_t) hold, HOLD_FRAMES, 220, 160, 60);
	}
}

/* ---- word check: after the words are shown, ask for a few of them as multiple choice. The choices are the word and
 * its alphabetical neighbours (similar spelling), so the paper has to be read carefully; "none match" catches a typo. */

static int word_index(const char *w, int len, int is_xmr)
{
	return is_xmr ? xmr_word_find(w, (size_t) len) : bip39_find(w, (size_t) len);
}

static void word_text(int idx, int is_xmr, char out[13])
{
	if (is_xmr) xmr_word((unsigned) idx, out);
	else bip39_word((unsigned) idx, out);
}

static void verify_start(void)
{
	sha256_ctx c;
	uint8_t h[32], att = (uint8_t) vattempt;
	int n = words_total(), cnt = 0;
	const char *m = words_is_monero(words_idx) ? xmr_mnemonic : mnemonic;

	sha256_init(&c);
	sha256_update(&c, (const uint8_t *) "psx-verify", 10);
	sha256_update(&c, &att, 1);
	sha256_update(&c, (const uint8_t *) m, strlen(m));
	sha256_final(&c, h);
	for (int i = 0; i < 32 && cnt < VQ; i++) {
		int p = h[i] % n, dup = 0;
		for (int j = 0; j < cnt; j++) if (vpos[j] == p) dup = 1;
		if (!dup) vpos[cnt++] = p;
	}
	for (int i = 0; i < VQ; i++)                /* ascending order: easy to follow on the paper */
		for (int j = i + 1; j < VQ; j++)
			if (vpos[j] < vpos[i]) { int t = vpos[i]; vpos[i] = vpos[j]; vpos[j] = t; }
	secure_zero(h, sizeof h);
	vq = 0; vfail = 0; vsel = 0;
}

static void verify_question(void)
{
	int is_xmr = words_is_monero(words_idx);
	const char *p = is_xmr ? xmr_mnemonic : mnemonic;
	int total = is_xmr ? 1626 : 2048;
	int idx = -1;
	int rot = (vpos[vq] * 7 + vq * 3 + vattempt) % VOPTS;

	for (int i = 0; *p; i++) {                  /* the word at position vpos[vq] */
		const char *e = p;
		while (*e && *e != ' ') e++;
		if (i == vpos[vq]) {
			int l = (int) (e - p);
			idx = word_index(p, l, is_xmr);
			if (l > 12) l = 12;
			memcpy(vword, p, (size_t) l);
			vword[l] = 0;
			break;
		}
		p = *e ? e + 1 : e;
	}
	vcorrect = -1;
	vsane = idx >= 0;
	if (idx < 0) idx = 0;
	int start = idx - 2;
	if (start < 0) start = 0;
	if (start > total - VOPTS) start = total - VOPTS;
	for (int j = 0; j < VOPTS; j++) {
		int cand = start + (j + rot) % VOPTS;
		word_text(cand, is_xmr, vopt[j]);
		if (cand == idx) vcorrect = j;
	}
	vsane = vsane && vcorrect >= 0 && !strcmp(vopt[vcorrect], vword);
	vsel = 0;
}

/* this word set is gone from RAM once confirmed */
static void words_done(void)
{
	if (words_is_monero(words_idx)) secure_zero(xmr_mnemonic, sizeof xmr_mnemonic);
	else secure_zero(mnemonic, sizeof mnemonic);
	hold = 0;
	words_page = 0;
	vattempt = 0;
	if (++words_idx >= words_screens()) { state = S_ADDR; page = 0; }
	else state = S_WORDS;
}

static void draw_verify(void)
{
	char line[48];

	if (vfail) {
		ctext(MARGIN, UI_TOP, T(TXT_MISMATCH), 255, 100, 100);
		text(MARGIN, 40, T(TXT_THE_PAPER_MUST_BE_EXACTLY_THE));
		text(MARGIN, 40 + LINE, T(TXT_WORDS_SHOWN_ON_THE_SCREEN));
		text(MARGIN, 40 + 3 * LINE, T(TXT_FIX_YOUR_NOTES_THEN_CHECK));
		sprintf(line, T(TXT_WORD_N_YOU_CHOSE_N), vpos[vq] + 1, vwhy == 2 ? "none" : vopt[vsel]);
		dim(MARGIN, 40 + 5 * LINE, line);
		sprintf(line, T(TXT_PROGRAM_CHECK_N), vsane ? "ok" : T(TXT_ERROR));
		dim(MARGIN, 40 + 6 * LINE, line);
		dim(MARGIN, UI_HINT2, T(TXT_HINT_BACK_TO_THE_WORDS));
		return;
	}
	sprintf(line, T(TXT_CHECK_N), vq + 1, VQ);
	text(MARGIN, UI_TOP, line);
	sprintf(line, T(TXT_WHICH_IS_WORD_N_ON_YOUR_PAPER), vpos[vq] + 1);
	ctext(MARGIN, 28, line, UI_SEL_RGB);
	for (int i = 0; i < VOPTS; i++) {
		snprintf(line, sizeof line, "%c %s", i == vsel ? '>' : ' ', vopt[i]);
		if (i == vsel) ctext(40, 62 + i * LINE, line, UI_SEL_RGB);
		else text(40, 62 + i * LINE, line);
	}
	dim(MARGIN, UI_HINT1, T(TXT_HINT_CHOOSE_SELECT_2));
	dim(MARGIN, UI_HINT2, T(TXT_HINT_NONE_MATCH_SEE_WORDS));
}

static const uint16_t NAMES[WALLET_STEPS] = {TXT_BITCOIN_LEGACY, TXT_BITCOIN_SEGWIT, TXT_ETHEREUM_ETC, TXT_DOGECOIN, TXT_NOSTR_NPUB_2};
static const char *const PATHS[WALLET_STEPS] = {"m/44'/0'/0'/0/0", "m/84'/0'/0'/0/0", "m/44'/60'/0'/0/0", "m/44'/3'/0'/0/0", "m/44'/1237'/0'/0/0"};

static const uint16_t TON_NAMES[TON_PAGES] = {TXT_TON_WALLET_V5R1, TXT_TON_WALLET_V5R1_BOUNCEABLE, TXT_TON_WALLET_V4R2, TXT_TON_WALLET_V4R2_BOUNCEABLE};

static const char *addr_of(int i)
{
	if (has_ton()) return ton_addr[i];
	switch (i) {
	case 0: return addrs.btc_legacy;
	case 1: return addrs.btc_segwit;
	case 2: return addrs.eth;
	case 3: return addrs.doge;
	default: return addrs.npub;
	}
}

static const char *current_address(void)
{
	if (!page_is_monero(page)) return addr_of(page);
	switch (monero_page()) {
	case 0:  return xmr_addr;
	case 1:  return xmr_view_hex;
	case XMR_INT_PAGE: return xmr_int;
	default: return xmr_sub;
	}
}

static const char *current_name(void)
{
	static char n[32];
	if (has_ton()) return T(TON_NAMES[page]);
	if (!page_is_monero(page)) return T(NAMES[page]);
	switch (monero_page()) {
	case 0:  return T(TXT_MONERO);
	case 1:  return T(TXT_MONERO_VIEW_KEY);
	case XMR_INT_PAGE: return T(TXT_MONERO_INTEGRATED_ADDRESS);
	default: sprintf(n, T(TXT_MONERO_SUBADDRESS_N), xmr_sub_idx); return n;
	}
}

/* Derive the address of the current Monero page when it is shown and not known yet: the subaddress of the chosen index (about 2 seconds), the integrated address. */
static void ensure_sub(void)
{
	if (!page_is_monero(page) || monero_page() < XMR_SUB_PAGE) return;
	if (monero_page() == XMR_INT_PAGE) {                                   /* the main address with an 8 byte payment ID; unless one was typed, Hs("psx-xmr-pid" | view key) */
		uint8_t pid[8];
		if (*xmr_int) return;
		if (!xmr_pid_hex[0]) {
			static const char HEXD[] = "0123456789abcdef";
			uint8_t buf[43], h[32];
			memcpy(buf, "psx-xmr-pid", 11);
			memcpy(buf + 11, xmr_view, 32);
			keccak256(buf, 43, h);
			for (int i = 0; i < 8; i++) { xmr_pid_hex[2 * i] = HEXD[h[i] >> 4]; xmr_pid_hex[2 * i + 1] = HEXD[h[i] & 15]; }
			xmr_pid_hex[16] = 0;
			secure_zero(buf, sizeof buf);
		}
		if (hex_decode(xmr_pid_hex, pid, 8) != 8 || xmr_integrated_address(xmr_int, sizeof xmr_int, xmr_spend_pub, xmr_view_pub, pid) < 0) strcpy(xmr_int, "error");
		return;
	}
	if (xmr_sub_have == xmr_sub_idx) return;
	show_status(T(TXT_DERIVING_SUBADDRESS), T(TXT_ABOUT_2_SECONDS));
	if (xmr_subaddress(xmr_sub, sizeof xmr_sub, xmr_view, xmr_spend_pub, 0, (uint32_t) xmr_sub_idx) < 0) strcpy(xmr_sub, "error");
	xmr_sub_have = xmr_sub_idx;
}

/* (Re)build the QR code of the current address and put it into VRAM. Runs between frames, the GPU is idle. */
static void refresh_qr(void)
{
	const char *a = current_address();
	qr_ok = qr_encode(&qr, (const uint8_t *) a, strlen(a), QR_ECC_M) > 0;
	if (qr_ok) {
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	}
	qr_dirty = 0;
}

static void draw_qr(void)
{
	char line[48];

	text(16, UI_TOP, current_name());
	qr_warn();
	if (qr_ok) {
		int w = qr_view_pixels(&qr, qr_scale);
		qr_view_draw(&ctx, 8, (GPU_XRES - 2 * w) / 2, UI_TOP + 20, &qr, qr_scale);
	} else {
		text(16, 60, T(TXT_QR_TOO_LONG));
	}
	if (page_count() > 1) sprintf(line, T(TXT_HINT_N_BACK), page + 1, page_count());
	else sprintf(line, T(TXT_HINT_BACK));
	dim(16, UI_HINT2, line);
}

static void draw_xpub(void)
{
	char line[64];

	if (!xp_have) {
		const char *names[XPUB_KINDS], *descs[XPUB_KINDS];
		for (int i = 0; i < XPUB_KINDS; i++) { names[i] = xpub_name(i); descs[i] = xpub_path(i); }
		int y = ui_menu(T(TXT_WATCH_ONLY_EXPORT), names, msg[0] ? NULL : descs, XPUB_KINDS, xp_sel, T(TXT_HINT_CHOOSE_SELECT));
		if (msg[0]) ctext(16, y, msg, 255, 120, 120);
		dim(16, UI_HINT2, T(TXT_HINT_BACK));
		return;
	}
	if (xp_qr) {
		text(16, UI_TOP, xp_page ? T(TXT_OUTPUT_DESCRIPTOR) : xpub_name(xp_sel));
		qr_warn();
		if (qr_ok) { int w = qr_view_pixels(&qr, qr_scale); qr_view_draw(&ctx, 8, (GPU_XRES - 2 * w) / 2, UI_TOP + 20, &qr, qr_scale); }
		else text(16, 60, T(TXT_QR_TOO_LONG));
		dim(16, UI_HINT2, T(TXT_HINT_KEY_DESCRIPTOR_BACK));
		return;
	}
	text(16, UI_TOP, xpub_name(xp_sel));
	sprintf(line, "%s  %s", xpub_path(xp_sel), xp_page ? T(TXT_OUTPUT_DESCRIPTOR_2) : xp_sel == XPUB_BIP47 ? T(TXT_PAYMENT_CODE) : T(TXT_EXTENDED_PUBLIC_KEY));
	dim(16, UI_TOP + LINE, line);
	wrapped(16, 50, xp_page ? xp_desc : xp_key, 0);                             /* a descriptor: three lines, 50 .. 108 */
	dim(16, 152, T(TXT_HINT_KEY_DESCRIPTOR_QR_CODE));
	dim(16, 178, xp_page ? T(TXT_IMPORT_IT_IN_A_WATCH_ONLY) : T(TXT_PASTE_OR_SCAN_IT_AS_THE_WALLET));
	dim(16, UI_HINT2, T(TXT_HINT_BACK));
}

/* the watch-only export (L1) makes the extended keys of Bitcoin (xpub, ypub, zpub, taproot): only the Bitcoin pages of the wallet fit it, not Ethereum, Dogecoin, Nostr, Monero, TON */
static const char *const PCHAIN[WALLET_STEPS] = {"btc44", "btc84", "eth", "doge", "nostr"};    /* the chains of the five pages (PATHS): their secret keys */
static int addr_secret_ok(void) { return hs_valid && !has_ton() && !page_is_monero(page); }
static int watch_ok(void) { return hs_valid && !has_ton() && !page_is_monero(page) && page < 2; }

static void draw_addr(void)
{
	char line[48];

	if (qr_mode) { draw_qr(); return; }
	text(16, UI_TOP, current_name());
	if (page_is_monero(page)) {
		int mp = monero_page();
		dim(16, UI_TOP + LINE, mp == 0 ? T(TXT_MAIN_ADDRESS_MAINNET)
		                       : mp == 1 ? T(TXT_PRIVATE_VIEW_KEY_SEES_INCOMING)
		                       : mp == XMR_INT_PAGE ? T(TXT_MAIN_ADDRESS_WITH_A_PAYMENT_ID) : T(TXT_ACCOUNT_0_FOR_RECEIVING));
		wrapped(16, 50, current_address(), mp == 1 ? 32 : 0);                  /* two lines at most: 50 .. 88 */
		if (mp == 1) dim(16, 96, T(TXT_WITH_THE_MAIN_ADDRESS_VIEW));
		if (mp == XMR_INT_PAGE) { char l[40]; sprintf(l, T(TXT_PAYMENT_ID_N), xmr_pid_hex); dim(16, 96, l); }
		if (mp == XMR_SUB_PAGE) dim(330, 152, ICO_L1 ICO_R1 " -1 +1  " ICO_L2 ICO_R2 " -10 +10");
		if (mp == XMR_INT_PAGE) dim(330, 152, T(TXT_HINT_TYPE_A_PAYMENT_ID));
	} else {
		dim(16, UI_TOP + LINE, has_ton() ? T(TXT_UQ_FOR_WALLETS_EQ_BOUNCEABLE) : PATHS[page]);
		wrapped(16, 50, addr_of(page), 0);
	}
	if (page_count() > 1) {
		sprintf(line, ICO_LEFTRIGHT " %d / %d", page + 1, page_count());
		text(16, 124, line);
	}
	dim(140, 124, T(TXT_ADDR_NOTE));
	dim(16, 152, T(addr_secret_ok() ? TXT_HINT_QR_SECRET_KEY : TXT_HINT_SHOW_QR_CODE));
#ifdef WITH_LOADER
	if (!addr_modal_on && (hs_valid || hs.xmr_ok || (has_ton() && ton_seed_ok))) dim(16, 180, T(TXT_HINT_SIGN_WITH_THIS_SEED));
#endif
	if (hs_valid) dim(330, 180, T(TXT_HINT_MORE_COINS));
	if (watch_ok()) dim(330, 152, T(TXT_HINT_WATCH_ONLY_KEY));
	if (hs_valid || (has_ton() && ton_seed_ok)) dim(330, UI_HINT2, T(TXT_HINT_SAVE_KEY_TO_CARD));
	if (hold) bar(16, 214, 290, 6, (uint32_t) hold, HOLD_FRAMES, 220, 60, 60);     /* SELECT held: in place of its hint */
	else dim(16, UI_HINT2, T(TXT_HINT_HOLD_TO_WIPE_RESTART));
}

/* ---- more coins and chains, HD wallet styles, custom coins (core/coin/chains.c) ----
 * The BIP39 secret (seed, entropy, passphrase) stays in RAM while the address pages are open, so that every chain and every
 * path can be derived on demand; restart() wipes it. Everything that is shown is public.
 *
 * Flow: chain list (sections, L1 / R1) -> style and count -> the addresses, one per page; sr25519 coins and the custom coin
 * have their own forms. A style says which level of the path runs through the count: the address index, or the account. */

#define CLIST_MAX 20
#define CHAIN_ROWS 7
enum { KT_PATH, KT_JUNCTION, KT_HRP };

static int              cgroup, csel, ctop;
static int              cstyle, ccount, cidx, cseg, cerr, cqr, cexpert, clist_n, ktarget, preturn;
static const chain_def *cc;                  /* the chain on the page */
static hd_path          cbase, cown, epath, custom_path;
static hd_path         *ptarget;             /* where the path editor writes its result */
static char             cstr[84];            /* sr25519: the junctions */
static char             skey[400];           /* the secret key being shown (see secret_wipe) */
static const char      *slabel = "";
static int              sstage, sres;        /* 0 warning, 1 key, 2 QR code; the length of the key or an error */
static int              sview;               /* 1: the view-only keys of the chain (L1 on its page) instead of the key that spends */
static int              sec_addr;            /* the secret key page was opened from an address page of the five coins (back goes there, not to the chain page) */
static char             clist[CLIST_MAX][132];
static char             ptitle[72];
static chain_def        custom;
static char             custom_hrp[12];
static int              ccurve, ckind, cfield;      /* custom coin: curve (0 secp256k1, 1 ed25519), kind, selected row */
static uint16_t         cparam;

typedef struct { uint16_t name; uint8_t curve, kind, ptype; uint16_t pdef; const char *hdef; } custom_kind;
/* ptype: 0 no parameter, 1 a number (version byte / prefix), 2 a text (bech32 prefix) */
static const custom_kind CK[] = {
	{TXT_P2PKH_BASE58_1_L_D,     CV_SECP256K1, K_P2PKH,      1, 0,        NULL},
	{TXT_P2SH_P2WPKH_BASE58_3_M,    CV_SECP256K1, K_P2SH_WPKH,  1, 5,        NULL},
	{TXT_P2WPKH_BECH32_BC1Q,           CV_SECP256K1, K_P2WPKH,     2, 0,        "bc"},
	{TXT_P2TR_BECH32M_BC1P,            CV_SECP256K1, K_P2TR,       2, 0,        "bc"},
	{TXT_CASHADDR_BITCOINCASH_Q,       CV_SECP256K1, K_CASHADDR,   2, 0,        "bitcoincash"},
	{TXT_ETHEREUM_STYLE_0X,              CV_SECP256K1, K_EVM,        0, 0,        NULL},
	{TXT_TRON_T,                         CV_SECP256K1, K_TRON,       0, 0,        NULL},
	{TXT_XRP_R,                          CV_SECP256K1, K_XRP,        0, 0,        NULL},
	{TXT_COSMOS_STYLE_BECH32,              CV_SECP256K1, K_COSMOS,     2, 0,        "cosmos"},
	{TXT_PUBLIC_KEY_HEX_33_BYTES,       CV_SECP256K1, K_PUBHEX,     0, 0,        NULL},
	{TXT_SOLANA_BASE58,                    CV_ED25519,   K_SOLANA,     0, 0,        NULL},
	{TXT_STELLAR_G,                      CV_ED25519,   K_STELLAR,    0, 0,        NULL},
	{TXT_NEAR_ACCOUNT_HEX,               CV_ED25519,   K_NEAR,       0, 0,        NULL},
	{TXT_SS58_SUBSTRATE_ED25519,        CV_ED25519,   K_SS58_ED,    1, 0,        NULL},
	{TXT_TON_V4R2,                         CV_ED25519,   K_TON,        0, TON_V4R2, NULL},
	{TXT_TON_V5R1,                         CV_ED25519,   K_TON,        0, TON_V5R1, NULL},
	{TXT_PUBLIC_KEY_HEX_32_BYTES,       CV_ED25519,   K_PUBHEX,     0, 0,        NULL},
};
#define NCK ((int) (sizeof CK / sizeof CK[0]))

static const char *chain_wait(const chain_def *c)
{
	return c->curve == CV_ORCHARD ? T(TXT_T_10_TO_30_SECONDS_EACH) : c->curve == CV_ICARUS ? T(TXT_T_10_TO_20_SECONDS_EACH)
	     : c->curve == CV_SR25519 ? T(TXT_ABOUT_8_SECONDS) : T(TXT_A_FEW_SECONDS_EACH);
}

static int count_max(const chain_def *c) { return c->curve == CV_ORCHARD ? 3 : c->curve == CV_ICARUS ? 5 : CLIST_MAX; }

/* ---- the sections of the chain list ---- */

static int group_len(int g)
{
	int n = 0;
	if (g == NCHAIN_GROUPS - 1) return 1;
	for (int i = 0; i < NCHAINS; i++) n += CHAINS[i].group == g;
	return n;
}

static const chain_def *group_item(int g, int k)
{
	if (g == NCHAIN_GROUPS - 1) return &custom;
	for (int i = 0; i < NCHAINS; i++) if (CHAINS[i].group == g && k-- == 0) return &CHAINS[i];
	return NULL;
}

/* ---- paths ---- */

static const char *path_problem(const chain_def *c, const hd_path *p)
{
	if ((c->curve == CV_ED25519 || c->curve == CV_ORCHARD) && !path_all_hardened(p)) return T(TXT_EVERY_LEVEL_NEEDS_THE_MARK);
	if (c->curve == CV_ORCHARD && !p->n) return T(TXT_NEEDS_AT_LEAST_ONE_LEVEL);
	if (c->curve == CV_ICARUS && p->n < 2) return T(TXT_NEEDS_AT_LEAST_TWO_LEVELS);
	return NULL;
}

/* a chain with a second wallet family (MWEB: Cake Wallet, Electrum-LTC) uses style 1 for that family; the other chains for the account level */
static int family_style(int style) { return style == 1 && chain_alt_path(cc); }
static int acct_style(int style) { return style == 1 && !chain_alt_path(cc); }

/* which level the count runs through */
static int vary_pos(const hd_path *p, int style) { return acct_style(style) ? 2 : p->n - 1; }

static int style_ok(int s)
{
	if (s == 1 && chain_alt_path(cc)) return 1;
	if (s == 1) return cbase.n >= 3 && cbase.n - 1 != 2;
	return s == 2 || cbase.n >= 1;
}

/* a style in words: which level of the path runs through the count */
static const char *style_name(int s)
{
	if (s == 2) return T(TXT_OWN_PATH_ADVANCED);
	if (chain_alt_path(cc)) return s == 1 ? T(TXT_MWEB_CAKE_WALLET_ELECTRUM_LTC) : T(TXT_MWEB_LITECOIN_CORE);
	return s == 1 || cbase.n - 1 == 2 ? T(TXT_NEW_ACCOUNT_PER_ADDRESS) : T(TXT_ONE_ACCOUNT_MANY_ADDRESSES);
}

/* the wallet apps that follow the style, by coin family */
static const char *style_wallets(const chain_def *c, int s)
{
	int acct = s == 1 || cbase.n - 1 == 2;
	if (s == 2) return T(TXT_FOR_A_WALLET_WITH_ITS_OWN);
	if (chain_alt_path(c)) return s == 1 ? T(TXT_MWEB_CAKE_WALLET_ELECTRUM_LTC_MWEBD) : T(TXT_MWEB_LITECOIN_CORE_WALLET);
	if (c->kind == K_EVM) return acct ? T(TXT_LEDGER_LIVE) : T(TXT_METAMASK_TREZOR_RABBY_EXODUS);
	if (c->kind == K_SOLANA) return acct ? T(TXT_PHANTOM_SOLFLARE_LEDGER) : T(TXT_SOLANA_CLI_SOLLET_OLD);
	if (c->curve == CV_SECP256K1 && (c->kind == K_P2PKH || c->kind == K_P2SH_WPKH || c->kind == K_P2WPKH || c->kind == K_P2TR ||
	                                 c->kind == K_CASHADDR || c->kind == K_ZEC_T))
		return acct ? T(TXT_TREZOR_SUITE_LEDGER_LIVE) : T(TXT_SPARROW_ELECTRUM_BITCOIN_CORE);
	if (c->curve == CV_ICARUS) return acct ? T(TXT_YOROI_LACE) : T(TXT_YOROI_LACE);
	if (c->curve == CV_ORCHARD) return T(TXT_ZASHI_YWALLET);
	return acct ? T(TXT_HARDWARE_WALLETS_USUALLY) : T(TXT_MOST_WALLETS);
}

/* the path of entry k of the list in a style */
static void build_path_s(hd_path *p, int style, int k)
{
	int vp;
	*p = style == 2 ? cown : cbase;
	if (family_style(style)) path_parse(p, chain_alt_path(cc));
	vp = vary_pos(p, style);
	if (p->n && vp >= 0 && vp < p->n) p->idx[vp] = (p->idx[vp] & PATH_HARD) | (((p->idx[vp] & ~PATH_HARD) + (uint32_t) k) & ~PATH_HARD);
}

static void build_path(hd_path *p, int k) { build_path_s(p, cstyle, k); }

/* m/84'/0'/0'/0/{i}: the path with the running level shown as {i} or {a} */
static void template_text(char *out, size_t cap, int style)
{
	hd_path alt;
	const hd_path *p = style == 2 ? &cown : &cbase;
	int vp;
	size_t o = 0;
	if (family_style(style)) { path_parse(&alt, chain_alt_path(cc)); p = &alt; }
	vp = vary_pos(p, style);
	if (cap < 4) return;
	out[o++] = 'm';
	for (int i = 0; i < p->n && o + 16 < cap; i++) {
		o += (size_t) sprintf(out + o, "/");
		if (i == vp) o += (size_t) sprintf(out + o, acct_style(style) ? "{a}" : "{i}");
		else o += (size_t) sprintf(out + o, "%lu", (unsigned long) (p->idx[i] & ~PATH_HARD));
		if (p->idx[i] & PATH_HARD) o += (size_t) sprintf(out + o, "'");
	}
	out[o] = 0;
}

/* ---- deriving ---- */

static void sr_derive(void)
{
	show_status(T(TXT_DERIVING_THE_ADDRESS), chain_wait(cc));
	cerr = chain_address_str(clist[0], sizeof clist[0], cc, &hs, cstr);
	if (cerr < 0) clist[0][0] = 0;
	clist_n = 1;
	cidx = 0;
	cqr = 0;
}

static void list_derive(void)
{
	for (int k = 0; k < ccount; k++) {
		char b[56], t[84];
		hd_path p;
		int r;
		sprintf(b, "%d of %d, %s", k + 1, ccount, chain_wait(cc));
		show_status(T(TXT_DERIVING_ADDRESSES), b);
		build_path(&p, k);
		path_format(&p, t, sizeof t);
		r = chain_address_str(clist[k], sizeof clist[k], cc, &hs, t);
		if (r < 0) clist[k][0] = 0;
		if (k == 0) cerr = r;
	}
	clist_n = ccount;
	cidx = 0;
	cqr = 0;
	msg[0] = 0;
	state = S_CHAIN;
}

/* open a chain: sr25519 coins go straight to their junction form, the others ask for style and count first */
static void chain_select(const chain_def *c)
{
	cc = c;
	msg[0] = 0;
	if (c->curve == CV_SR25519) {
		snprintf(cstr, sizeof cstr, "%s", c->path);
		sr_derive();
		state = S_CHAIN;
		return;
	}
	if (c == &custom) cbase = custom_path;
	else path_parse(&cbase, c->path);
	cown = cbase;
	cstyle = 0;
	ccount = count_max(c) < 5 ? 1 : 5;
	state = S_STYLE;
}

/* ---- the path editor ---- */

static void edit_path(hd_path *target, int ret, int expert)
{
	ptarget = target;
	epath = *target;
	preturn = ret;
	cexpert = expert;
	cseg = epath.n ? epath.n - 1 : 0;
	state = S_PATH;
}

static int seg_locked(int i) { return i < 2 && !cexpert; }       /* purpose and coin type: the chain decides them */

static void key_edit(int target, const char *title, const char *initial, int mode, int limit)
{
	ktarget = target;
	kb_init(&kb, title, initial, 0, 0);
	kb_set(&kb, limit, mode);
	state = S_PATHTXT;
}

/* the typed text of the keypad / keyboard */
static void key_done(void)
{
	char t[84];
	if (ktarget == KT_HRP) {
		snprintf(custom_hrp, sizeof custom_hrp, "%s", kb.text);
		kb_wipe(&kb);
		state = S_CUSTOM;
	} else if (ktarget == KT_JUNCTION) {
		uint8_t dummy[32] = {1};
		int bad = substrate_derive_path(dummy, kb.text);
		secure_zero(dummy, sizeof dummy);
		snprintf(cstr, sizeof cstr, "%s", kb.text);
		if (bad) { key_edit(KT_JUNCTION, T(TXT_JUNCTIONS_LIKE_NAME_0_AGAIN), cstr, 0, (int) sizeof cstr - 1); return; }
		kb_wipe(&kb);
		sr_derive();
		state = S_CHAIN;
	} else {
		hd_path p;
		int r = path_parse(&p, kb.text);
		const char *why = r == PATH_ERR_SYNTAX ? T(TXT_BAD_SYNTAX) : r == PATH_ERR_RANGE ? T(TXT_NUMBER_TOO_LARGE) : r == PATH_ERR_DEPTH ? T(TXT_TOO_MANY_LEVELS) : path_problem(cc, &p);
		if (why) {
			snprintf(ptitle, sizeof ptitle, T(TXT_PATH_N_AGAIN), why);
			snprintf(t, sizeof t, "%s", kb.text);
			key_edit(KT_PATH, ptitle, t, 2, (int) sizeof t - 1);
			return;
		}
		kb_wipe(&kb);
		epath = p;
		cseg = epath.n ? epath.n - 1 : 0;
		state = S_PATH;
	}
}

static void chain_qr(void)
{
	qr_ok = qr_encode(&qr, (const uint8_t *) clist[cidx], strlen(clist[cidx]), QR_ECC_M) > 0;
	if (qr_ok) {
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	}
	cqr = 1;
}

/* ---- the secret key of the address on the screen: a warning, then the key as text, then (X) as a QR code ----
 * Nothing is stored: the buffer, the QR code and the VRAM texture are wiped when the page is left. */

static void secret_wipe_qr(void)
{
	secure_zero(&qr, sizeof qr);
	qr_view_clear();
	qr_ok = 0;
	qr_dirty = 1;
}

static void secret_wipe(void)
{
	secure_zero(skey, sizeof skey);
	sres = 0;
	slabel = "";
	if (sstage == 2) secret_wipe_qr();
	sstage = 0;
}

static void secret_derive(void)
{
	hd_path p;
	char t[84];

	show_status(T(TXT_SECRET_KEY_2), cc->curve == CV_SR25519 || cc->curve == CV_ICARUS ? T(TXT_DERIVING) : T(TXT_DERIVING_THE_KEY));
	build_path(&p, cidx);
	path_format(&p, t, sizeof t);
	sres = sview ? chain_view_keys(skey, sizeof skey, &slabel, cc, &hs, &p) : chain_secret(skey, sizeof skey, &slabel, cc, &hs, &p, cstr);
	if (sres < 0) skey[0] = 0;
}

static void secret_qr(void)
{
	qr_ok = qr_encode(&qr, (const uint8_t *) skey, strlen(skey), QR_ECC_M) > 0 || qr_encode(&qr, (const uint8_t *) skey, strlen(skey), QR_ECC_L) > 0;
	if (qr_ok) {
		qr_scale = qr_view_scale(&qr);
		qr_view_upload(&qr, qr_scale);
	}
	sstage = 2;
}

static void draw_secret(void)
{
	char t[100];
	hd_path p;

	if (sstage == 2) {
		ctext(16, UI_TOP, T(TXT_SECRET_KEY_DO_NOT_SHOW_TO), 255, 100, 100);
		if (qr_ok) qr_view_draw(&ctx, 8, (GPU_XRES - 2 * qr_view_pixels(&qr, qr_scale)) / 2, UI_TOP + 20, &qr, qr_scale);
		else text(16, 60, T(TXT_QR_TOO_LONG));
		dim(16, UI_HINT2, T(TXT_HINT_HIDE));
		return;
	}
	if (sstage == 0) {
		ctext(16, UI_TOP, T(sview ? TXT_VIEW_ONLY_KEYS : TXT_SECRET_KEY_2), 255, 100, 100);
		dim(16, UI_TOP + LINE, T(cc->name));
		ctext(16, 64, T(sview ? TXT_ANYONE_WHO_SEES_THESE_CAN_SEE : TXT_ANYONE_WHO_SEES_THIS_CAN_SPEND), 255, 180, 120);
		ctext(16, 64 + LINE, T(sview ? TXT_PAYMENT_TO_THIS_ADDRESS_NOT_SPEND : TXT_THE_FUNDS_OF_THIS_ADDRESS), 255, 180, 120);
		text(16, 64 + 2 * LINE, T(TXT_NO_CAMERA_NO_ONLOOKERS_NOTHING));
		dim(16, UI_HINT1, T(TXT_HINT_HOLD_TO_SHOW));
		if (hold) bar(180, UI_HINT1 + 7, RIGHT - 180, 4, (uint32_t) hold, HOLD_FRAMES, 220, 60, 60);
		dim(16, UI_HINT2, T(TXT_HINT_BACK_2));
		return;
	}
	ctext(16, UI_TOP, T(sview ? TXT_VIEW_ONLY_KEYS : TXT_SECRET_KEY), 255, 100, 100);
	if (cc->curve == CV_SR25519) sprintf(t, T(TXT_JUNCTIONS_N), cstr[0] ? cstr : T(TXT_NONE));
	else { build_path(&p, cidx); path_format(&p, t, sizeof t); }
	dim(16, UI_TOP + LINE, t);
	if (sres <= 0) {
		ctext(16, 66, T(TXT_CANNOT_DERIVE_THIS_KEY), 255, 100, 100);
		dim(16, UI_HINT2, T(TXT_HINT_BACK_2));
		return;
	}
	dim(16, UI_TOP + 2 * LINE, slabel);
	wrapped2(16, 66, skey);
	dim(16, UI_HINT1, T(sview ? TXT_HINT_QR_CODE_HIDE_SPEND_KEYS : TXT_HINT_QR_CODE_HIDE));
	dim(16, UI_HINT2, T(TXT_WIPED_WHEN_YOU_LEAVE_THIS_PAGE));
}

/* ---- the custom coin ---- */

static int ck_next(int from, int dir)
{
	for (int i = 1; i <= NCK; i++) {
		int k = (from + dir * i + NCK * 2) % NCK;
		if (CK[k].curve == (ccurve ? CV_ED25519 : CV_SECP256K1)) return k;
	}
	return from;
}

static void custom_kind_set(int k)
{
	ckind = k;
	cparam = CK[k].pdef;
	snprintf(custom_hrp, sizeof custom_hrp, "%s", CK[k].hdef ? CK[k].hdef : "");
}

static void custom_sync(void)
{
	custom.id = "custom";
	custom.name = TXT_CUSTOM_COIN_YOU_CHOOSE;
	custom.curve = CK[ckind].curve;
	custom.kind = CK[ckind].kind;
	custom.param = cparam;
	custom.hrp = custom_hrp;
	custom.path = "m";
	custom.group = NCHAIN_GROUPS - 1;
}

static void custom_init(void)
{
	ccurve = 0;
	custom_kind_set(0);
	path_parse(&custom_path, "m/44'/0'/0'/0/0");
	custom_sync();
}

static void custom_curve(int c)
{
	ccurve = c;
	custom_kind_set(ck_next(c ? NCK - 1 : NCK - 1, 1));      /* the first kind of that curve */
	path_parse(&custom_path, c ? "m/44'/0'/0'/0'" : "m/44'/0'/0'/0/0");
	custom_sync();
}

/* ---- drawing ---- */

static void draw_chains(void)
{
	char line[64];
	int n = group_len(cgroup);
	sprintf(line, "%s  (%d)", T(CHAIN_GROUPS[cgroup]), n);
	text(16, UI_TOP, line);
	sprintf(line, T(TXT_SECTION_N), cgroup + 1, NCHAIN_GROUPS);
	dim(GPU_XRES - 16 - font_width(line), UI_TOP, line);
	for (int i = 0; i < CHAIN_ROWS && ctop + i < n; i++) {
		int idx = ctop + i;
		const chain_def *c = group_item(cgroup, idx);
		ui_row(16, 28 + i * LINE, idx == csel, T(c->name));
	}
	dim(16, UI_HINT1, T(TXT_HINT_CHOOSE_OPEN_SECTION));
	dim(16, UI_HINT2, T(TXT_HINT_BACK_2));
}

static void draw_style(void)
{
	char line[96], t[84];
	hd_path p;
	int y = UI_TOP + LINE;

	text(16, UI_TOP, T(cc->name));
	sprintf(line, T(TXT_N_ADDRESSES), ccount);
	ui_right(UI_TOP, line, UI_SEL_RGB);
	for (int s = 0; s < 3; s++) {
		if (!style_ok(s)) continue;
		ui_row(16, y, s == cstyle, style_name(s));
		y += 20;
	}
	sprintf(t, cstyle == 2 ? "%s" : T(TXT_USED_BY_N), style_wallets(cc, cstyle));
	dim(16, 88, t);
	template_text(t, sizeof t, cstyle);
	dim(16, 106, t);
	build_path_s(&p, cstyle, 1);
	path_format(&p, line, sizeof line);
	sprintf(t, T(TXT_T_2ND_ADDRESS_N), line);
	dim(16, 124, t);
	dim(16, 146, T(chain_has_view_keys(cc) ? (cstyle == 1 ? TXT_MWEB_INDEX_0_CHANGE_RECEIVING_FROM_1 : TXT_MWEB_INDEX_0_CHANGE_1_PEG_IN) : TXT_NOT_SURE_TAKE_THE_FIRST_BOTH));        /* MWEB: what the first indexes are */
	sprintf(line, T(TXT_HINT_STYLE_COUNT_1_N_5), count_max(cc));
	dim(16, UI_HINT1, line);
	dim(16, UI_HINT2, T(TXT_HINT_DERIVE_OWN_PATH_BACK));
}

static void draw_chain(void)
{
	char line[96], t[84];
	hd_path p;

	if (cqr) {
		text(16, UI_TOP, T(cc->name));
		if (qr_ok) qr_view_draw(&ctx, 8, (GPU_XRES - 2 * qr_view_pixels(&qr, qr_scale)) / 2, UI_TOP + 20, &qr, qr_scale);
		else text(16, 60, T(TXT_QR_TOO_LONG));
		dim(16, UI_HINT2, T(TXT_HINT_BACK));
		return;
	}
	text(16, UI_TOP, T(cc->name));
	if (cc->curve == CV_SR25519) sprintf(line, T(TXT_JUNCTIONS_N), cstr[0] ? cstr : T(TXT_NONE));
	else { build_path(&p, cidx); path_format(&p, line, sizeof line); }
	dim(16, UI_TOP + LINE, line);
	if (cc->curve != CV_SR25519 && (cstyle == 2 || cc == &custom)) ctext(16, UI_TOP + 2 * LINE, T(TXT_OWN_PATH_CHECK_IT_MATCHES_YOUR), 255, 190, 80);
	if (clist[cidx][0]) wrapped(16, 66, clist[cidx], 0);
	else ctext(16, 66, cerr == CHAIN_ERR_PATH ? T(TXT_THIS_PATH_DOES_NOT_SUIT_THE) : T(TXT_CANNOT_DERIVE_THIS_ADDRESS), 255, 100, 100);
	if (clist_n > 1) {
		sprintf(t, ICO_LEFTRIGHT " %d / %d", cidx + 1, clist_n);
		text(16, 140, t);
	}
	if (msg[0]) ctext(330, 140, msg, UI_SEL_RGB);
	if (cc->curve == CV_SR25519) dim(16, UI_HINT1, T(TXT_HINT_QR_JUNCTIONS_SECRET_KEY));
	else if (cc->curve == CV_ORCHARD) dim(16, UI_HINT1, T(TXT_HINT_QR));   /* its key is restored from the words */
	else dim(16, UI_HINT1, chain_has_view_keys(cc) ? T(TXT_HINT_QR_VIEW_KEYS) : T(TXT_HINT_QR_SECRET_KEY));
	dim(16, UI_HINT2, T(TXT_HINT_BACK_2));
}

static void draw_path(void)
{
	char line[96];
	const char *why;

	text(16, UI_TOP, T(TXT_DERIVATION_PATH));
	dim(16, UI_TOP + LINE, T(cc->name));
	text(16, 58, "m");
	for (int i = 0; i < epath.n; i++) {
		int x = 36 + i * 58, sel = i == cseg, lock = seg_locked(i), hard = (epath.idx[i] & PATH_HARD) != 0;
		char seg[16];
		sprintf(seg, "%lu", (unsigned long) (epath.idx[i] & ~PATH_HARD));
		if ((int) strlen(seg) + hard > 5) strcpy(seg + 3 - hard, "..");             /* five characters fit the box: 21..' */
		if (hard) strcat(seg, "'");
		gpu_draw_rect(&ctx, 5, x, 56, 54, 24, sel ? 255 : lock ? 36 : 50, sel ? 210 : lock ? 40 : 56, sel ? 60 : lock ? 60 : 96);
		ctext(x + (54 - font_width(seg)) / 2, 56 + 3, seg, sel ? 20 : lock ? 120 : 255, sel ? 20 : lock ? 120 : 255, sel ? 20 : lock ? 130 : 255);
	}
	if (!epath.n) dim(36, 58, T(TXT_NO_LEVELS));
	path_format(&epath, line, sizeof line);
	if (strlen(line) > 60) { memmove(line + 3, line + strlen(line) - 57, 58); memcpy(line, "...", 3); }     /* the end of a long path */
	dim(16, 88, line);
	why = path_problem(cc, &epath);
	if (why) ctext(16, 108, why, 255, 100, 100);
	else if (!cexpert && epath.n > 1) dim(16, 108, T(TXT_THE_FIRST_TWO_LEVELS_PURPOSE));
	else ctext(16, 108, "OK", 120, 230, 120);
	ctext(16, 128, T(TXT_PATH_WARNING), 255, 160, 80);
	dim(16, 150, T(TXT_HINT_LEVEL_1_10));
	dim(16, UI_HINT1, T(TXT_HINT_APPLY_ADD_DELETE_R2_TYPE));
	dim(16, UI_HINT2, T(TXT_HINT_CANCEL_L2_UNLOCK_THE_FIRST_TWO));
}

static void draw_custom(void)
{
	char line[100], t[84];
	const custom_kind *k = &CK[ckind];
	const char *const ROW[5] = {T(TXT_CURVE), T(TXT_ADDRESS), T(TXT_PARAMETER), T(TXT_PATH), ""};

	text(16, UI_TOP, T(TXT_CUSTOM_COIN));
	for (int i = 0; i < 5; i++) {
		int y = 26 + i * 24;
		if (i == 4) sprintf(line, T(TXT_N_CONTINUE), cfield == 4 ? '>' : ' ');
		else {
			const char *v;
			if (i == 0) v = ccurve ? T(TXT_ED25519_SLIP_10) : T(TXT_SECP256K1_BIP32);
			else if (i == 1) v = T(k->name);
			else if (i == 2) {
				if (k->ptype == 1) { sprintf(t, "%u (0x%02x)", (unsigned) cparam, (unsigned) cparam); v = t; }
				else if (k->ptype == 2) v = custom_hrp[0] ? custom_hrp : T(TXT_EMPTY);
				else v = "none";
			} else { path_format(&custom_path, t, sizeof t); v = t; }
			sprintf(line, "%c %s: %s", cfield == i ? '>' : ' ', ROW[i], v);
		}
		ui_hl(16, y, cfield == i, line);
	}
	{
		custom_sync();
		if (path_problem(&custom, &custom_path)) ctext(16, 26 + 5 * 24, path_problem(&custom, &custom_path), 255, 100, 100);
	}
	dim(16, UI_HINT1, T(TXT_HINT_ROW_CHANGE_16));
	dim(16, UI_HINT2, T(TXT_HINT_EDIT_BACK));
}

/* ---- state machine, once per frame ---- */

/* generate with the entropy pool (and the passphrase in kb.text if one was entered); on failure start over */
static void start_generate(void)
{
	enum wtype chosen = wtype;
	used_pass = use_pass && has_bip39() && kb.text[0];
	failed = generate();
	if (!failed) { state = S_WORDS; words_idx = 0; words_page = 0; hold = 0; }
	else { restart(); wtype = chosen; failed = 1; state = S_SOURCE; }   /* the pool is spent: collect fresh entropy */
}

/* ---- start menu, encryption menu, restore from words ---- */

/* ---- the tip of the main menu ----
 * One of TIP_COUNT security tips (the texts TIP_1 ... in a row), another every time the main menu comes up: the system has no clock, so the number is made of the cycle counter and the
 * frame counter, which after a visit to another screen depend on how long the user took. Right of the menu, in the colour of the "splash" of a game's title screen. */
#define TIP_COUNT 15
#define TIP_X 300
static int tip = -1;
_Static_assert(TXT_TIP_1 + TIP_COUNT - 1 == TXT_TIP_15, "the tips are TIP_COUNT texts in a row (tools/strings/en_a.txt)");

static void tip_pick(void)
{
	const uint32_t t = ticks_cycles() ^ ((uint32_t) VSync(-1) * 2654435761u);
	int n = (int) ((t >> 7) % TIP_COUNT);

	if (n == tip) n = (n + 1) % TIP_COUNT;
	tip = n;
}

static void draw_tip(void)
{
	if (tip < 0) return;
	ctext(TIP_X, 32, T(TXT_SECURITY_TIP), 150, 160, 200);
	wrap_text(TIP_X, 54, GPU_XRES - 16 - TIP_X, 5, T(TXT_TIP_1 + tip), UI_SEL_RGB);
}

/* is there a language of the screens to switch to: one of the data card is loaded, besides English */
static int lang_choice(void)
{
	for (int l = 1; l < UI_NLANG; l++)
		if (ui_lang_have(l)) return 1;
	return 0;
}

static void draw_home(void)
{
	const char *const NAME[5] = {T(TXT_GENERATE_A_NEW_SEED), T(TXT_RESTORE_FROM_SEED), T(TXT_ENCRYPTION), T(TXT_EXTRAS), T(TXT_LANGUAGE)};
	const char *DESC[5] = {T(TXT_COLLECT_ENTROPY_THEN_BIP39), T(TXT_TYPE_YOUR_RECOVERY_WORDS_GET),
	                       T(TXT_ENCRYPT_A_TEXT_OR_OPEN_AN), T(TXT_SIGNER_AND_CD_PLAYER_B_CARD), T(TXT_WORD_LISTS_OF_OTHER_LANGUAGES)};
#ifdef WITH_LOADER
	{
		int y = ui_menu(T(TXT_PSX_CRYPTO_MULTITOOL), NAME, sig_msg[0] ? NULL : DESC, HOME_N, hsel, T(TXT_HINT_CHOOSE_SELECT));
		if (sig_msg[0]) ctext(16, y, sig_msg, 255, 120, 120);                 /* why the signer did not start, in place of the description */
	}
	draw_tip();
	if (psxx_lang) { char l[64]; sprintf(l, T(TXT_WORDS_IN_N_NEW_SEEDS_AND), psxx_lang->name); ctext(16, UI_HINT2, l, UI_SEL_RGB); }
#else
	ui_menu(T(TXT_PSX_CRYPTO_MULTITOOL), NAME, DESC, HOME_N, hsel, T(TXT_HINT_CHOOSE_SELECT));
	draw_tip();
#endif
	if (lang_choice()) {                                                   /* only when another language is loaded (the data card): SELECT switches between them */
		const char *const H = T(TXT_HINT_LANGUAGE_NYELV);              /* the same in every language: it has to be found */
		dim(RIGHT - font_width(H), UI_HINT1, H);
	}
}

static void draw_encmenu(void)
{
	static const uint16_t M[] = {TXT_ENCRYPT_A_TEXT, TXT_OPEN_AN_ENCRYPTED_TEXT, TXT_AES_256_GCM_NEEDS_ENTROPY, TXT_TEXTS_SAVED_ON_CARD_2_OR_PASTE};
	ui_menu_ids(TXT_ENCRYPTION, M, 2, 1, esel, TXT_HINT_CHOOSE_SELECT_BACK_2);
	wrap_text(16, 120, GPU_XRES - 32, 2, T(TXT_E2E_NOTE), 255, 190, 80);
}

static void draw_restopt(void)
{
	char line[64];

	const char *const KIND[4] = {T(TXT_BIP39_WORDS), T(TXT_TON_PHRASE), T(TXT_RAW_KEY_HEX), T(TXT_MONERO_WORDS)};

	text(16, UI_TOP, T(TXT_RESTORE_OR_IMPORT));
	sprintf(line, T(TXT_N_KIND_N), ropt_row == 0 ? '>' : ' ', '<', KIND[rest_kind], '>');
	ui_hl(16, 40, ropt_row == 0, line);
	if (rest_kind == 0) sprintf(line, T(TXT_N_WORDS_N), ropt_row == 1 ? '>' : ' ', '<', 12 + 3 * rest_nw, '>');
	else sprintf(line, T(TXT_WORDS_N), rest_kind == 1 ? "24" : rest_kind == 3 ? "25" : "-");
	ui_hl(16, 68, ropt_row == 1 && rest_kind == 0, line);
	if (rest_kind == 0) dim(16, 110, T(TXT_TYPE_THE_WORDS_WITH_THE));
	else if (rest_kind == 1) dim(16, 110, T(TXT_TONKEEPER_OR_TONHUB_PHRASE_THE));
	else if (rest_kind == 3) dim(16, 110, T(TXT_THE_25_WORDS_OF_A_LEGACY));
	else dim(16, 110, T(TXT_A_KEY_OF_64_HEX_DIGITS_SAVED));
	dim(16, UI_HINT2, T(TXT_HINT_ROW_CHANGE_CONTINUE_BACK));
}

static void draw_raw_curve(void)
{
	static const uint16_t M[] = {TXT_ED25519_TON_SOLANA, TXT_SECP256K1_ETHEREUM_BITCOIN, TXT_THE_32_BYTES_ARE_AN_ED25519, TXT_THE_32_BYTES_ARE_A_SECRET_KEY};

	int y = ui_menu_ids(TXT_CURVE_OF_THE_KEY, M, 2, !msg[0], raw_sel, TXT_HINT_CHOOSE_SELECT_BACK_2);
	if (msg[0]) ctext(16, y, msg, 255, 120, 120);
}

static void draw_rest(void)
{
	if (rest_len != kb.len) msg[0] = 0;                  /* the error belongs to the text it was shown for */
	kb.note = msg[0] ? msg : NULL;
	kb.warn = 2;
	kb_draw(&ctx, &kb);
}

static int rest_suggest_xmr(const char *pre, int len, int from, char out[][KB_SUGLEN], int max)
{
	char w[KB_SUG][13];
	int n = xmr_complete(pre, (size_t) len, from, w, max > KB_SUG ? KB_SUG : max);
	for (int i = 0; i < n - from && i < max; i++) strcpy(out[i], w[i]);
	return n;
}

static int rest_suggest(const char *pre, int len, int from, char out[][KB_SUGLEN], int max)
{
	char w[KB_SUG][BIP39_MAX_WORD + 1];
	int n = bip39_complete(pre, (size_t) len, from, w, max > KB_SUG ? KB_SUG : max);
	for (int i = 0; i < n - from && i < max; i++) strcpy(out[i], w[i]);
	return n;
}

static void rest_kb(const char *title)
{
	kb_init(&kb, title, NULL, 0, 0);
	kb_set(&kb, rest_kind == 3 ? 480 : 300, 0);
	kb_set_suggest(&kb, rest_kind == 3 ? rest_suggest_xmr : rest_suggest);
	kb.goal = rest_goal;
	rest_len = -1;
}

/* the typed words -> `mnemonic` in full words (the first 4 letters of a word are enough) and the entropy; 0 or -1 with msg */
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
		if (idx < 0 || o + BIP39_MAX_WORD + 1 >= (int) sizeof mnemonic) {
			sprintf(msg, T(TXT_WORD_N_IS_NOT_IN_THE_LIST), n);
			return -1;
		}
		o += bip39_word((unsigned) idx, mnemonic + o);
		mnemonic[o++] = ' ';
		mnemonic[o] = 0;
	}
	if (o) mnemonic[o - 1] = 0;
	if (n != rest_goal) {
		sprintf(msg, T(TXT_N_WORDS_TYPED_N_CHOSEN), n, rest_goal);
		return -1;
	}
	if (rest_kind == 1) return 0;                                      /* a TON phrase has no BIP39 checksum; ton_entropy_is_basic checks it later */
	r = bip39_mnemonic_to_entropy(mnemonic, ent);
	if (r < 0) { sprintf(msg, T(TXT_CHECKSUM_WRONG_A_WORD_IS)); return -1; }
	return r;
}

/* the Monero key of the 25 words: the keys are derived as for a new wallet (the key stays in hs for the signer) */
static void restore_monero(const uint8_t key[32])
{
	uint8_t spend[32];

	memcpy(spend, key, 32);
	wtype = W_MONERO;
	failed = generate_monero(spend) != 0;
	secure_zero(spend, sizeof spend);
	kb_wipe(&kb);
	page = 0;
	qr_mode = 0;
	if (failed) { failed = 0; restart(); return; }
	state = S_ADDR;
}

/* the typed Monero words -> the key; 0, or -1 with msg */
static int rest_monero_text(void)
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
	restore_monero(key);
	secure_zero(key, sizeof key);
	return 0;
}

/* hs is filled (entropy, passphrase): the address pages of the BIP39 seed */
static void addr_open(const uint8_t seed[64])
{
	hs_valid = 1;
	wtype = hs.entlen >= 32 ? W_BIP39_24 : W_BIP39_12;
	used_pass = hs_pass[0] != 0;
	failed = wallet_derive(&addrs, seed, progress_cb, NULL) != 0;
	kb_wipe(&kb);
	page = 0;
	qr_mode = 0;
	if (failed) { failed = 0; restart(); return; }
	state = S_ADDR;
}

static void restore_derive(void)
{
	uint8_t seed[64];

	show_status(T(TXT_HASHING_SEED), T(TXT_ABOUT_5_SECONDS));
	bip39_seed(mnemonic, kb.text, seed);
	memcpy(hs.seed, seed, 64);
	snprintf(hs_pass, sizeof hs_pass, "%s", kb.text);
	hs.passphrase = hs_pass;
	addr_open(seed);
	secure_zero(seed, sizeof seed);
	secure_zero(mnemonic, sizeof mnemonic);
}

/* the TON phrase is typed (and its password): the check (390 PBKDF2 rounds), then the key (100000 rounds, minutes), then the addresses; the seed stays for saving it */
static void restore_ton(void)
{
	uint8_t e[64], seed[64], pub[32];

	show_status(T(TXT_CHECKING_THE_TON_PHRASE), T(TXT_A_MOMENT));
	ton_entropy(e, mnemonic, kb.text);
	if (!ton_entropy_is_basic(e)) {
		secure_zero(e, sizeof e);
		kb_wipe(&kb);
		sprintf(msg, T(TXT_NOT_A_VALID_TON_PHRASE_OR_IT));
		rest_kb(T(TXT_TON_PHRASE_24_WORDS));
		state = S_REST;
		return;
	}
	kb_wipe(&kb);
	if (ton_private_seed_cb(seed, e, ton_progress, NULL) != 0) {
		secure_zero(e, sizeof e);
		secure_zero(seed, sizeof seed);
		secure_zero(mnemonic, sizeof mnemonic);
		state = S_HOME;
		return;
	}
	memcpy(ton_seed, seed, 32);
	ton_seed_ok = 1;
	ed25519_pubkey_from_seed(pub, seed);
	ton_address(ton_addr[0], sizeof ton_addr[0], TON_V5R1, 0, pub);
	ton_address(ton_addr[1], sizeof ton_addr[1], TON_V5R1, 1, pub);
	ton_address(ton_addr[2], sizeof ton_addr[2], TON_V4R2, 0, pub);
	ton_address(ton_addr[3], sizeof ton_addr[3], TON_V4R2, 1, pub);
	secure_zero(e, sizeof e);
	secure_zero(seed, sizeof seed);
	secure_zero(mnemonic, sizeof mnemonic);
	wtype = W_TON;
	hs_valid = 0;
	page = 0;
	qr_mode = 0;
	state = S_ADDR;
}

/* ---- the start screen: the logo fills with colour from the bottom as the tables of the curves are built ---- */

#define SPLASH_TEXT "p2p_$_x"
#define SPLASH_K 4                                   /* every font pixel is 8 x 4 screen pixels: 560 x 72 */
#define SPLASH_H (SPLASH_K * 18)
#define SPLASH_BAND 24

/* A few milliseconds of work towards the tables of secp256k1, ed25519 and Pallas (in that order), at most two steps per frame; the
 * progress is weighted by the time of the stages (about 55 %, 42 %, 3 %). */
/* the English word lists are decoded behind the start screen (words.c): the overlay region is their work area, so this has to be done before an overlay is loaded */
static int words_step(void)
{
	uint32_t t0 = ticks_cycles();
	int r = words_prepare();

	LOG("[words] the word lists are %s, %u ms\n", r ? "NOT ready" : "decoded", (unsigned) ((ticks_cycles() - t0) / 33869u));
	return 100;
}

static void splash_work(void)
{
	static const int BASE[5] = {0, 50, 90, 93, 100}, WEIGHT[5] = {50, 40, 3, 7, 0};
	int tries = 0;

	while (splash_stage < 4 && tries < 2) {
		int p0 = splash_cur, p;
		p = splash_stage == 0 ? secp256k1_table_step() : splash_stage == 1 ? ed25519_table_step() : splash_stage == 2 ? pallas_table_step() : words_step();
		splash_cur = p;
		if (p >= 100) { splash_stage++; splash_cur = 0; }
		tries++;
		if (p - p0 >= 3 || p >= 100) break;          /* a heavy step or the end of a stage fills the frame */
	}
	splash_p = (BASE[splash_stage] + WEIGHT[splash_stage] * splash_cur / 100) * 256 / 100;
}

static void splash_colour(int y, uint8_t rgb[3], void *user)
{
	static const int DIM[3] = {70, 80, 135}, BRIGHT[3] = {255, 200, 60};
	int f = (y - *(int *) user) * 256 / SPLASH_BAND + 128;       /* a soft edge: half way at the line, bright below it */

	if (f < 0) f = 0;
	if (f > 256) f = 256;
	for (int i = 0; i < 3; i++) rgb[i] = (uint8_t) (DIM[i] + (BRIGHT[i] - DIM[i]) * f / 256);
}

static void draw_splash(void)
{
	int y0 = (ctx.yres - SPLASH_H) / 2 - 6, x0 = (GPU_XRES - 7 * 2 * SPLASH_K * font_cell_w()) / 2;
	int line = y0 + SPLASH_H + SPLASH_BAND / 2 - splash_pd * (SPLASH_H + SPLASH_BAND) / 256;      /* where the bright colour starts */

	font_draw_big(&ctx, 3, x0, y0, SPLASH_TEXT, SPLASH_K, splash_colour, &line);
}

static void update(uint16_t pr)
{
	switch (state) {
	case S_SPLASH:
		if (splash_stage < 4) splash_work();
		splash_pd += (splash_p - splash_pd) * 3 / 8 + (splash_p > splash_pd);       /* eases towards the real progress */
		if (splash_pd > splash_p) splash_pd = splash_p;
		if (splash_stage >= 4 && splash_pd >= splash_p) {
			if (splash_hold < 18) splash_hold++;                                  /* the finished logo stays a moment */
			else if (splash_out < 20) { splash_out++; gpu_set_fade(&ctx, 256 - splash_out * 256 / 20); }
			else { state = S_HOME; fade_in = 20; gpu_set_fade(&ctx, 0); }
		}
		break;
	case S_HOME:
		if ((pr & PAD_SELECT) && lang_choice()) ui_lang_cycle();                     /* the language of the screens: English, the one of the data card (Hungarian is one of them) */
		ui_nav(&hsel, HOME_N, pr);
		if (pr & PAD_CROSS) {
			if (hsel == 0) { src_next = S_TYPE; failed = 0; state = S_SOURCE; }
			else if (hsel == 1) { ropt_row = 0; msg[0] = 0; state = S_RESTOPT; }
#ifdef WITH_LOADER
			else if (hsel == 3) {
				sig_msg[0] = 0;
				if (!release_filled()) snprintf(sig_msg, sizeof sig_msg, T(TXT_THE_RELEASE_RECORD_IS_EMPTY));
				else b_open(B_SIGNER, S_HOME);
			}
			else if (hsel == 4) {
				sig_msg[0] = 0;
				if (!release_filled()) snprintf(sig_msg, sizeof sig_msg, T(TXT_THE_RELEASE_RECORD_IS_EMPTY));
				else {
					int pinned = 0;
					for (int i = 0; i < 32; i++) pinned |= psxx_release_info.data_key[i];
					if (!pinned) snprintf(sig_msg, sizeof sig_msg, T(TXT_THIS_RELEASE_HAS_NO_LANGUAGE));
					else b_open(B_LANG, S_HOME);
				}
			}
#endif
			else { esel = 0; state = S_ENCMENU; }
		}
		break;
	case S_ENCMENU:
		ui_nav(&esel, 2, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_HOME; break; }
		if (pr & PAD_CROSS) {
			if (esel == 0) {
				wtype = W_ENCRYPT;
				enc_hex = 0;
				if (entropy_ready(&pool)) state = S_ENC_KIND;
				else { src_next = S_ENC_KIND; failed = 0; state = S_SOURCE; }
			} else {
				dec_scan();
				msg[0] = 0;
				state = S_DEC_LIST;
			}
		}
		break;
	case S_RESTOPT:
		if ((pr & (PAD_DOWN | PAD_UP)) && rest_kind == 0) ropt_row ^= 1;
		if (rest_kind != 0) ropt_row = 0;
		if (pr & (PAD_LEFT | PAD_RIGHT)) {
			if (ropt_row == 0) rest_kind = (rest_kind + ((pr & PAD_RIGHT) ? 1 : 3)) % 4;
			else rest_nw = (rest_nw + ((pr & PAD_RIGHT) ? 1 : 4)) % 5;
		}
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) state = S_HOME;
		if (pr & PAD_CROSS) {
			msg[0] = 0;
			if (rest_kind == 2) {
				kb_init(&kb, T(TXT_KEY_64_HEX_DIGITS), NULL, 1, 0);
				kb_set(&kb, 64, 1);
				rest_len = -1;
				state = S_RAW_KEY;
				break;
			}
#ifdef WITH_LOADER
			if ((rest_kind == 0 || rest_kind == 3) && psxx_lang) {             /* the words typed in the language that is on */
				uint8_t ent[32];
				int r = psxx_lang->restore(&ctx, &in, rest_kind == 3, rest_kind == 3 ? 25 : 12 + 3 * rest_nw, mnemonic, sizeof mnemonic, ent);
				if (r != -2) {
					if (r == 32 && rest_kind == 3) restore_monero(ent);
					else if (r > 0) { memcpy(hs.entropy, ent, (size_t) r); hs.entlen = r; hs_loc = psxx_lang->id; kb_init(&kb, T(TXT_PASSPHRASE_EMPTY_NONE), NULL, 1, 0); state = S_REST_PASS; }
					secure_zero(ent, sizeof ent);
					break;
				}
			}
#endif
			rest_goal = rest_kind == 1 ? 24 : rest_kind == 3 ? 25 : 12 + 3 * rest_nw;
			rest_kb(rest_kind == 1 ? T(TXT_TON_PHRASE_24_WORDS) : rest_kind == 3 ? T(TXT_MONERO_WORDS_25) : T(TXT_RECOVERY_WORDS));
			state = S_REST;
		}
		break;
	case S_REST: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			secure_zero(mnemonic, sizeof mnemonic);
			msg[0] = 0;
			state = S_HOME;
		} else if (r == KB_DONE) {
			uint8_t ent[32];
			int n;
			if (rest_kind == 3) { if (rest_monero_text()) rest_len = kb.len; break; }
			n = rest_parse(ent);
			if (n < 0) {
				rest_len = kb.len;
			} else if (rest_kind == 1) {
				secure_zero(ent, sizeof ent);
				kb_wipe(&kb);
				kb_init(&kb, T(TXT_TON_PASSWORD_EMPTY_NONE), NULL, 1, 0);
				state = S_REST_PASS;
			} else {
				memcpy(hs.entropy, ent, (size_t) n);
				hs.entlen = n;
				hs_loc = 0;
				secure_zero(ent, sizeof ent);
				kb_wipe(&kb);
				kb_init(&kb, T(TXT_PASSPHRASE_EMPTY_NONE), NULL, 1, 0);
				state = S_REST_PASS;
			}
		}
		break;
	}
	case S_REST_PASS: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			secure_zero(mnemonic, sizeof mnemonic);
			secure_zero(&hs, sizeof hs);
			state = S_HOME;
		} else if (r == KB_DONE) {
			if (rest_kind == 1) restore_ton();
			else restore_derive();
		}
		break;
	}
	case S_RAW_KEY: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_RESTOPT;
		} else if (r == KB_DONE) {
			int ok = kb.len == 64;
			for (int i = 0; ok && i < 32; i++) {
				int hi = hex_val(kb.text[2 * i]), lo = hex_val(kb.text[2 * i + 1]);
				if (hi < 0 || lo < 0) ok = 0; else ks_ent[i] = (uint8_t) (hi << 4 | lo);
			}
			if (!ok) { secure_zero(ks_ent, sizeof ks_ent); sprintf(msg, T(TXT_NEEDS_EXACTLY_64_HEX_DIGITS)); rest_len = kb.len; }
			else { ks_elen = 32; raw_sel = 0; kb_wipe(&kb); msg[0] = 0; state = S_RAW_CURVE; }
		}
		break;
	}
	case S_RAW_CURVE:
		if (pr & (PAD_DOWN | PAD_UP)) raw_sel ^= 1;
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { ks_wipe(); state = S_RESTOPT; break; }
		if (pr & PAD_CROSS) {
			uint8_t k[32], pub[33];
			memcpy(k, ks_ent, 32);
			if (raw_sel == 1 && secp256k1_pubkey_create(pub, k)) { sprintf(msg, T(TXT_NOT_A_VALID_SECP256K1_KEY)); }
			else {
				ks_wipe();
				ks_begin(KS_TYPE_RAW, k, 32, (raw_sel ? KS_CURVE_SECP256K1 : KS_CURVE_ED25519) << KS_FLAG_CURVE_SHIFT, S_HOME);
				msg[0] = 0;
			}
			secure_zero(k, sizeof k);
		}
		break;
	case S_SOURCE:
		ui_wrap(&srcsel, NSOURCES, pr);
		if (pr & PAD_CROSS) {
			if (srcsel == 0) { jsaved = pool; state = S_COLLECT; }
			else if (srcsel == 1) { state = S_COIN; nflips = 0; coin_step = -1; }
			else if (srcsel == 2) { state = S_DICE; nrolls = 0; }
			else if (srcsel == 3) enter_cd();
		}
		if (entropy_ready(&pool) && (pr & PAD_START)) state = src_next;
		if (pr & PAD_TRIANGLE) state = src_next == S_ENC_KIND ? S_ENCMENU : S_HOME;
		hold = (in.ps.buttons & PAD_SELECT) ? hold + 1 : 0;      /* hold SELECT: forget everything collected so far */
		if (hold >= HOLD_FRAMES) restart();
		break;
	case S_COLLECT:
		if (pr & PAD_START) {                                   /* keep what the buttons added */
			secure_zero(&jsaved, sizeof jsaved);
			state = S_SOURCE;
		} else if (pr & PAD_SELECT) {                           /* discard it: the pool is as it was before */
			pool = jsaved;
			secure_zero(&jsaved, sizeof jsaved);
			state = S_SOURCE;
		}
		break;
	case S_CD:
		if (pr & PAD_SELECT) { state = S_SOURCE; break; }
		if (cd_rc != CD_OK) { if (pr & PAD_CROSS) enter_cd(); break; }
		if (cd_pending) break;
		cdview_step();
		if (pr & PAD_CROSS) {
			cd_pending = 1;                                 /* the seek runs after this frame has been shown */
			cd_tpress = ticks_cycles();
			cd_target = cdview_target();
			cdview_pos(&cd_r, &cd_a);
		}
		break;
	case S_COIN: {
		int need = flips_needed(), face = pr & (PAD_TRIANGLE | PAD_CROSS);
		if (pr & PAD_SELECT) {                                  /* cancel: the flips are thrown away */
			secure_zero(flips, sizeof flips);
			nflips = 0;
			coin_step = -1;
			coin_face = 0;
			state = S_SOURCE;
			break;
		}
		if (pr & PAD_START) {                                   /* done: 1 bit per flip into the pool */
			for (int i = 0; i < nflips; i++) entropy_add_coin(&pool, flips[i]);
			coin_units += (uint32_t) nflips * entropy_symbol_credit(2);
			secure_zero(flips, sizeof flips);
			nflips = 0;
			coin_step = -1;
			coin_face = 0;
			state = S_SOURCE;
			break;
		}
		if (pr & PAD_L1) {                                      /* take back the last flip */
			if (nflips) flips[--nflips] = 0;
			coin_step = -1;
			coin_face = 0;
		} else if (coin_face) {                                 /* a button is down: the flip is thrown when it is let go (or at the longest hold); the longer, the higher */
			if ((in.ps.buttons & coin_face) && coin_hold < COIN_HOLD_MAX) coin_hold++;
			else {
				flips[nflips++] = (coin_face == PAD_TRIANGLE);
				coin_start = (coin_face == PAD_TRIANGLE) ? COIN_TAILS_SIDE : COIN_HEADS_SIDE;   /* it ends on the other side */
				coin_height = 12 + coin_hold * 28 / COIN_HOLD_MAX;
				coin_face = 0;
				coin_step = 0;
			}
		} else if (face && face != (PAD_TRIANGLE | PAD_CROSS) && nflips < need) {
			coin_face = face;
			coin_hold = 0;
		}
		if (coin_step >= 0 && coin_step <= COIN_STEPS) coin_step++;
		break;
	}
	case S_DICE: {
		int need = symbols_needed(6);
		if (pr & PAD_SELECT) {                                  /* cancel: the rolls are thrown away */
			secure_zero(rolls, sizeof rolls);
			nrolls = 0;
			state = S_SOURCE;
			break;
		}
		if (pr & PAD_START) {                                   /* done: the rolls into the pool */
			for (int i = 0; i < nrolls; i++) entropy_add_dice(&pool, rolls[i]);
			dice_units += (uint32_t) nrolls * entropy_symbol_credit(6);
			secure_zero(rolls, sizeof rolls);
			nrolls = 0;
			state = S_SOURCE;
			break;
		}
		if (pr & PAD_LEFT)  dsel = dsel == 1 ? 6 : dsel - 1;
		if (pr & PAD_RIGHT) dsel = dsel == 6 ? 1 : dsel + 1;
		if (pr & PAD_L1) { if (nrolls) rolls[--nrolls] = 0; }
		else if ((pr & PAD_CROSS) && nrolls < need) rolls[nrolls++] = (uint8_t) dsel;
		break;
	}
	case S_TYPE:
		ui_nav(&tsel, 3, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_SOURCE; failed = 0; break; }
		if (pr & PAD_CROSS) {
			failed = 0;
			if (tsel == 0) { t2sel = 0; state = S_TYPE2; }
			else { wtype = tsel == 1 ? W_MONERO : W_TON; start_generate(); }
		}
		break;
	case S_TYPE2:
		ui_nav(&t2sel, 3, pr);
		if (pr & (PAD_LEFT | PAD_RIGHT)) {
			if (t2sel == 0) w24 = !w24;
			else if (t2sel == 1) wxmr = !wxmr;
			else use_pass = !use_pass;
		}
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { state = S_TYPE; break; }
		if (pr & PAD_CROSS) {
			wtype = wxmr ? (w24 ? W_BOTH_24 : W_BOTH_12) : (w24 ? W_BIP39_24 : W_BIP39_12);
			if (use_pass) {
				kb_init(&kb, T(TXT_BIP39_PASSPHRASE_EMPTY_NONE), NULL, 1, 0);
				pass_stage = 0;
				pass_err = 0;
				state = S_PASS;
			} else {
				start_generate();
			}
		}
		break;
	case S_CHAINS: {
		int n = group_len(cgroup);
		ui_nav(&csel, n, pr);
		if (pr & (PAD_L1 | PAD_R1)) {
			cgroup = (cgroup + ((pr & PAD_R1) ? 1 : NCHAIN_GROUPS - 1)) % NCHAIN_GROUPS;
			csel = ctop = 0;
			n = group_len(cgroup);
		}
		if (csel < ctop) ctop = csel;
		if (csel >= ctop + CHAIN_ROWS) ctop = csel - CHAIN_ROWS + 1;
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) { state = S_ADDR; qr_mode = 0; }
		else if (pr & PAD_CROSS) {
			const chain_def *c = group_item(cgroup, csel);
			if (c == &custom) { cc = &custom; cfield = 0; custom_sync(); state = S_CUSTOM; }
			else chain_select(c);
		}
		break;
	}
	case S_STYLE:
		if (pr & PAD_DOWN) { for (int s = cstyle + 1; s < 3; s++) if (style_ok(s)) { cstyle = s; break; } }
		if (pr & PAD_UP) { for (int s = cstyle - 1; s >= 0; s--) if (style_ok(s)) { cstyle = s; break; } }
		if (pr & PAD_RIGHT) ccount++;
		if (pr & PAD_LEFT) ccount--;
		if (pr & PAD_R1) ccount += 5;
		if (pr & PAD_L1) ccount -= 5;
		if (ccount < 1) ccount = 1;
		if (ccount > count_max(cc)) ccount = count_max(cc);
		if (pr & PAD_SQUARE) { cstyle = 2; edit_path(&cown, S_STYLE, cc == &custom); break; }
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) { state = cc == &custom ? S_CUSTOM : S_CHAINS; break; }
		if (pr & PAD_CROSS) list_derive();
		break;
	case S_CHAIN:
		if (cqr) { if (pr & (PAD_CIRCLE | PAD_SELECT | PAD_TRIANGLE | PAD_CROSS)) cqr = 0; break; }
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) { msg[0] = 0; state = cc->curve == CV_SR25519 ? S_CHAINS : S_STYLE; break; }
		if ((pr & PAD_RIGHT) && cidx < clist_n - 1) cidx++;
		if ((pr & PAD_LEFT) && cidx > 0) cidx--;
		if ((pr & PAD_CROSS) && clist[cidx][0]) chain_qr();
		if ((pr & PAD_CIRCLE) && cc->curve != CV_ORCHARD) { sview = chain_has_view_keys(cc); sstage = sec_addr = 0; hold = 0; state = S_SECRET; break; }
		if ((pr & PAD_SQUARE) && cc->curve == CV_SR25519) key_edit(KT_JUNCTION, T(TXT_JUNCTIONS_LIKE_POLKADOT_0_1), cstr, 0, (int) sizeof cstr - 1);
		break;
	case S_SECRET:
		if (sstage == 0) {
			hold = (in.ps.buttons & PAD_CROSS) ? hold + 1 : 0;
			if (pr & (PAD_SELECT | PAD_TRIANGLE | PAD_CIRCLE)) { hold = 0; state = sec_addr ? S_ADDR : S_CHAIN; break; }
			if (hold >= HOLD_FRAMES) { hold = 0; secret_derive(); sstage = 1; }
		} else if (sstage == 1) {
			if ((pr & PAD_CROSS) && sres > 0) secret_qr();
			if ((pr & PAD_L1) && sview) { secret_wipe(); sview = 0; hold = 0; break; }                 /* from the view keys to the keys that spend: the warning first */
			if (pr & (PAD_SELECT | PAD_TRIANGLE | PAD_CIRCLE)) { secret_wipe(); state = sec_addr ? S_ADDR : S_CHAIN; }
		} else if (pr & (PAD_SELECT | PAD_TRIANGLE | PAD_CIRCLE | PAD_CROSS)) {
			secret_wipe_qr();
			sstage = 1;
		}
		break;
	case S_PATH:
		if (pr & PAD_SELECT) { state = preturn; break; }
		if (pr & PAD_L2) cexpert = !cexpert;
		if ((pr & PAD_LEFT) && cseg > 0) cseg--;
		if ((pr & PAD_RIGHT) && cseg < epath.n - 1) cseg++;
		if (epath.n && !seg_locked(cseg)) {
			uint32_t *v = &epath.idx[cseg], hard = *v & PATH_HARD, n = *v & ~PATH_HARD;
			int d = ((pr & PAD_UP) ? 1 : 0) - ((pr & PAD_DOWN) ? 1 : 0) + ((pr & PAD_R1) ? 10 : 0) - ((pr & PAD_L1) ? 10 : 0);
			if (d < 0 && n < (uint32_t) -d) n = 0;
			else if (d > 0 && n + (uint32_t) d >= PATH_HARD) n = PATH_HARD - 1;
			else n += (uint32_t) d;
			*v = n | hard;
			if (pr & PAD_TRIANGLE) *v ^= PATH_HARD;
			if (pr & PAD_CIRCLE) {
				for (int i = cseg; i < epath.n - 1; i++) epath.idx[i] = epath.idx[i + 1];
				epath.n--;
				if (cseg >= epath.n && cseg > 0) cseg--;
			}
		}
		if ((pr & PAD_SQUARE) && epath.n < PATH_MAX_DEPTH) { epath.idx[epath.n++] = 0; cseg = epath.n - 1; }
		if (pr & PAD_R2) {
			char t[84];
			path_format(&epath, t, sizeof t);
			key_edit(KT_PATH, T(TXT_DERIVATION_PATH), t, 2, (int) sizeof t - 1);
			break;
		}
		if ((pr & PAD_CROSS) && !path_problem(cc, &epath)) {
			*ptarget = epath;
			if (ptarget == &cown) cstyle = 2;
			state = preturn;
		}
		break;
	case S_PATHTXT: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = ktarget == KT_JUNCTION ? S_CHAIN : ktarget == KT_HRP ? S_CUSTOM : S_PATH;
		} else if (r == KB_DONE) {
			key_done();
		}
		break;
	}
	case S_CUSTOM: {
		const custom_kind *k = &CK[ckind];
		ui_nav(&cfield, 5, pr);
		if (pr & (PAD_LEFT | PAD_RIGHT | PAD_L1 | PAD_R1)) {
			int dir = (pr & (PAD_RIGHT | PAD_R1)) ? 1 : -1, big = (pr & (PAD_L1 | PAD_R1)) ? 16 : 1;
			if (cfield == 0) custom_curve(!ccurve);
			else if (cfield == 1) custom_kind_set(ck_next(ckind, dir));
			else if (cfield == 2 && k->ptype == 1) {
				int v = (int) cparam + dir * big;
				cparam = (uint16_t) (v < 0 ? 0 : v > 65535 ? 65535 : v);
			}
		}
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) { state = S_CHAINS; break; }
		if (pr & PAD_CROSS) {
			custom_sync();
			if (cfield == 2 && k->ptype == 2) key_edit(KT_HRP, T(TXT_BECH32_CASHADDR_PREFIX), custom_hrp, 0, 11);
			else if (cfield == 3) { cc = &custom; edit_path(&custom_path, S_CUSTOM, 1); }
			else if (cfield == 4) chain_select(&custom);
		}
		break;
	}
	case S_ENC_KIND:
		if (pr & (PAD_UP | PAD_DOWN)) enc_hex = !enc_hex;
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) state = S_ENCMENU;
		if (pr & PAD_CROSS) {
			enc_kb(enc_hex ? T(TXT_HEX_TO_ENCRYPT) : T(TXT_TEXT_TO_ENCRYPT));
			state = S_ENC_TEXT;
		}
		break;
	case S_ENC_TEXT: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_ENC_KIND;
		} else if (r == KB_DONE) {
			if (kb.len == 0) {
				enc_kb(T(TXT_NOTHING_TO_ENCRYPT));
			} else if (enc_hex && (kb.len & 1)) {
				kb.title = T(TXT_EVEN_DIGITS_ONLY);                 /* the digits typed so far stay, only the title warns */
			} else {
				if (enc_hex) txt_len = hex_decode(kb.text, txt, (int) sizeof txt);
				else { memcpy(txt, kb.text, (size_t) kb.len); txt_len = kb.len; }
				kb_wipe(&kb);
				pw_enter(PW_FOR_TEXT);
			}
		}
		break;
	}
	case S_ENC_PASS: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			pw_cancel();
		} else if (r == KB_DONE) {
			if (kb.len == 0) {
				pw_kb(T(TXT_PASSWORD_NOT_EMPTY), NULL);
				pass_stage = 0;
			} else if (pass_stage == 0) {
				if (pw_first_entry_weak()) break;
				memcpy(pass, kb.text, sizeof pass);
				pw_kb(T(TXT_REPEAT_THE_PASSWORD), NULL);
				pass_stage = 1;
			} else if (strcmp(pass, kb.text) == 0) {
				do_encrypt();
			} else {
				pw_kb(T(TXT_THEY_DIFFER_ENTER_IT_AGAIN), NULL);
				secure_zero(pass, sizeof pass);
				pass_stage = 0;
			}
		}
		break;
	}
	case S_ENC_OUT:
		if (pr & PAD_CROSS) {
			kb_init(&kb, T(TXT_NAME_OF_THE_SAVED_TEXT_EMPTY), NULL, 0, 1);
			kb_set(&kb, NAME_MAX_BYTES, 0);
			state = S_ENC_NAME;
			break;
		}
		if (pr & PAD_TRIANGLE) restart();
		if (pr & PAD_R2) {
			out_page = (out_page + 1) % 3;
			out_scroll = 0;
			if (out_page == 0) { if (out_ur) show_part(); else set_out_mode(0); }
		}
		if (out_page) {
			if (pr & PAD_DOWN) out_scroll++;                      /* the draw routine limits it */
			if ((pr & PAD_UP) && out_scroll > 0) out_scroll--;
			break;
		}
		if (pr & PAD_SQUARE) set_out_mode(!out_ur);
		if (pr & PAD_L1) { ur_fpp += 3; if (ur_fpp > 45) ur_fpp = 45; }
		if (pr & PAD_R1) { ur_fpp -= 3; if (ur_fpp < 3) ur_fpp = 3; }
		if (out_ur && urp.parts > 1 && ++ur_tick >= ur_fpp) {     /* next part of the animation */
			ur_tick = 0;
			ur_seq = ur_seq % (int) urp.parts + 1;
			show_part();
		}
		break;
	case S_ENC_NAME: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_ENC_OUT;
		} else if (r == KB_DONE) {
			save_text_file(kb.text);
			kb_wipe(&kb);
			state = S_ENC_OUT;
		}
		break;
	}
	case S_DEC_LIST:
		ui_wrap(&dsel_i, dn, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { msg[0] = 0; state = S_ENCMENU; }
		else if (pr & PAD_SQUARE) {
			msg[0] = 0;
			kb_init(&kb, T(TXT_CIPHERTEXT_IN_HEX), NULL, 0, 0);
			kb_set(&kb, 2 * BLOB_BUF, 1);
			state = S_DEC_HEX;
		} else if ((pr & PAD_CROSS) && dn > 0) {
			int r = dec_load();
			if (r) {
				sprintf(msg, T(TXT_CANNOT_READ_THE_FILE_N), card_error(r));
			} else {
				msg[0] = 0;
				pw_kb(T(TXT_PASSWORD), NULL);
				state = S_DEC_PASS;
			}
		}
		break;
	case S_DEC_HEX: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_DEC_LIST;
		} else if (r == KB_DONE) {
			int n = hex_decode(kb.text, enc_blob, BLOB_BUF);
			if (n < BLOB_OVERHEAD) {
				static char again[KB_MAX + 1];
				memcpy(again, kb.text, sizeof again);
				kb_init(&kb, T(TXT_HEX_WHOLE_BYTES_AT_LEAST_58), again, 0, 0);
				kb_set(&kb, 2 * BLOB_BUF, 1);
			} else {
				enc_len = n;
				msg[0] = 0;
				pw_kb(T(TXT_PASSWORD), NULL);
				state = S_DEC_PASS;
			}
		}
		break;
	}
	case S_DEC_PASS: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_DEC_LIST;
		} else if (r == KB_DONE) {
			do_decrypt();
		}
		break;
	}
	case S_KS_STORE: {
		int rows = KS_ROWS, nv = ks_nvaults();

		if (ks_rc == MCF_OK) {
			ui_nav(&ks_sel, rows, pr);
		}
		if (pr & (PAD_TRIANGLE | PAD_SELECT)) { ks_wipe(); state = (enum state) ks_back; break; }
		if (pr & PAD_SQUARE) { ks_scan(); break; }
		if ((pr & PAD_CROSS) && ks_rc == MCF_OK) {
			ks_kok = ks_new_pw = ks_use_store = 0;
			ks_target = ks_sel == 0 ? -2 : ks_sel > nv ? -1 : ks_vault(ks_sel - 1);
			ks_msg[0] = 0;
			if (ks_target == -2) {                                                        /* a single key: its own password, no name of a place */
				if (!ks_room_single()) sprintf(ks_msg, T(TXT_THE_CARD_IS_FULL_DELETE_A_KEY));
				else { memset(ks_slabel, 0, sizeof ks_slabel); ks_ask_label(); }
			} else if (ks_target == -1) {                                                 /* a new vault: its name, then its password */
				if (!ks_room_vault()) sprintf(ks_msg, T(TXT_NO_FREE_BLOCK_FREE_ONE_ON_THE));
				else {
					kb_init(&kb, T(TXT_NAME_OF_THE_NEW_STORE), NULL, 0, 1);
					kb_set(&kb, KS_STORE_LABEL, 0);
					state = S_KS_SLABEL;
				}
			} else if (ks_st.st[ks_target].n >= KS_MAX_KEYS) sprintf(ks_msg, T(TXT_THAT_STORE_IS_FULL_N_KEYS), KS_MAX_KEYS);
			else {                                                                        /* a vault: its password is typed once, to write into it */
				kb_init(&kb, T(TXT_PASSWORD_OF_THE_STORE), NULL, 1, 0);
				kb_set(&kb, PW_MAX, 0);
				state = S_KS_SPW;
			}
		}
		break;
	}
	case S_KS_SLABEL: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_KS_STORE;
		} else if (r == KB_DONE) {
			memset(ks_slabel, 0, sizeof ks_slabel);
			memcpy(ks_slabel, kb.text, (size_t) kb.len < KS_STORE_LABEL ? (size_t) kb.len : KS_STORE_LABEL);
			kb_wipe(&kb);
			pw_enter(PW_FOR_STORE);                                                      /* the password of the vault: typed or made, twice */
		}
		break;
	}
	case S_KS_SPW: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_KS_STORE;
		} else if (r == KB_DONE) {
			if (ks_unlock(&ks_st.st[ks_target].dir)) { ks_use_store = 1; ks_ask_label(); }
			else { kb_init(&kb, T(TXT_WRONG_STORE_PASSWORD_AGAIN), NULL, 1, 0); kb_set(&kb, PW_MAX, 0); }
		}
		break;
	}
	case S_KS_LABEL: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_KS_STORE;
		} else if (r == KB_DONE) {
			memset(ks_label, 0, sizeof ks_label);
			memcpy(ks_label, kb.text, (size_t) kb.len < (size_t) (ks_use_store ? KS_LABEL_STORE : KS_LABEL) ? (size_t) kb.len : (size_t) (ks_use_store ? KS_LABEL_STORE : KS_LABEL));
			kb_wipe(&kb);
			memset(ks_plabel, 0, sizeof ks_plabel);
			if (ks_use_store) do_keysave();
			else {                                                                        /* an own entry: a cover name the list shows without the password, "Key N" if nothing else is typed */
				char dn[24];

				sprintf(dn, T(TXT_KEY_N), ks_singles() + 1);
				kb_init(&kb, T(TXT_OPEN_LABEL_SEEN_WITHOUT_THE_PASSWORD), dn, 0, 1);
				kb_set(&kb, KS_PUBLIC, 0);
				state = S_KS_PLABEL;
			}
		}
		break;
	}
	case S_KS_PLABEL: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			state = S_KS_STORE;
		} else if (r == KB_DONE) {
			memcpy(ks_plabel, kb.text, (size_t) kb.len < KS_PUBLIC ? (size_t) kb.len : KS_PUBLIC);
			kb_wipe(&kb);
			pw_enter(PW_FOR_KEY);
		}
		break;
	}
	case S_KS_PASS: {
		int r = kb_step(pr);

		if (r == KB_CANCEL) {
			pw_cancel();
		} else if (r == KB_DONE) {
			if (kb.len == 0) {
				pw_kb(T(TXT_PASSWORD_NOT_EMPTY), NULL);
				pass_stage = 0;
			} else if (pass_stage == 0) {
				if (pw_first_entry_weak()) break;
				memcpy(pass, kb.text, sizeof pass);
				pw_kb(T(TXT_REPEAT_THE_PASSWORD), NULL);
				pass_stage = 1;
			} else if (strcmp(pass, kb.text) == 0) {
				if (pw_for == PW_FOR_STORE) { ks_make_store_key(); ks_use_store = 1; ks_ask_label(); }
				else do_keysave();
			} else {
				pw_kb(T(TXT_THEY_DIFFER_ENTER_IT_AGAIN), NULL);
				secure_zero(pass, sizeof pass);
				pass_stage = 0;
			}
		}
		break;
	}
	case S_PW_CHOOSE:
		ui_nav(&pw_sel, 3, pr);
		if (pr & (PAD_TRIANGLE | PAD_SELECT | PAD_CIRCLE)) { pw_cancel(); break; }
		if (pr & PAD_CROSS) {
			if (pw_sel == 0) {
				pw_kb(pw_for == PW_FOR_KEY ? T(TXT_PASSWORD_FOR_THIS_KEY) : pw_for == PW_FOR_STORE ? T(TXT_PASSWORD_FOR_THE_STORE) : T(TXT_PASSWORD), NULL);
				pass_stage = 0;
				pw_warned = 0;
				state = pw_for != PW_FOR_TEXT ? S_KS_PASS : S_ENC_PASS;
			} else {
				pw_kind = pw_sel == 1 ? PW_CHARS : PW_WORDS;
				pw_count = 0;
				pw_make();
				hold = 0;
				pw_armed = 0;
				state = S_PW_SHOW;
			}
		}
		break;
	case S_PW_SHOW:
		if (pr & PAD_TRIANGLE) { pw_count++; pw_make(); hold = 0; pw_armed = 0; break; }
		if (pr & (PAD_CIRCLE | PAD_SELECT)) { secure_zero(pw_sug, sizeof pw_sug); state = S_PW_CHOOSE; break; }
		if (!(in.ps.buttons & PAD_CROSS)) pw_armed = 1;                       /* the button that chose this screen must be let go first */
		hold = (pw_armed && (in.ps.buttons & PAD_CROSS)) ? hold + 1 : 0;
		if (hold >= HOLD_FRAMES && pw_sug[0]) {
			hold = 0;
			snprintf(pass, sizeof pass, "%s", pw_sug);
			secure_zero(pw_sug, sizeof pw_sug);
			if (pw_for == PW_FOR_KEY) do_keysave();
			else if (pw_for == PW_FOR_STORE) { ks_make_store_key(); ks_use_store = 1; ks_ask_label(); }
			else do_encrypt();
		}
		break;
	case S_KS_DONE:
		if (pr & (PAD_CROSS | PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) { ks_wipe(); state = (enum state) ks_back; }
		break;
	case S_XPUB:
		if (!xp_have) {
			ui_nav(&xp_sel, XPUB_KINDS, pr);
			if (pr & (PAD_TRIANGLE | PAD_SELECT | PAD_CIRCLE)) { state = S_ADDR; break; }
			if (pr & PAD_CROSS) {
				show_status(T(TXT_DERIVING_THE_ACCOUNT_KEY), T(TXT_ABOUT_2_SECONDS));
				if (xpub_export(xp_key, xp_desc, hs.seed, xp_sel) == 0) { xp_have = 1; xp_page = 0; xp_qr = 0; }
				else snprintf(msg, sizeof msg, T(TXT_THE_KEY_COULD_NOT_BE_DERIVED));
			}
		} else {
			if ((pr & (PAD_LEFT | PAD_RIGHT)) && xp_desc[0]) { xp_page ^= 1; if (xp_qr) { qr_dirty = 1; } }
			if (pr & PAD_CROSS) { xp_qr = !xp_qr; qr_dirty = 1; }
			if (pr & (PAD_CIRCLE | PAD_TRIANGLE | PAD_SELECT)) {
				if (xp_qr) xp_qr = 0; else xp_have = 0;
			}
			if (xp_qr && qr_dirty) {
				const char *t = xp_page ? xp_desc : xp_key;
				qr_ok = qr_encode(&qr, (const uint8_t *) t, strlen(t), QR_ECC_M) > 0;
				if (qr_ok) { qr_scale = qr_view_scale(&qr); qr_view_upload(&qr, qr_scale); }
				qr_dirty = 0;
			}
		}
		break;
#ifdef WITH_LOADER
	case S_SIGNER: {
		int r = su_update(&sui, pr, sframe);
		if (r == SU_LOADED) { if (b_next == B_LANG) run_lang(); else run_signer(); }
		else if (r == SU_CANCEL) {                              /* nothing was loaded (the loader wipes a slot whose loading fails) */
			secure_zero(&psxx_handoff, sizeof psxx_handoff);   /* and no seed waits for the signer */
			state = sig_back;
		}
		break;
	}
#endif
	case S_DEC_OUT:
		if (pr & PAD_SQUARE) { dec_hexview = !dec_hexview; dec_scroll = 0; }
		if (pr & PAD_DOWN) dec_scroll++;                          /* the draw routine limits it */
		if ((pr & PAD_UP) && dec_scroll > 0) dec_scroll--;
		if (pr & (PAD_SELECT | PAD_TRIANGLE)) {
			secure_zero(dec_text, sizeof dec_text);
			secure_zero(dec_hexs, sizeof dec_hexs);
			kb_clip_wipe();
			dec_len = 0;
			state = S_DEC_LIST;
		}
		break;
	case S_PASS: {
		int r = kb_step(pr);
		if (r == KB_CANCEL) {
			kb_wipe(&kb);
			secure_zero(pass, sizeof pass);
			state = S_TYPE;
		} else if (r == KB_DONE) {
			if (pass_stage == 0) {
				memcpy(pass, kb.text, sizeof pass);
				kb_init(&kb, T(TXT_REPEAT_THE_PASSPHRASE), NULL, 1, 0);
				pass_stage = 1;
			} else if (strcmp(pass, kb.text) == 0) {
				start_generate();
			} else {
				kb_init(&kb, T(TXT_THEY_DIFFER_ENTER_IT_AGAIN), NULL, 1, 0);
				secure_zero(pass, sizeof pass);
				pass_stage = 0;
				pass_err = 1;
			}
		}
		break;
	}
	case S_WORDS: {
		uint16_t both = PAD_CIRCLE | PAD_CROSS;
		int last = words_page == words_pages() - 1;
#ifdef WITH_LOADER
		if (psxx_lang && (words_is_monero(words_idx) ? xmr_loc : bip_loc)) break;      /* the module shows these words: words_module(), after this switch */
#endif
		if ((pr & PAD_SQUARE) && words_is_monero(words_idx)) {          /* the Monero seed is gone from RAM once the words are confirmed: this is the time to save it */
			uint8_t spend[32];

			if (xmr_seed_decode(xmr_mnemonic, spend) == 0) ks_begin(KS_TYPE_MONERO, spend, 32, 0, S_WORDS);
			secure_zero(spend, sizeof spend);
			break;
		}
		if ((pr & PAD_SQUARE) && has_ton() && ton_seed_ok) {                 /* the TON key: only the ed25519 seed is saved, not the words */
			ks_begin(KS_TYPE_RAW, ton_seed, 32, KS_CURVE_ED25519 << KS_FLAG_CURVE_SHIFT, S_WORDS);
			break;
		}
		if ((pr & PAD_RIGHT) && !last) { words_page++; hold = 0; }
		if ((pr & PAD_LEFT) && words_page > 0) { words_page--; hold = 0; }
		last = words_page == words_pages() - 1;
		hold = (last && (in.ps.buttons & both) == both) ? hold + 1 : 0;
		if (hold >= HOLD_FRAMES) {
			hold = 0;
			verify_start();
			verify_question();
			state = S_VERIFY;
		}
		break;
	}
	case S_VERIFY:
		if (vfail) {
			if (pr & PAD_CROSS) { vattempt++; vfail = 0; hold = 0; state = S_WORDS; }
			break;
		}
		ui_wrap(&vsel, VOPTS, pr);
		if (pr & PAD_SQUARE) { vattempt++; hold = 0; state = S_WORDS; }
		if (pr & PAD_TRIANGLE) { vfail = 1; vwhy = 2; }
		if (pr & PAD_CROSS) {
			if (vsel != vcorrect) { vfail = 1; vwhy = 1; }
			else if (++vq >= VQ) words_done();
			else verify_question();
		}
		break;
	case S_PID: {
		int r = kb_update(&kb, pr);
		uint8_t pid[8];
		if (r == KB_DONE) {
			if (kb.len == 16 && hex_decode(kb.text, pid, 8) == 8) {
				for (int i = 0; i < 16; i++) xmr_pid_hex[i] = (char) (kb.text[i] >= 'A' && kb.text[i] <= 'F' ? kb.text[i] + 32 : kb.text[i]);
				xmr_pid_hex[16] = 0;
				xmr_int[0] = 0;                                                     /* made again with it */
				state = S_ADDR;
			} else {
				char again[17];
				snprintf(again, sizeof again, "%s", kb.text);
				kb_init(&kb, T(TXT_PAYMENT_ID_EXACTLY_16_HEX), again, 0, 0);
				kb_set(&kb, 16, 1);
			}
		} else if (r == KB_CANCEL) state = S_ADDR;
		break;
	}
	case S_ADDR: {
		int old_page = page;
		if (pr & PAD_RIGHT) page = (page + 1) % page_count();
		if (pr & PAD_LEFT)  page = (page + page_count() - 1) % page_count();
		if ((pr & PAD_TRIANGLE) && hs_valid && !qr_mode) { cgroup = csel = ctop = 0; state = S_CHAINS; break; }
		if ((pr & PAD_L1) && watch_ok() && !qr_mode) { xp_sel = xp_have = 0; msg[0] = 0; state = S_XPUB; break; }
		if (page_is_monero(page) && monero_page() == XMR_SUB_PAGE && !qr_mode) {           /* another subaddress */
			if (pr & PAD_R1) xmr_sub_idx = xmr_sub_idx < XMR_SUB_MAX ? xmr_sub_idx + 1 : 1;
			if (pr & PAD_L1) xmr_sub_idx = xmr_sub_idx > 1 ? xmr_sub_idx - 1 : XMR_SUB_MAX;
			if (pr & PAD_R2) xmr_sub_idx = xmr_sub_idx + 10 <= XMR_SUB_MAX ? xmr_sub_idx + 10 : XMR_SUB_MAX;
			if (pr & PAD_L2) xmr_sub_idx = xmr_sub_idx > 10 ? xmr_sub_idx - 10 : 1;
		}
		if ((pr & PAD_R2) && page_is_monero(page) && monero_page() == XMR_INT_PAGE && !qr_mode) {     /* type the payment ID: 16 hex digits */
			kb_init(&kb, T(TXT_PAYMENT_ID_16_HEX_DIGITS), xmr_pid_hex, 0, 0);
			kb_set(&kb, 16, 1);
			state = S_PID;
			break;
		}
		if ((pr & PAD_SQUARE) && has_ton() && ton_seed_ok && !qr_mode) { ks_begin(KS_TYPE_RAW, ton_seed, 32, KS_CURVE_ED25519 << KS_FLAG_CURVE_SHIFT, S_ADDR); break; }
		if ((pr & PAD_SQUARE) && hs_valid && !qr_mode && hs.entlen >= 16) { ks_begin(KS_TYPE_BIP39, hs.entropy, hs.entlen, (hs_pass[0] ? KS_FLAG_PASSPHRASE : 0) | hs_loc << KS_FLAG_LANG_SHIFT, S_ADDR); break; }
#ifdef WITH_LOADER
		if ((pr & PAD_START) && !qr_mode && !addr_modal_on && (hs_valid || hs.xmr_ok || (has_ton() && ton_seed_ok)) && release_filled()) {     /* sign with this seed: the signer gets it from here */
			psxx_handoff.hs = hs;
			psxx_handoff.hs.passphrase = NULL;
			snprintf(psxx_handoff.pass, sizeof psxx_handoff.pass, "%s", hs_pass);
			if (!hs_valid) psxx_handoff.hs.no_bip = 1;                                   /* only Monero words, or a TON key */
			if (has_ton() && ton_seed_ok) { memcpy(psxx_handoff.hs.raw, ton_seed, 32); psxx_handoff.hs.raw_curve = 1; psxx_handoff.hs.no_bip = 1; }
			psxx_handoff.valid = 1;
			sig_msg[0] = 0;
			b_open(B_SIGNER, S_ADDR);                                        /* in memory already: the signer takes the seed at once */
			break;
		}
#endif
		if ((pr & PAD_CIRCLE) && !qr_mode && addr_secret_ok()) {                                   /* the secret key of the address on the page: the chain pages' warning, then the key */
			cc = chain_find(PCHAIN[page]);
			path_parse(&cbase, PATHS[page]);
			cown = cbase;
			cstyle = cidx = sview = sstage = hold = 0;
			sec_addr = 1;
			state = S_SECRET;
			break;
		}
		if (pr & PAD_CROSS)  { qr_mode = 1; qr_dirty = 1; }
		if (pr & PAD_CIRCLE) qr_mode = 0;
		ensure_sub();
		if (qr_mode && page != old_page) qr_dirty = 1;
		if (qr_mode && qr_dirty) refresh_qr();
		hold = (in.ps.buttons & PAD_SELECT) ? hold + 1 : 0;
		if (hold >= HOLD_FRAMES) { if (addr_modal_on) { hold = 0; state = S_MODAL_END; } else restart(); }
		break;
	}
	}
}

static void draw(void)
{
	switch (state) {
	case S_SPLASH:  draw_splash(); break;
	case S_HOME:    draw_home(); break;
	case S_ENCMENU: draw_encmenu(); break;
	case S_RESTOPT: draw_restopt(); break;
	case S_REST:    draw_rest(); break;
	case S_REST_PASS: kb_draw(&ctx, &kb); break;
	case S_RAW_KEY: draw_rest(); break;
	case S_RAW_CURVE: draw_raw_curve(); break;
	case S_SOURCE:  draw_source(); break;
	case S_COLLECT: draw_collect(); break;
	case S_COIN:    draw_coin(); break;
	case S_DICE:    draw_dice(); break;
	case S_CD:      draw_cd(); break;
	case S_TYPE:    draw_type(); break;
	case S_TYPE2:   draw_type2(); break;
	case S_CHAINS:  draw_chains(); break;
	case S_STYLE:   draw_style(); break;
	case S_CHAIN:   draw_chain(); break;
	case S_SECRET:  draw_secret(); break;
	case S_PATH:    draw_path(); break;
	case S_PATHTXT: kb_draw(&ctx, &kb); break;
	case S_CUSTOM:  draw_custom(); break;
	case S_ENC_KIND: draw_enc_kind(); break;
	case S_ENC_TEXT: enc_note(); kb_draw(&ctx, &kb); break;
	case S_DEC_HEX:  sprintf(note, T(TXT_N_BYTES), kb.len / 2); kb.note = note; kb_draw(&ctx, &kb); break;
	case S_PASS:
	case S_ENC_NAME:
	case S_DEC_PASS: kb_draw(&ctx, &kb); break;
	case S_ENC_PASS: if (pass_stage == 0) pw_note(); else kb.note = NULL; kb_draw(&ctx, &kb); break;
	case S_PW_CHOOSE: draw_pw_choose(); break;
	case S_PW_SHOW: draw_pw_show(); break;
	case S_ENC_OUT:  draw_enc_out(); break;
	case S_DEC_LIST: draw_dec_list(); break;
	case S_DEC_OUT:  draw_dec_out(); break;
	case S_KS_STORE: draw_ks_store(); break;
	case S_KS_LABEL: case S_KS_PLABEL: case S_KS_SLABEL: case S_KS_SPW: kb_draw(&ctx, &kb); break;
	case S_KS_PASS: if (pass_stage == 0) pw_note(); else kb.note = NULL; kb_draw(&ctx, &kb); break;
	case S_KS_DONE:  draw_ks_done(); break;
#ifdef WITH_LOADER
	case S_SIGNER:   su_draw(&sui); break;
#endif
	case S_WORDS:   draw_words(); break;
	case S_VERIFY:  draw_verify(); break;
	case S_ADDR:    draw_addr(); break;
	case S_PID:     kb_draw(&ctx, &kb); break;
	case S_XPUB:    draw_xpub(); break;
	}
}

/* Holding up / down repeats in the lists and the scrolling screens (the keyboards repeat by themselves). The other
 * buttons never repeat: X and the dice / coin buttons are entropy events. */
static uint16_t repeat_updown(uint16_t pr)
{
	static uint16_t btn;
	static int cnt, last_state = -1;
	int lists = state == S_HOME || state == S_ENCMENU || state == S_CHAINS || state == S_PATH || state == S_TYPE || state == S_TYPE2 || state == S_STYLE || state == S_CUSTOM || state == S_SOURCE || state == S_TYPE || state == S_ENC_KIND || state == S_DEC_LIST || state == S_DEC_OUT || state == S_KS_STORE || state == S_PW_CHOOSE ||
	            state == S_ENC_OUT;

	if ((int) state != last_state) { last_state = (int) state; btn = 0; }
	if (btn && (!lists || !(in.ps.buttons & btn))) btn = 0;
	if (lists && (pr & (PAD_UP | PAD_DOWN))) { btn = (pr & PAD_UP) ? PAD_UP : PAD_DOWN; cnt = 0; return pr; }
	if (btn && ++cnt >= 22 && (cnt - 22) % 3 == 0) pr |= btn;
	return pr;
}

#ifndef PSXX_QUIET
/* Boot measurements on the TTY: what the unpacking stub measured (tools/packexe.py with PSXX_STUB_PROF=1), and the speed of our own polled reads of
 * the memory card in slot 2, from which the time the BIOS needs to load the packed program from the boot card can be estimated. */
static void boot_report(void)
{
	volatile uint32_t *r = (volatile uint32_t *) 0x801FC000u;
	uint8_t f[MC_FRAME];
	uint32_t t0, frames = 0, ms;

	if (r[0] == 0x42555453u) {
		uint32_t cyc = r[1] * 8;
		LOG("[boot] the stub unpacked %u bytes from a stream of %u bytes in %u ms (%u kB/s of output)\n", (unsigned) r[2], (unsigned) r[3],
		       (unsigned) (cyc / 33869u), (unsigned) ((uint64_t) r[2] * 33869u / (cyc ? cyc : 1)));
		LOG("[boot] so the BIOS has read about %u frames of 128 bytes from the boot card before that\n", (unsigned) (r[3] / 128));
		r[0] = 0;
	} else LOG("[boot] no measurement of the stub (the card was not packed with PSXX_STUB_PROF=1)\n");
	t0 = ticks_cycles();
	for (int block = 1; block <= 3; block++) {
		for (int frame = MCF_FIRST_DATA; frame < 64; frame++) {
			if (mcf_read(1, block, frame, f)) { block = 99; break; }
			frames++;
			(void) ticks_cycles();
		}
	}
	ms = (ticks_cycles() - t0) / 33869u;
	if (frames) LOG("[boot] our polled read of the card in slot 2: %u frames (%u bytes) in %u ms, %u frames/s, %u kB/s\n", (unsigned) frames, (unsigned) (frames * 128),
	                   (unsigned) ms, (unsigned) (ms ? frames * 1000 / ms : 0), (unsigned) (ms ? frames * 128 / ms : 0));
	else LOG("[boot] the card in slot 2 could not be read\n");
}
#endif

#ifndef PSXX_QUIET
/* The background pool on the TTY: one [bg] line for every poll that added events (the timestamp, the buttons, the
 * credit it earned in 1/256 bit), and a line at every change of screen. */
static void bg_log(void)
{
	static uint32_t ev, cr;
	static int last_state = -1;

	if (bgpool.events != ev) {
		LOG("[bg] ev %u +%u, t=%u, buttons %04x, credit +%u/256, total %u bits\n", (unsigned) bgpool.events, (unsigned) (bgpool.events - ev), (unsigned) in.last_sample,
		       (unsigned) in.ps.buttons, (unsigned) (bgpool.credit - cr), (unsigned) entropy_bits(&bgpool));
		ev = bgpool.events;
		cr = bgpool.credit;
	}
	if ((int) state != last_state) {
		last_state = (int) state;
		LOG("[bg] screen %d: %u events, %u bits credited by the buttons\n", (int) state, (unsigned) bgpool.events, (unsigned) entropy_bits(&bgpool));
	}
}
#endif

/* One turn of the main loop: the pad is polled, and on every vertical blank the screen is updated and drawn. A function of its own (not inlined) so that update() and draw(), which are
 * big, have one call site, for the main loop and for ks_save_modal alike. */
static int last_frame = -1, prev_state = -1;

#ifdef WITH_LOADER
/* The words in the language that is on: the module shows them in a loop of its own and asks the check; it returns when they are confirmed (0) or the Monero key is to be saved (1). It runs
 * here, at the end of update(), so that the next page of words (the Monero ones after the BIP39 ones) is entered in the same frame: no frame of the English words is drawn in between. */
static void words_module(void)
{
	while (state == S_WORDS && psxx_lang && (words_is_monero(words_idx) ? xmr_loc : bip_loc)) {
		int xm = words_is_monero(words_idx), r = psxx_lang->show(&ctx, &in, xm, xm ? T(TXT_WRITE_THEM_DOWN) : used_pass ? T(TXT_KEEP_PASSPHRASE) : T(TXT_NO_PASSPHRASE));

		if (r == 0) { words_done(); continue; }
		if (r == 1) {
			uint8_t spend[32];

			if (xmr_seed_decode(xmr_mnemonic, spend) == 0) ks_begin(KS_TYPE_MONERO, spend, 32, 0, S_WORDS);
			secure_zero(spend, sizeof spend);
		}
		break;
	}
}
#endif

static __attribute__((noinline)) void frame_step(void)
{
	int f;

	/* the pad is polled continuously, but only while collecting entropy do the events go into the pool */
	input_poll(&in, state == S_COLLECT ? &pool : NULL);                 /* in.extra: the background pool gets every event, the collecting screen's too */
#ifndef PSXX_QUIET
	bg_log();
#endif

	/* redraw once per vertical blank */
	f = VSync(-1);
	if (f != last_frame) {
		last_frame = f;
#ifdef WITH_LOADER
		sframe++;
#endif
		update(repeat_updown(input_take_pressed(&in)));
#ifdef WITH_LOADER
		words_module();
#endif
		if (state == S_HOME && prev_state != S_HOME) tip_pick();
		prev_state = state;
		if (fade_in > 0) { fade_in--; gpu_set_fade(&ctx, 256 - fade_in * 256 / 20); }     /* the home screen comes up from black */
		draw();
		gpu_present(&ctx);
		if (state == S_CD && cd_pending) do_seek();     /* "Seeking..." is on screen while the drive works */
	}
}

/* The key save for the signer overlay, which has none of its own screens: the same ones as here (the store, a new store with its name and password, the password of an old one, the key of
 * the store or a password of its own, the labels, the chooser of a random password), run until the user is done; the key, its entry flags and a first guess for its label come from the
 * caller. The screen is started again here (the overlay has its own state of it) and has to be started again by the caller. */
static void modal_enter(void)
{
	int t0 = VSync(-1);

	gpu_init(&ctx, 20, 20, 60);
	while (in.ps.buttons && VSync(-1) - t0 < 120) input_poll(&in, NULL);                    /* the button that asked for the screens is let go of first */
}

int ks_save_modal(int type, const uint8_t *ent, int elen, int flags, const char *label)
{
	enum state keep = state;
	int go;

	modal_enter();
	ks_dry = elen > 32;                                                    /* the choices only: the long key (Cardano) is finished by the signer (ks_pass, ks_st ... are read there) */
	ks_dry_go = 0;
	ks_begin(type, ent, ks_dry ? 32 : elen, flags, S_MODAL_END);
	snprintf(ks_label, KS_LABEL + 1, "%s", label);
	while (state != S_MODAL_END) frame_step();
	state = keep;
	go = ks_dry_go;
	ks_dry = 0;
	return go;
}

/* The address pages for the signer overlay, which has none of its own: the coins, the styles and paths, the secret and watch-only keys of every chain - the same screens, for the seed that
 * the signer holds (the BIP39 seed, else the Monero key). They run until SELECT is held; this copy of the seed is wiped, and the signer starts its screen again. */
void addr_modal(const hd_secret *s, const char *pass)
{
	enum state keep = state;

	modal_enter();
	hs = *s;
	snprintf(hs_pass, sizeof hs_pass, "%s", pass);
	hs.passphrase = hs_pass;
	if (!hs.no_bip) addr_open(hs.seed);
	else restore_monero(hs.xmr_seed);
	if (state == S_ADDR) {
		addr_modal_on = 1;
		while (state != S_MODAL_END) frame_step();
		addr_modal_on = 0;
	}
	restart();
	state = keep;
}

int main(void)
{
	ui_reg_a();                                    /* the texts of the screens (English, Hungarian) */
	gpu_init(&ctx, 20, 20, 60);
	font_init(1);                                    /* the bitmap font for all text */
	coin_init();
	dice_init();
	ticks_init();
#ifndef PSXX_QUIET
	boot_report();
#endif
	input_init(&in);
	entropy_init(&bgpool, PSXX_EMULATED ? ENTROPY_EMULATED : 0);
	in.extra = &bgpool;
#ifdef WITH_LOADER
	su_init(&sui, &ctx, &in, GetVideoMode() == MODE_PAL ? 50 : 60, T(TXT_B_CARD), SIGNER_PKG, PKG_KIND_OVERLAY, psxx_release_info.key, psxx_release_info.base_id, SIGNER_GROUP);
	sui.group2 = LANG_GROUP;                                                 /* the language module comes with the signer */
	cw_refresh(&sui.cw, 0);
#endif
	restart();
	state = S_SPLASH;                                /* the tables of the curves are built behind the start screen (restart() skips it) */

	for (;;) frame_step();
	return 0;
}
