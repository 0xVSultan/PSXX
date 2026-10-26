/* The word check of the wallet app (hal/psx/wallet_app.c, verify_question): host copy of the choice logic, run over every
 * word of both lists and over random mnemonics, all positions and attempts. The correct choice must always be present
 * and must be the word on the paper. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/bip39.h"
#include "coin/xmr_seed.h"

#define VOPTS 5

static int is_xmr_g;

static int word_index(const char *w, int len, int is_xmr) { return is_xmr ? xmr_word_find(w, (size_t) len) : bip39_find(w, (size_t) len); }
static void word_text(int idx, int is_xmr, char out[13])
{
	if (is_xmr) xmr_word((unsigned) idx, out);
	else bip39_word((unsigned) idx, out);
}

/* same as verify_question() for one word: returns the index of the correct choice, or -1 if it is missing */
static int question(const char *w, int is_xmr, int pos, int vq, int attempt, char vopt[VOPTS][13])
{
	int total = is_xmr ? 1626 : 2048, idx, vcorrect = -1;
	int rot = (pos * 7 + vq * 3 + attempt) % VOPTS;
	idx = word_index(w, (int) strlen(w), is_xmr);
	if (idx < 0) idx = 0;
	int start = idx - 2;
	if (start < 0) start = 0;
	if (start > total - VOPTS) start = total - VOPTS;
	for (int j = 0; j < VOPTS; j++) {
		int cand = start + (j + rot) % VOPTS;
		word_text(cand, is_xmr, vopt[j]);
		if (cand == idx) vcorrect = j;
	}
	return vcorrect;
}

int main(void)
{
	int bad = 0, n = 0;
	(void) is_xmr_g;
	for (int x = 0; x < 2; x++) {
		int total = x ? 1626 : 2048;
		for (int i = 0; i < total; i++) {
			char w[13], v[VOPTS][13];
			word_text(i, x, w);
			if (word_index(w, (int) strlen(w), x) != i) { printf("find mismatch %s #%d: %d\n", w, i, word_index(w, (int) strlen(w), x)); bad++; continue; }
			for (int pos = 0; pos < 25; pos++)
				for (int vq = 0; vq < 4; vq++)
					for (int att = 0; att < 5; att++) {
						int c = question(w, x, pos, vq, att, v);
						n++;
						if (c < 0 || strcmp(v[c], w) != 0) { printf("wrong choice %s #%d pos %d vq %d att %d -> %d\n", w, i, pos, vq, att, c); bad++; }
					}
		}
	}
	/* real mnemonics, as the app builds them */
	srand(1);
	for (int t = 0; t < 300; t++) {
		uint8_t e[32];
		char m[400], xm[400];
		for (int i = 0; i < 32; i++) e[i] = (uint8_t) rand();
		if (bip39_entropy_to_mnemonic(e, (t & 1) ? 32 : 16, m, sizeof m) < 0) { printf("encode failed\n"); return 1; }
		if (xmr_seed_encode(e, xm, sizeof xm) < 0) { printf("xmr encode failed\n"); return 1; }
		for (int x = 0; x < 2; x++) {
			const char *p = x ? xm : m;
			for (int pos = 0; *p; pos++) {
				const char *q = p;
				char w[16], v[VOPTS][13];
				int l = 0;
				while (*q && *q != ' ') w[l++] = *q++;
				w[l] = 0;
				int c = question(w, x, pos, pos & 3, t & 3, v);
				n++;
				if (c < 0 || strcmp(v[c], w) != 0) { printf("mnemonic word %s (%s) wrong\n", w, x ? "xmr" : "bip39"); bad++; }
				p = *q ? q + 1 : q;
			}
		}
	}
	/* completion: every prefix of every word; the matches are exactly the words starting with it, in list order, in windows too */
	{
		static char all[2048][BIP39_MAX_WORD + 1];
		int cn = 0;
		for (int i = 0; i < 2048; i++) bip39_word((unsigned) i, all[i]);
		for (int i = 0; i < 2048; i++)
			for (int l = 1; l <= (int) strlen(all[i]); l++) {
				char out[6][BIP39_MAX_WORD + 1];
				int want = 0, tot = bip39_complete(all[i], (size_t) l, 0, out, 6);
				for (int j = 0; j < 2048; j++) want += !strncmp(all[j], all[i], (size_t) l);
				cn++;
				if (tot != want) { printf("complete %.*s: %d, want %d\n", l, all[i], tot, want); bad++; continue; }
				for (int from = 0; from < tot; from += 5) {
					int k = 0;
					bip39_complete(all[i], (size_t) l, from, out, 6);
					for (int j = 0; j < 2048 && k < from + 6 && k < tot; j++) {
						if (strncmp(all[j], all[i], (size_t) l)) continue;
						if (k >= from && strcmp(out[k - from], all[j])) { printf("complete %.*s window %d: %s != %s\n", l, all[i], from, out[k - from], all[j]); bad++; }
						k++;
					}
				}
			}
		if (bip39_complete("zzz", 3, 0, NULL, 0) != 0 || bip39_complete("", 0, 0, NULL, 0) != 0) { printf("complete: empty cases\n"); bad++; }
		printf("completion: %d prefixes\n", cn);
	}
	printf("word check: %d questions, %d errors\n", n, bad);
	return bad != 0;
}
