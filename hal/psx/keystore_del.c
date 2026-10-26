/* The changes of a key store that the main card does not make (the signer overlay only): entries of two frames, replacing an entry, deleting one or several. The main card adds
 * entries of one frame (keystore.c). See hal/psx/keystore.h. */
#include <string.h>
#include "keystore.h"
#include "mcard.h"

static uint8_t xor127(const uint8_t *f) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= f[i]; return x; }

/* A vault is one block, so its directory entry can be freed without following a chain. The entry is not trusted to have a good checksum: a directory write that a power cut tore is a store
 * whose frames are complete and whose entry is not; it is freed all the same. */
static int free_store(int port, int block)
{
	uint8_t f[MC_FRAME];
	int r = mc_read(port, block, f);

	if (r) return r == MC_NO_CARD ? MCF_NO_CARD : MCF_IO;
	if (f[0] != 0x51 || f[8] != 0xFF || f[9] != 0xFF) return MCF_NOT_FOUND;
	f[0] = 0xA1;
	f[127] = xor127(f);
	r = mc_write(port, block, f);
	return r ? (r == MC_NO_CARD ? MCF_NO_CARD : MCF_IO) : MCF_OK;
}

int ksd_remove_store(int port, ksd_state *s, int store)
{
	ks_dir d;
	uint32_t crc;
	int r, which;

	if (store < 0 || store >= s->nstores || s->st[store].single) return KSD_ERR_ARG;                 /* (the single keys go together: ksd_remove_singles) */
	r = ksd_read_dir(port, s->st[store].block, &d, &which, &crc);
	if (r) return r;
	if (crc != s->st[store].dir_crc) return KSD_ERR_CHANGED;
	r = free_store(port, s->st[store].block);
	if (r) return r;
	for (int i = store; i + 1 < s->nstores; i++) s->st[i] = s->st[i + 1];
	s->nstores--;
	s->free_count++;
	return KSD_OK;
}

int ksd_create(int port, ksd_state *s, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id_hint, uint8_t work[KS_DATA], int *store)
{
	if (!label || (pw && !key)) return KSD_ERR_ARG;
	return ksd_make_block(port, s, 0, label, pw, key, ksd_free_id(s, id_hint), NULL, 0, work, store);
}

/* `entry` (or NULL) goes into the next free slot (a pair of slots for an entry of two frames), `remove` (or -1: the first slot of an entry) becomes free; one new directory frame */
static int change2(int port, ksd_state *s, int store, const uint8_t *entry, int remove, const uint8_t key[32], uint8_t work[KS_DATA])
{
	ksd_store *st;
	ks_dir d, nd;
	uint32_t crc;
	int slot = -1, r, which, nf = entry ? ks_frames_of_entry(entry) : 1;

	if (store < 0 || store >= s->nstores) return KSD_ERR_ARG;
	st = &s->st[store];
	r = ksd_read_dir(port, st->block, &d, &which, &crc);
	if (r) return r;
	if (crc != st->dir_crc) return KSD_ERR_CHANGED;                     /* not the card the scan saw: nothing is written */
	if (!ks_dir_pairs_ok(&d)) return KSD_ERR_IMAGE;
	r = ksd_read(port, st, work);
	if (r) return r;
	if ((d.flags & KS_DIR_PW) && (!key || !ks_dir_mac_ok(&d, key))) return KSD_ERR_PASSWORD;
	if (remove >= 0 && (!ks_slot_live(&d, remove) || ((remove & 1) && ks_slot_pair(&d, remove)))) return KSD_ERR_ARG;     /* (the second slot of a pair is not an entry) */
	nd = d;
	if (entry) {
		slot = nf == 2 ? ks_next_pair(&d) : ks_next_slot(&d);
		if (slot < 0) return KSD_ERR_FULL;
		for (int i = 0; i < nf; i++) {
			r = ksd_put_frame(port, st->block, KS_DIR_FRAMES + slot + i, entry + i * KS_FRAME);   /* free slots: no live frame is touched */
			if (r) return r;
			memcpy(work + (KS_DIR_FRAMES + slot + i) * KS_FRAME, entry + i * KS_FRAME, KS_FRAME);
			ks_slot_set(&nd, slot + i, 1);
		}
		if (nf == 2) ks_pair_set(&nd, slot, 1);
		nd.last = slot;
	}
	if (remove >= 0) {
		if (ks_slot_pair(&d, remove)) { ks_slot_set(&nd, remove + 1, 0); ks_pair_set(&nd, remove, 0); }
		ks_slot_set(&nd, remove, 0);
	}
	nd.seq = d.seq + 1;
	ks_chain(nd.chain, work + KS_DIR_FRAMES * KS_FRAME, nd.live);
	if (nd.flags & KS_DIR_PW) ks_dir_seal(&nd, key);
	ks_dir_encode(work, &nd);
	r = ksd_put_frame(port, st->block, 1 - which, work);                /* over the older directory: the last write */
	if (r) return r;
	if (ksd_read_dir(port, st->block, &d, &which, &crc) || d.seq != nd.seq) return KSD_ERR_VERIFY;
	ksd_fill_store(st, st->block, &d, which, crc);
	return KSD_OK;
}

int ksd_add2(int port, ksd_state *s, int store, const uint8_t *entry, int replace_slot, const uint8_t key[32], uint8_t work[KS_DATA])
{
	int r = entry ? change2(port, s, store, entry, replace_slot, key, work) : KSD_ERR_ARG;

	if (r == KSD_OK && s->st[store].single) ksd_single_title(port, s);
	return r;
}

int ksd_del2(int port, ksd_state *s, int store, int slot, const uint8_t key[32], uint8_t work[KS_DATA])
{
	int r = slot >= 0 ? change2(port, s, store, NULL, slot, key, work) : KSD_ERR_ARG;

	if (r == KSD_OK && s->st[store].single) ksd_single_title(port, s);
	return r;
}

int ksd_del_marked(int port, ksd_state *s, uint8_t (*marks)[KS_SLOTS], int key_store, const uint8_t key[32], uint8_t work[KS_DATA], int *deleted, int *need_store)
{
	for (int st = s->nstores - 1; st >= 0; st--) {
		int m = 0, ns = 0, r = KSD_OK, slots[KS_SLOTS];

		for (int k = 0; k < s->st[st].n && k < KS_SLOTS; k++) if (marks[st][k]) { m++; slots[ns++] = ks_live_slot(&s->st[st].dir, k); }
		if (!m) continue;
		if (m >= s->st[st].n && !s->st[st].single) {
			r = ksd_remove_store(port, s, st);
			if (r == KSD_OK) *deleted += m;
		} else {
			if ((s->st[st].dir.flags & KS_DIR_PW) && (key_store != st || !key)) { *need_store = st; return KSD_ERR_PASSWORD; }
			for (int i = 0; i < ns && r == KSD_OK; i++) {
				r = ksd_del2(port, s, st, slots[i], key, work);
				if (r == KSD_OK) (*deleted)++;
			}
		}
		if (r != KSD_OK) return r;
		memset(marks[st], 0, KS_SLOTS);
	}
	if (s->single_head) {                                                    /* the file of the single keys goes when no key is left in any of its blocks (an empty block of it stays for the next key) */
		int n = 0;

		for (int i = 0; i < s->nstores; i++) if (s->st[i].single) n += s->st[i].n;
		if (!n) return ksd_remove_singles(port, s);
	}
	return KSD_OK;
}

int ksd_remove_singles(int port, ksd_state *s)
{
	ks_dir d;
	uint32_t crc;
	int r, which, w = 0;

	if (!s->single_head) return KSD_OK;
	for (int i = 0; i < s->nstores; i++) {
		if (!s->st[i].single) continue;
		r = ksd_read_dir(port, s->st[i].block, &d, &which, &crc);
		if (r) return r;
		if (crc != s->st[i].dir_crc) return KSD_ERR_CHANGED;
	}
	r = mcf_invalidate(port, s->single_head);                           /* the first block first: that write removes the file */
	if (r) return r;
	for (int i = 0; i < s->nstores; i++) {
		if (s->st[i].single) s->free_count++;
		else s->st[w++] = s->st[i];
	}
	s->nstores = w;
	s->single_head = s->single_last = 0;
	return KSD_OK;
}
