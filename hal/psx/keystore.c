#include "keystore.h"
#include <string.h>
#include "hash/crc32.h"
#include "mcard.h"
#include <stdio.h>

static int fail(int mc) { return mc == MC_NO_CARD ? MCF_NO_CARD : MCF_IO; }

static uint8_t xor127(const uint8_t *f) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= f[i]; return x; }

/* A torn directory entry (a write that a power cut tore: the first half of the frame new, the checksum at the end old) is repaired when the card is scanned. */
static int repair_entry(int port, int block)
{
	uint8_t f[MC_FRAME];
	int r = mc_read(port, block, f);

	if (r) return fail(r);
	if (xor127(f) == f[127]) return MCF_OK;
	f[127] = xor127(f);
	r = mc_write(port, block, f);
	return r ? fail(r) : MCF_OK;
}

/* the two directory frames of a block: the current directory, its index, and a CRC over both as they are */
int ksd_read_dir(int port, int block, ks_dir *d, int *which, uint32_t *crc)
{
	uint8_t f[2][KS_FRAME], both[2 * KS_FRAME];
	int r;

	for (int i = 0; i < 2; i++) {
		r = mcf_read(port, block, MCF_FIRST_DATA + i, f[i]);
		if (r) return r;
		memcpy(both + i * KS_FRAME, f[i], KS_FRAME);
	}
	if (crc) *crc = crc32(both, sizeof both);
	r = ks_dir_pick(d, f[0], f[1]);
	if (which) *which = r;
	return r < 0 ? KSD_ERR_IMAGE : MCF_OK;
}

void ksd_fill_store(ksd_store *o, int block, const ks_dir *d, int which, uint32_t crc)
{
	o->block = block;
	o->id = d->id;
	o->seq = d->seq;
	o->n = ks_live_count(d);
	o->which = which;
	o->next_slot = ks_next_slot(d);
	o->dir_crc = crc;
	o->dir = *d;
}

int ksd_add_store(ksd_state *s, int block, const ks_dir *d, int which, uint32_t crc, int single)
{
	ksd_store o;
	int at = s->nstores;

	ksd_fill_store(&o, block, d, which, crc);
	o.single = single;
	while (at > 0 && s->st[at - 1].block > block) { s->st[at] = s->st[at - 1]; at--; }
	s->st[at] = o;
	s->nstores++;
	return at;
}

int ksd_scan(int port, ksd_state *s, int clean)
{
	mcf_entry ents[15];
	int nfiles, next, fb, nk, r;

	memset(s, 0, sizeof *s);
	for (int pass = 0; pass < 2; pass++) {                              /* the vaults, then the single keys */
		r = mcf_scan_raw(port, pass ? MCF_SKEY_TAG : MCF_KEY_TAG, ents, 15, &nfiles, &next, &fb, &s->free_count, &nk);
		if (r) return r;
		for (int i = 0; i < nfiles && i < 15; i++) {
			int b = ents[i].block, left = 15, link = 0xFFFF;

			if (pass) { if (s->single_head) continue; s->single_head = b; }          /* one file of single keys */
			do {
				ks_dir d;
				uint32_t crc;
				int which;

				if (pass) {
					uint8_t f[MC_FRAME];

					if (mc_read(port, b, f)) return MCF_IO;
					link = f[8] | f[9] << 8;                                             /* the next block of the file (its number less one) */
					s->single_last = b;
				}
				r = ksd_read_dir(port, b, &d, &which, &crc);
				if (r == KSD_ERR_IMAGE) s->corrupt++;                                /* the name is right and no directory is: left alone */
				else if (r) return r;
				else if (s->nstores < KSD_MAX_STORES) {
					if (clean && repair_entry(port, b)) return MCF_IO;
					ksd_add_store(s, b, &d, which, crc, pass);
				}
				b = link + 1;
			} while (pass && link != 0xFFFF && b >= 1 && b <= 15 && --left);
		}
	}
	return MCF_OK;                                                      /* the blocks come in block order */
}

int ksd_read(int port, const ksd_store *st, uint8_t img[KS_DATA])
{
	ks_dir d;
	uint8_t h[16];

	for (int fr = 0; fr < KS_FRAMES; fr++) {
		int r = mcf_read(port, st->block, MCF_FIRST_DATA + fr, img + fr * KS_FRAME);

		if (r) return r;
	}
	if (ks_dir_pick(&d, img, img + KS_FRAME) < 0) return KSD_ERR_IMAGE;
	if (d.seq != st->seq || d.id != st->id) return KSD_ERR_CHANGED;
	ks_chain(h, img + KS_DIR_FRAMES * KS_FRAME, d.live);
	return memcmp(h, d.chain, 16) ? KSD_ERR_IMAGE : MCF_OK;
}

/* one frame of the block written and read back */
int ksd_put_frame(int port, int block, int frame, const uint8_t *data)
{
	uint8_t f[MC_FRAME];
	int r = mcf_write(port, block, MCF_FIRST_DATA + frame, data);

	if (r) return r;
	r = mcf_read(port, block, MCF_FIRST_DATA + frame, f);
	if (r) return r;
	return memcmp(f, data, MC_FRAME) ? KSD_ERR_VERIFY : MCF_OK;
}

static int id_taken(const ksd_state *s, uint16_t id) { for (int i = 0; i < s->nstores; i++) if (s->st[i].id == id) return 1; return 0; }

uint16_t ksd_free_id(const ksd_state *s, uint16_t hint)
{
	while (!hint || id_taken(s, hint)) hint++;
	return hint;
}

/* An entry of ONE frame goes into the next free slot, one new directory frame. (Entries of two frames, replacing and deleting: keystore_del.c, in the signer overlay.) */
int ksd_add(int port, ksd_state *s, int store, const uint8_t entry[KS_FRAME], const uint8_t key[32], uint8_t work[KS_DATA])
{
	ksd_store *st;
	ks_dir d, nd;
	uint32_t crc;
	int slot, r, which;

	if (store < 0 || store >= s->nstores || !entry) return KSD_ERR_ARG;
	st = &s->st[store];
	r = ksd_read_dir(port, st->block, &d, &which, &crc);
	if (r) return r;
	if (crc != st->dir_crc) return KSD_ERR_CHANGED;                     /* not the card the scan saw: nothing is written */
	r = ksd_read(port, st, work);
	if (r) return r;
	if ((d.flags & KS_DIR_PW) && (!key || !ks_dir_mac_ok(&d, key))) return KSD_ERR_PASSWORD;
	nd = d;
	slot = ks_next_slot(&d);
	if (slot < 0) return KSD_ERR_FULL;
	r = ksd_put_frame(port, st->block, KS_DIR_FRAMES + slot, entry);   /* a free slot: no live frame is touched */
	if (r) return r;
	memcpy(work + (KS_DIR_FRAMES + slot) * KS_FRAME, entry, KS_FRAME);
	ks_slot_set(&nd, slot, 1);
	nd.last = slot;
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

/* ---- the single keys: one file, a block for every 60 keys, linked like the blocks of a long save (the BIOS card manager shows one entry that grows) ---- */

/* one directory entry of the card rewritten: its state, the size of the file in blocks (size < 0: as it is), the link (next < 0: as it is) */
static int patch_entry(int port, int block, int state, int size, int next)
{
	uint8_t f[MC_FRAME];
	int r = mc_read(port, block, f);

	if (r) return fail(r);
	f[0] = (uint8_t) state;
	if (size >= 0) { f[4] = 0; f[5] = (uint8_t) (size * 0x20); f[6] = (uint8_t) (size * 0x20 >> 8); f[7] = 0; }
	if (next >= 0) { f[8] = (uint8_t) next; f[9] = (uint8_t) (next >> 8); }
	f[127] = xor127(f);
	r = mc_write(port, block, f);
	return r ? fail(r) : MCF_OK;
}

int ksd_link_block(int port, const ksd_state *s, int block)
{
	uint8_t f[MC_FRAME];
	int n = 1, r;

	for (int i = 0; i < s->nstores; i++) n += s->st[i].single;           /* the blocks of the file, with this one */
	memset(f, 0, sizeof f);
	f[0] = 0x53;                                                        /* the last block of a file, not yet reached from the first */
	f[8] = f[9] = 0xFF;
	f[127] = xor127(f);
	r = mc_write(port, block, f);
	if (r) return fail(r);
	if (s->single_last == s->single_head) return patch_entry(port, s->single_head, 0x51, n, block - 1);
	r = patch_entry(port, s->single_last, 0x52, -1, block - 1);          /* the link: from here the block is part of the file */
	return r ? r : patch_entry(port, s->single_head, 0x51, n, -1);       /* the size, for the BIOS (the chain is what is read) */
}

int ksd_single_title(int port, const ksd_state *s)
{
	uint8_t f[MC_FRAME];
	int n = 0, r;

	if (!s->single_head) return MCF_OK;
	for (int i = 0; i < s->nstores; i++) if (s->st[i].single) n += s->st[i].n;
	r = mcf_read(port, s->single_head, 0, f);
	if (r) return r;
	memset(f + 4, 0, 60);
	snprintf((char *) f + 4, 60, "PSXX key store S %02d", n);
	return mcf_write(port, s->single_head, 0, f);
}

/* A new block of key store, with its first entry in slot 0 (nf frames; the main card never makes one without; tests and ksd_create: entry NULL): a vault (a name, a password; the entry sealed
 * for the id, slot 0, seq 1) or a block of the single keys. The block is written whole before it can
 * be seen; the last write is the directory entry of the file, or the link from the last block of the single keys. Nothing of a block that was used before stays. */
int ksd_make_block(int port, ksd_state *s, int single, const char *label, const ks_dir *pw, const uint8_t key[32], uint16_t id,
                      const uint8_t *entry, int nf, uint8_t work[KS_DATA], int *store)
{
	mcf_entry e[1];
	ks_dir d;
	uint32_t crc;
	uint8_t z[MC_FRAME];
	int nfiles, next, fb, fc, nk, r, which, cont = single && s->single_head;

	r = mcf_scan_raw(port, single ? MCF_SKEY_TAG : MCF_KEY_TAG, e, 0, &nfiles, &next, &fb, &fc, &nk);
	if (r) return r;
	if (s->nstores >= KSD_MAX_STORES) return KSD_ERR_LIMIT;
	for (int i = 0, nv = 0; !single && i < s->nstores; i++) if (!s->st[i].single && ++nv >= KSD_MAX_VAULTS) return KSD_ERR_LIMIT;
	if (fc < 1 || !fb) return KSD_ERR_FULL;
	memset(&d, 0, sizeof d);
	d.id = id;
	d.seq = 1;
	d.last = KS_SLOTS - 1;                                              /* the first entry goes to slot 0 */
	memset(work, 0xFF, KS_DATA);                                        /* every frame is written */
	if (entry) {
		d.last = 0;
		for (int i = 0; i < nf; i++) ks_slot_set(&d, i, 1);
		if (nf == 2) d.two[0] = 1;                                      /* the entry of two frames: the pair of slots 0 and 1 */
		memcpy(work + KS_DIR_FRAMES * KS_FRAME, entry, (size_t) nf * KS_FRAME);
		ks_chain(d.chain, work + KS_DIR_FRAMES * KS_FRAME, d.live);
	}
	for (int i = 0; label && i < KS_STORE_LABEL && label[i]; i++) d.label[i] = label[i];
	if (pw) {
		d.flags = KS_DIR_PW;
		d.iter = pw->iter;
		memcpy(d.salt, pw->salt, 16);
		memcpy(d.check, pw->check, 16);
		ks_dir_seal(&d, key);
	}
	ks_dir_encode(work, &d);
	memset(z, 0, sizeof z);
	if (cont) { r = mcf_write(port, fb, 0, z); if (!r) r = mcf_write(port, fb, 1, z); }       /* a later block of the single keys has no header: its first two frames are cleared */
	else r = mcf_begin(port, fb, single ? "PSXX key store S" : "PSXX key store M", MCF_ICON_LOCK);   /* not visible yet */
	for (int fr = 0; !r && fr < KS_FRAMES; fr++) r = ksd_put_frame(port, fb, fr, work + fr * KS_FRAME);
	if (!r) r = cont ? ksd_link_block(port, s, fb) : mcf_commit(port, fb, single ? MCF_SKEY_TAG : MCF_KEY_TAG, next);
	if (r) return r;
	r = ksd_read_dir(port, fb, &d, &which, &crc);
	if (r) return r;
	*store = ksd_add_store(s, fb, &d, which, crc, single);
	s->free_count--;
	if (single) {
		if (!s->single_head) s->single_head = fb;
		s->single_last = fb;
		ksd_single_title(port, s);                                      /* (only a title: not worth an error) */
	}
	return KSD_OK;
}

int ksd_new_single(int port, ksd_state *s, const uint8_t *entry, int nf, uint16_t id_hint, uint8_t work[KS_DATA], int *store)
{
	return ksd_make_block(port, s, 1, NULL, NULL, NULL, ksd_free_id(s, id_hint), entry, nf, work, store);
}
