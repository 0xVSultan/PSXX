#include "cdlog.h"
#include <string.h>
#include "mcfile.h"

#define PORT 1                       /* slot 2 */
#define BLOCK_FRAMES 64
#define FIRST_DATA 4                 /* frame (within the block) of the first record frame */
#define REC_SIZE 32
#define TICKS_PER_S 4233600u         /* 33868800 / 8 */
#define TAG "PSXXCD"

_Static_assert(sizeof(cdlog_rec) == REC_SIZE, "record layout");
_Static_assert(CDLOG_MAX == (BLOCK_FRAMES - FIRST_DATA) * (MC_FRAME / REC_SIZE), "records per block");

static int     block, count, err;    /* the file's block, records written, sticky error */
static uint8_t hdr[MC_FRAME];        /* session header (frame 2), kept for the record count updates */
static uint8_t fbuf[MC_FRAME];       /* the record frame being filled */
static char    name[MCF_NAME];

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24); }

static int map(int mcf)
{
	switch (mcf) {
	case MCF_OK: return CDLOG_OK;
	case MCF_NO_CARD: return CDLOG_NO_CARD;
	case MCF_BAD_CARD: return CDLOG_BAD_CARD;
	case MCF_FULL: return CDLOG_FULL;
	default: return CDLOG_IO;
	}
}

static void make_session(uint8_t f[MC_FRAME], const cd_disc *d, uint32_t build_flags, uint32_t cap, unsigned suffix)
{
	memset(f, 0, MC_FRAME);
	memcpy(f, "PSXXCDL1", 8);
	put32(f + 8, 1);                         /* format version */
	put32(f + 12, 0);                        /* records, updated after every write */
	put32(f + 16, build_flags);
	put32(f + 20, d->leadout);
	put32(f + 24, cap);
	f[28] = d->first; f[29] = d->last; f[30] = d->ntoc; f[31] = d->mode;
	memcpy(f + 32, d->fw, 4);
	memcpy(f + 36, d->id, 8);
	put32(f + 44, TICKS_PER_S);
	put32(f + 48, REC_SIZE);
	put32(f + 52, FIRST_DATA);
	put32(f + 56, CDLOG_MAX);
	put32(f + 60, suffix);
}

int cdlog_open(const cd_disc *d, uint32_t build_flags, uint32_t capacity_sectors)
{
	uint8_t f[MC_FRAME];
	mcf_entry e[1];
	int r, nfiles, next;

	count = 0;
	err = CDLOG_OK;
	name[0] = 0;

	r = mcf_scan(PORT, TAG, e, 0, &nfiles, &next, &block);
	if (r) return err = map(r);
	if (!block) return err = CDLOG_FULL;
	mcf_name(name, TAG, next);

	make_session(hdr, d, build_flags, capacity_sectors, (unsigned) next);
	r = mcf_begin(PORT, block, "PSXX CD seek log", MCF_ICON_DISC);
	if (r) return err = map(r);
	r = mcf_write(PORT, block, 2, hdr);
	if (r) return err = map(r);
	memset(f, 0, MC_FRAME);
	for (int t = 0; t < d->ntoc && t < CD_MAX_TRACKS; t++) { f[2 * t] = d->toc[t][0]; f[2 * t + 1] = d->toc[t][1]; }
	r = mcf_write(PORT, block, 3, f);
	if (r) return err = map(r);
	memset(fbuf, 0, sizeof fbuf);
	r = mcf_commit(PORT, block, TAG, next);                     /* the directory entry last */
	return err = map(r);
}

int cdlog_add(const cdlog_rec *rec)
{
	int r, slot;

	if (err) return err;
	if (count >= CDLOG_MAX) return CDLOG_LOG_FULL;
	slot = count % (MC_FRAME / REC_SIZE);
	if (slot == 0) memset(fbuf, 0, sizeof fbuf);
	memcpy(fbuf + slot * REC_SIZE, rec, REC_SIZE);
	r = mcf_write(PORT, block, FIRST_DATA + count / (MC_FRAME / REC_SIZE), fbuf);
	if (r) return err = map(r);
	count++;
	put32(hdr + 12, (uint32_t) count);
	r = mcf_write(PORT, block, 2, hdr);
	if (r) return err = map(r);
	return CDLOG_OK;
}

int cdlog_count(void) { return count; }
const char *cdlog_name(void) { return name; }
