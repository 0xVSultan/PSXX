#include "cdrom.h"
#include <string.h>
#include <hwregs_c.h>
#include "timer.h"

#define IRQ_CD (1 << 2)
#define ST_BUSY 0x80                /* CD_STAT: command busy */
#define ST_RSLRRDY 0x20             /* CD_STAT: response FIFO not empty */
#define CYC_MS 33869u               /* CPU cycles per millisecond */

typedef struct {
	uint8_t  type;                  /* interrupt number 1..5 */
	uint8_t  n;
	uint8_t  r[16];
	uint32_t t;                     /* ticks_cycles() when the interrupt flag was seen */
} cd_int;

static uint32_t t_cmd;              /* ticks_cycles() just before the last command byte went out */
static uint8_t  last_stat, last_err;

static uint8_t bcd(unsigned v) { return (uint8_t) (((v / 10) << 4) | (v % 10)); }
static unsigned unbcd(uint8_t v) { return (unsigned) ((v >> 4) * 10 + (v & 15)); }

static void drain(void) { while (CD_STAT & ST_RSLRRDY) (void) CD_CMD; }

/* Index 1: 0x1803 reads the interrupt flags, writing 0x1F acknowledges them. */
static void ack_all(void)
{
	CD_STAT = 1;
	CD_IRQ = 0x1F;
	IRQ_STAT = (uint16_t) ~IRQ_CD;
}

static void send(uint8_t c, const uint8_t *p, int n)
{
	uint32_t t0 = ticks_cycles();
	while ((CD_STAT & ST_BUSY) && (uint32_t) (ticks_cycles() - t0) < 500 * CYC_MS) {}
	CD_STAT = 0;                           /* index 0: 0x1801 = command, 0x1802 = parameter FIFO */
	for (int i = 0; i < n; i++) CD_DATA = p[i];
	t_cmd = ticks_cycles();
	CD_CMD = c;
	CD_STAT = 1;
}

/* Wait for the next interrupt, read its response, acknowledge it. Returns the interrupt number or 0 on a timeout. */
static int get_int(cd_int *o, uint32_t timeout_ms)
{
	uint32_t t0 = ticks_cycles(), lim = timeout_ms * CYC_MS;

	CD_STAT = 1;
	for (;;) {
		uint8_t f = CD_IRQ & 7;
		if (f) {
			o->t = ticks_cycles();
			o->type = f;
			break;
		}
		if ((uint32_t) (ticks_cycles() - t0) > lim) return 0;
	}
	o->n = 0;
	while ((CD_STAT & ST_RSLRRDY) && o->n < sizeof o->r) o->r[o->n++] = CD_CMD;
	drain();
	ack_all();
	return o->type;
}

/* Send a command and collect its first interrupt `a` (and, if `b` is not NULL, the second one). */
static int command(uint8_t c, const uint8_t *p, int n, cd_int *a, cd_int *b, uint32_t t1_ms, uint32_t t2_ms)
{
	int t;

	send(c, p, n);
	t = get_int(a, t1_ms);
	if (t == 0) return CD_TIMEOUT;
	if (t == 5) {
		last_stat = a->n > 0 ? a->r[0] : 0;
		last_err = a->n > 1 ? a->r[1] : 0;
		return CD_ERROR;
	}
	if (b) {
		t = get_int(b, t2_ms);
		if (t == 0) return CD_TIMEOUT;
		if (t == 5) {
			last_stat = b->n > 0 ? b->r[0] : 0;
			last_err = b->n > 1 ? b->r[1] : 0;
			return CD_ERROR;
		}
	}
	return CD_OK;
}

static int open_inner(cd_disc *d)
{
	cd_int a, b;
	uint8_t p[3];
	int r;

	ack_all();
	drain();
	CD_DATA = 0x1F;                         /* index 1: interrupt enable */

#define STEP(id, expr) do { d->fail_cmd = (int8_t) (id); r = (expr); if (r) { d->fail_stat = last_stat; d->fail_err = last_err; return r; } } while (0)

	STEP(0x01, command(0x01, NULL, 0, &a, NULL, 1000, 0));              /* GetStat: the first answer may carry the old lid event */
	STEP(0x01, command(0x01, NULL, 0, &a, NULL, 1000, 0));
	if (a.r[0] & 0x10) { last_stat = a.r[0]; d->fail_stat = a.r[0]; return CD_NO_DISC; }   /* shell open */
	STEP(0x0A, command(0x0A, NULL, 0, &a, &b, 1000, 20000));            /* Init: spin up, known state */
	p[0] = 0x80;
	STEP(0x0E, command(0x0E, p, 1, &a, NULL, 1000, 0));                 /* Setmode: double speed, nothing else */
	d->mode = 0x80;

	r = command(0x13, NULL, 0, &a, NULL, 5000, 0);                      /* GetTN */
	if (r == CD_ERROR) { d->fail_cmd = 0x13; d->fail_stat = last_stat; d->fail_err = last_err; return CD_NO_DISC; }
	if (r) { d->fail_cmd = 0x13; return r; }
	d->first = (uint8_t) unbcd(a.r[1]);
	d->last = (uint8_t) unbcd(a.r[2]);

	p[0] = 0;
	STEP(0x14, command(0x14, p, 1, &a, NULL, 5000, 0));                 /* GetTD 0: lead-out */
	d->leadout = (unbcd(a.r[1]) * 60 + unbcd(a.r[2])) * 75;
	for (unsigned t = d->first; t <= d->last && d->ntoc < CD_MAX_TRACKS; t++) {
		p[0] = bcd(t);
		if (command(0x14, p, 1, &a, NULL, 2000, 0) != CD_OK) break;
		d->toc[d->ntoc][0] = (uint8_t) unbcd(a.r[1]);
		d->toc[d->ntoc][1] = (uint8_t) unbcd(a.r[2]);
		d->ntoc++;
	}

	p[0] = 0x20;                                                        /* Test 20h: drive firmware date and version */
	if (command(0x19, p, 1, &a, NULL, 1000, 0) == CD_OK && a.n >= 4) memcpy(d->fw, a.r, 4);
	if (command(0x1A, NULL, 0, &a, &b, 2000, 5000) == CD_OK && b.n >= 8) memcpy(d->id, b.r, 8);   /* GetID */
	d->fail_cmd = 0;
#undef STEP
	return CD_OK;
}

int cd_open(cd_disc *d)
{
	uint16_t saved = IRQ_MASK;
	int r;

	memset(d, 0, sizeof *d);
	IRQ_MASK = saved & (uint16_t) ~IRQ_CD;
	r = open_inner(d);
	ack_all();
	IRQ_MASK = saved;
	return r;
}

int cd_seek(uint32_t sector, cd_seek_result *res)
{
	uint16_t saved = IRQ_MASK;
	cd_int a, b;
	uint8_t p[3];
	int rc = CD_OK;
	uint32_t tc;

	memset(res, 0, sizeof *res);
	res->landed = 0xFFFFFFFFu;
	IRQ_MASK = saved & (uint16_t) ~IRQ_CD;
	ack_all();
	drain();

	p[0] = bcd(sector / 4500);
	p[1] = bcd((sector / 75) % 60);
	p[2] = bcd(sector % 75);
	rc = command(0x02, p, 3, &a, NULL, 1000, 0);                        /* Setloc */
	if (rc == CD_OK) {
		send(0x16, NULL, 0);                                            /* SeekP: works on data and audio tracks alike */
		tc = t_cmd;
		if (get_int(&a, 1000) == 0) rc = CD_TIMEOUT;
		else if (a.type == 5) { rc = CD_ERROR; res->stat = a.r[0]; res->err = a.n > 1 ? a.r[1] : 0; }
		else {
			res->ack = (a.t - tc) >> 3;
			int t = get_int(&b, 4000);
			if (t == 0) rc = CD_TIMEOUT;
			else {
				res->stat = b.n > 0 ? b.r[0] : 0;
				if (t == 5) { rc = CD_ERROR; res->err = b.n > 1 ? b.r[1] : 0; }
				else res->seek = (b.t - a.t) >> 3;
			}
		}
	}
	if (rc != CD_OK) res->flags |= rc == CD_TIMEOUT ? CDS_TIMEOUT : CDS_FAIL;

	if (rc == CD_OK) {                                                  /* where did the head really land? */
		if (command(0x11, NULL, 0, &a, NULL, 1000, 0) == CD_OK && a.n >= 8)
			res->landed = (unbcd(a.r[5]) * 60 + unbcd(a.r[6])) * 75 + unbcd(a.r[7]);
		else
			res->flags |= CDS_NOLOC;
	}
	ack_all();
	IRQ_MASK = saved;
	return rc;
}

/* ---- CD-DA playback ---- */
static uint16_t audio_begin(void)
{
	uint16_t saved = IRQ_MASK;

	IRQ_MASK = saved & (uint16_t) ~IRQ_CD;
	ack_all();
	drain();
	return saved;
}

static void audio_end(uint16_t saved)
{
	ack_all();
	IRQ_MASK = saved;
}

void cd_audio_init(void)
{
	uint16_t saved = audio_begin();

	CD_STAT = 2;                       /* index 2: left CD -> left SPU (1802), left CD -> right SPU (1803) */
	CD_DATA = 0x80;
	CD_IRQ = 0x00;
	CD_STAT = 3;                       /* index 3: right CD -> right SPU (1801), right CD -> left SPU (1802), apply (1803 bit 5) */
	CD_CMD = 0x80;
	CD_DATA = 0x00;
	CD_IRQ = 0x20;
	CD_STAT = 1;
	SPU_MASTER_VOL_L = 0x3FFF;
	SPU_MASTER_VOL_R = 0x3FFF;
	SPU_CD_VOL_L = 0x7FFF;
	SPU_CD_VOL_R = 0x7FFF;
	SPU_CTRL = (uint16_t) (SPU_CTRL | 0xC001);   /* SPU on, not muted, CD audio input on */
	audio_end(saved);
}

static int setloc(uint32_t sector)
{
	cd_int a;
	uint8_t p[3];

	p[0] = bcd(sector / 4500);
	p[1] = bcd((sector / 75) % 60);
	p[2] = bcd(sector % 75);
	return command(0x02, p, 3, &a, NULL, 1000, 0);
}

static int play_inner(const uint8_t *track, int n)
{
	cd_int a;
	uint8_t m = 0x01;                  /* CD-DA on, single speed, no auto pause, no report */
	int rc = command(0x0E, &m, 1, &a, NULL, 1000, 0);

	if (rc != CD_OK) return rc;
	return command(0x03, track, n, &a, NULL, 2000, 0);
}

int cd_audio_play(int track)
{
	uint16_t saved = audio_begin();
	uint8_t p = bcd((unsigned) (track < 1 ? 1 : track));
	int rc = play_inner(&p, 1);

	audio_end(saved);
	return rc;
}

int cd_audio_play_from(uint32_t sector)
{
	uint16_t saved = audio_begin();
	int rc = setloc(sector);

	if (rc == CD_OK) rc = play_inner(NULL, 0);
	audio_end(saved);
	return rc;
}

static int where_inner(cd_audio_pos *pos)
{
	cd_int a;
	int rc;

	memset(pos, 0, sizeof *pos);
	pos->abs = 0xFFFFFFFFu;
	rc = command(0x01, NULL, 0, &a, NULL, 1000, 0);                      /* GetStat */
	if (rc != CD_OK) return rc;
	pos->stat = a.r[0];
	pos->playing = (a.r[0] & 0x80) ? 1 : 0;
	rc = command(0x11, NULL, 0, &a, NULL, 1000, 0);                      /* GetlocP */
	if (rc != CD_OK) return rc;
	if (a.n >= 8) {
		pos->track = (uint8_t) unbcd(a.r[0]);
		pos->rel_min = (uint8_t) unbcd(a.r[2]);
		pos->rel_sec = (uint8_t) unbcd(a.r[3]);
		pos->abs = (unbcd(a.r[5]) * 60 + unbcd(a.r[6])) * 75 + unbcd(a.r[7]);
	}
	return CD_OK;
}

int cd_audio_where(cd_audio_pos *pos)
{
	uint16_t saved = audio_begin();
	int rc = where_inner(pos);

	audio_end(saved);
	return rc;
}

int cd_audio_pause(cd_audio_pos *pos)
{
	uint16_t saved = audio_begin();
	cd_int a, b;
	int rc = command(0x09, NULL, 0, &a, &b, 1000, 5000);

	if (rc == CD_OK && pos) rc = where_inner(pos);
	audio_end(saved);
	return rc;
}

int cd_audio_stop(void)
{
	uint16_t saved = audio_begin();
	cd_int a, b;
	int rc = command(0x08, NULL, 0, &a, &b, 1000, 8000);

	audio_end(saved);
	return rc;
}
