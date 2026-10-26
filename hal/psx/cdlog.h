#pragma once
#include <stdint.h>
#include "cdrom.h"

/* Analysis log of the CD seek test: one save file ("PSXXCDnn") in a free block of the memory card in slot 2.
 *
 * File layout (one block = 64 frames of 128 bytes):
 *   frame 0     Shift-JIS title, icon header (standard save file header)
 *   frame 1     icon
 *   frame 2     session header (see cdlog.c): disc, drive, TOC summary, record count
 *   frame 3     track start times (minute, second) of the first 40 tracks
 *   frames 4..63  records of 32 bytes, 4 per frame (up to CDLOG_MAX)
 * All values little endian. Times are in ticks of 8 CPU cycles (4233600 per second).
 * This is a test tool: it writes timing data only, never keys, seeds or entropy pool state. */

#define CDLOG_MAX 240

typedef struct {
	uint16_t seq;        /* 0, 1, 2 ... within the session */
	uint8_t  flags;      /* CDS_* of the seek + CDL_* */
	uint8_t  stat;       /* drive status byte after the seek */
	uint32_t target;     /* absolute sector asked for */
	uint32_t from;       /* absolute sector where the head was before (0 = unknown) */
	uint32_t landed;     /* absolute sector GetlocP reported afterwards (0xFFFFFFFF = unknown) */
	uint32_t seek;       /* ticks: SeekP first interrupt -> completion */
	uint32_t ack;        /* ticks: SeekP command -> first interrupt */
	uint32_t t_press;    /* ticks (8 cycle units, 32 bit) when the seek button press was handled */
	uint16_t r, a;       /* crosshair radius (1/16 pixel) and angle (65536 = turn) on the disc picture */
} cdlog_rec;

enum { CDL_FROM_UNKNOWN = 0x10 };   /* flag: the head position before this seek was not known */

enum { CDLOG_OK = 0, CDLOG_NO_CARD = -1, CDLOG_BAD_CARD = -2, CDLOG_FULL = -3, CDLOG_IO = -4, CDLOG_LOG_FULL = -5 };

/* Create the save file. `build_flags`: bit 0 = emulator build. Returns CDLOG_OK or an error (nothing is logged then). */
int cdlog_open(const cd_disc *d, uint32_t build_flags, uint32_t capacity_sectors);
/* Append a record and write it to the card. Returns CDLOG_OK or an error (further records are dropped). */
int cdlog_add(const cdlog_rec *r);
int cdlog_count(void);
const char *cdlog_name(void);
