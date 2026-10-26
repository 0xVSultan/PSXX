#pragma once
#include <stdint.h>

/* Polled CD-ROM controller access (no SDK CD library, no interrupts), for the CD seek timing test.
 *
 * Only the CD interrupt is masked in the CPU while a call runs; the controller's own interrupt flags are polled, so the
 * kernel's handler (if any) never sees these responses. All times are in "ticks" of 8 CPU cycles (236.2 ns, 4233.6
 * ticks per millisecond). Sectors are absolute (minute * 4500 + second * 75 + frame); the first program sector is 150. */

#define CD_TICKS_PER_MS 4234

enum { CD_OK = 0, CD_NO_DISC = -1, CD_TIMEOUT = -2, CD_ERROR = -3 };

#define CD_MAX_TRACKS 40

typedef struct {
	uint8_t  first, last;                 /* first / last track number */
	uint8_t  ntoc;                        /* entries stored in toc */
	uint8_t  mode;                        /* Setmode value used (0x80 = double speed) */
	uint8_t  fw[4];                       /* drive firmware: year, month, day, version (BCD), 0 if unknown */
	uint8_t  id[8];                       /* GetID answer: stat, flags, disc type, atip, "SCEx" region string; 0 if it failed */
	uint8_t  toc[CD_MAX_TRACKS][2];       /* start of each track: minute, second (binary) */
	uint32_t leadout;                     /* absolute sector where the lead-out starts = end of the written area */
	int8_t   fail_cmd;                    /* command that failed when cd_open() returned an error, else 0 */
	uint8_t  fail_stat, fail_err;
} cd_disc;

typedef struct {
	uint32_t ack;       /* command write to first interrupt (INT3) */
	uint32_t seek;      /* first interrupt to completion (INT2): the seek itself */
	uint32_t landed;    /* absolute sector reported by GetlocP afterwards, 0xFFFFFFFF if unknown */
	uint8_t  stat;      /* status byte of the completion */
	uint8_t  err;       /* error code byte when the seek failed */
	uint8_t  flags;     /* CDS_* */
} cd_seek_result;

enum { CDS_FAIL = 1, CDS_TIMEOUT = 4, CDS_NOLOC = 8 };

/* Reset the drive state, spin up, read the TOC. Takes up to ~10 s. Returns CD_OK or a negative CD_* code. */
int cd_open(cd_disc *d);
/* Seek to an absolute sector (Setloc + SeekP) and measure it. Blocks until the seek is done (up to ~1.5 s).
 * Returns CD_OK, or a CD_* code when the seek failed (the result is filled in as far as possible). */
int cd_seek(uint32_t sector, cd_seek_result *r);

/* ---- CD-DA playback (hal/psx/hidetest.c, the disguise player) ----
 * The drive plays and the SPU mixes the sound: while it plays the CPU and the RAM have nothing to do with it. The head is one, though: every seek of the
 * timing source (cd_seek) ends the music, so the caller pauses first and starts it again from the position that cd_audio_pause() gave back.
 * cd_open() must have run (it resets the drive, which also stops the music, so it is not called while a disc plays). */
typedef struct {
	uint8_t  playing;       /* 1 while the drive reports "playing" */
	uint8_t  track;         /* track number (1..), 0 if unknown */
	uint8_t  rel_min, rel_sec;   /* time in the track */
	uint8_t  stat;          /* the drive's status byte */
	uint32_t abs;           /* absolute sector, 0xFFFFFFFF if unknown */
} cd_audio_pos;

/* Open the way from the drive to the speakers (SPU master and CD volume, CD input on, the drive's mixer straight through). Call once before the first play. */
void cd_audio_init(void);
/* Play from the start of a track (1..) to the end of the disc; track 0 = the first one. Returns CD_OK or a CD_* code. */
int cd_audio_play(int track);
/* Play from an absolute sector (Setloc + Play), to continue after a pause or after a seek of the timing source. */
int cd_audio_play_from(uint32_t sector);
/* Pause; `pos` (may be NULL) gets the position where it stopped. */
int cd_audio_pause(cd_audio_pos *pos);
/* Stop and spin the motor down. */
int cd_audio_stop(void);
/* Where is it (GetlocP) and is it playing (GetStat). Returns CD_OK or a CD_* code. */
int cd_audio_where(cd_audio_pos *pos);
