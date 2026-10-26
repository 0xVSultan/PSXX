#pragma once
#include <stddef.h>
#include <stdint.h>
#include "pkg/watch.h"
#include "loader.h"

/* The watch over the two memory card slots. It runs only while a screen asks for it (cw_tick), at a slow pace: one byte exchange per slot
 * per interval (mc_present), the full look at a card (16 frames) only after a change and every few seconds as a check of the content.
 *
 * Every raw change of the presence (even a single poll) voids what was known about the slot; the card is looked at again when it has been steady for two polls. A fingerprint
 * that changes while the card never left (a switchable card that changed its image) voids it as well. What the watch says is information for the user: the package is
 * checked against the pin again when it is read (ldr_open) and its hash decides. */

typedef enum {
    CW_UNKNOWN = 0,          /* not polled yet */
    CW_CHECKING,             /* a change was seen, the card has not been looked at yet */
    CW_NO_CARD,
    CW_UNFORMATTED,
    CW_BOOT,                 /* a FreePSXBoot card */
    CW_NO_PACKAGE,           /* a card without the package file (the card of the requests, for example) */
    CW_PKG_OK,               /* the package opens: its header and table match the pin (its content is read and checked when it is loaded) */
    CW_PKG_BAD,              /* a package that is refused: code and detail say why */
    CW_READ_ERROR            /* a card that answers but cannot be read */
} cw_state;

typedef struct {
    watch    w;
    cw_state state;
    int      code, detail;   /* for CW_PKG_BAD: the loader code and its detail */
    uint32_t fp;             /* the fingerprint of the directory at the look */
    int      have;           /* the look is valid (it belongs to the current generation of the slot) */
    int      next_check;     /* the frame of the next fingerprint check */
    char     digest[9];      /* for CW_PKG_OK: the first 4 bytes of the digest of header and table, in hex */
} cw_slot;

typedef struct {
    cw_slot     s[2];
    int         hz, interval, next_poll;
    const char *name;
    int         kind;
    const uint8_t *pin;
} cw;

void cw_init(cw *c, int hz, const char *package_name, int kind, const uint8_t pin[32]);
/* Starts watching (when a screen opens, or to look again): fresh polls from the next tick, interval_ms between polls. */
void cw_begin(cw *c, int frame, int interval_ms);
/* One step per frame while the screen is open: polls when the interval is over, looks at one changed slot. */
void cw_tick(cw *c, int frame);
/* A quick look without waiting: two polls and the look at both slots (for the status line of the main screen). */
void cw_refresh(cw *c, int frame);
/* 1 if the slot holds an openable package that was looked at in the current generation. */
int cw_ok(const cw *c, int port);
/* a short text for the status line */
void cw_text(const cw *c, int port, char *buf, size_t n);
