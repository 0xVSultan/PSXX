#pragma once
#include <stdint.h>

/* The bookkeeping of the presence polls of one memory card slot. Each poll says "a card answered" or "none"; this tells what to do with it:
 *  - the shown state (in / out) changes after two equal polls in a row, so a single odd poll does not flash;
 *  - but every raw change, even a single poll, raises the generation: whatever was found out about the card (a fingerprint, a verified package) belongs to a generation and
 *    is void as soon as the generation moves on. A card that was out between two polls cannot be seen at all: the content (fingerprint, hash) is what decides. */

enum { WATCH_EVENT_NONE = 0, WATCH_EVENT_RAW_FLIP = 1, WATCH_EVENT_SHOWN = 2 };

typedef struct {
    int      raw;                /* the last poll: -1 none yet, 0 no card, 1 a card */
    int      shown;              /* -1 unknown, 0 out, 1 in */
    uint32_t gen;                /* raised at every raw change */
    uint32_t flips;
} watch;

void watch_init(watch *w);
/* One poll. Returns a mask of WATCH_EVENT_*. */
unsigned watch_feed(watch *w, int present);
