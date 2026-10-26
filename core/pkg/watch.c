#include "watch.h"

void watch_init(watch *w)
{
    w->raw = w->shown = -1;
    w->gen = 0;
    w->flips = 0;
}

unsigned watch_feed(watch *w, int present)
{
    unsigned ev = WATCH_EVENT_NONE;
    int prev = w->raw;

    present = present != 0;
    if (prev >= 0 && present != prev) {
        w->flips++;
        w->gen++;
        ev |= WATCH_EVENT_RAW_FLIP;
    }
    w->raw = present;
    if (present == prev && present != w->shown) {            /* two equal polls in a row */
        w->shown = present;
        ev |= WATCH_EVENT_SHOWN;
    }
    return ev;
}
