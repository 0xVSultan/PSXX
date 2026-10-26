/* The presence bookkeeping (core/pkg/watch.c) and the look at the directory of a card (core/pkg/dirscan.c). The frames of the FreePSXBoot card are the ones the card probe
 * read from the card of this project (M0, 2026-10-22). Usage: test_watch */
#include <stdio.h>
#include <string.h>
#include "pkg/dirscan.h"
#include "pkg/watch.h"

static int fails, checks;

#define CHECK(c, ...) do { checks++; if (!(c)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static void fix(uint8_t *e) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= e[i]; e[127] = x; }

static void blank(uint8_t f[DIRSCAN_FRAMES][DIRSCAN_FRAME])
{
    memset(f, 0, DIRSCAN_FRAMES * DIRSCAN_FRAME);
    f[0][0] = 'M'; f[0][1] = 'C'; fix(f[0]);
    for (int b = 1; b < 16; b++) { f[b][0] = 0xA0; f[b][8] = f[b][9] = 0xFF; fix(f[b]); }
}

int main(void)
{
    watch w;
    unsigned ev;
    static uint8_t f[DIRSCAN_FRAMES][DIRSCAN_FRAME], g[DIRSCAN_FRAMES][DIRSCAN_FRAME];
    dirscan d, d2;

    /* the polls: the first two equal polls show the state, a card that stays is quiet */
    watch_init(&w);
    CHECK(watch_feed(&w, 1) == WATCH_EVENT_NONE && w.shown == -1, "the first poll shows nothing yet");
    ev = watch_feed(&w, 1);
    CHECK(ev == WATCH_EVENT_SHOWN && w.shown == 1 && w.gen == 0, "two polls show the card (%u, shown %d, gen %u)", ev, w.shown, (unsigned) w.gen);
    CHECK(watch_feed(&w, 1) == WATCH_EVENT_NONE, "a card that stays is quiet");

    /* one poll without the card: a raw flip (the generation moves on) but the shown state stays */
    ev = watch_feed(&w, 0);
    CHECK(ev == WATCH_EVENT_RAW_FLIP && w.shown == 1 && w.gen == 1, "one poll out: a raw flip only (%u, shown %d, gen %u)", ev, w.shown, (unsigned) w.gen);
    ev = watch_feed(&w, 1);
    CHECK(ev == WATCH_EVENT_RAW_FLIP && w.shown == 1 && w.gen == 2, "back again: the generation moved twice (%u, gen %u)", ev, (unsigned) w.gen);
    CHECK(watch_feed(&w, 1) == WATCH_EVENT_NONE && w.shown == 1, "and quiet again");

    /* out for two polls: the shown state follows */
    watch_feed(&w, 0);
    ev = watch_feed(&w, 0);
    CHECK(ev == WATCH_EVENT_SHOWN && w.shown == 0, "two polls out show the card as out (%u, shown %d)", ev, w.shown);
    ev = watch_feed(&w, 1);
    CHECK((ev & WATCH_EVENT_RAW_FLIP) && w.shown == 0, "a poll in: a raw flip, shown still out");
    ev = watch_feed(&w, 1);
    CHECK(ev == WATCH_EVENT_SHOWN && w.shown == 1 && w.flips == 4, "two polls in: shown in (flips %u)", (unsigned) w.flips);

    /* a poll that flickers every time: the generation moves every time, the shown state never changes */
    watch_init(&w);
    watch_feed(&w, 0); watch_feed(&w, 0);
    for (int i = 0; i < 10; i++) watch_feed(&w, i & 1);
    CHECK(w.shown == 0 && w.gen == 9, "a flicker never shows, every change moves the generation (shown %d, gen %u)", w.shown, (unsigned) w.gen);   /* the first poll is 0 as before: no change */

    /* the directory */
    blank(f);
    dirscan_run(&d, f);
    CHECK(d.formatted && d.used == 0 && !d.boot && d.bad_sums == 0, "a blank card");

    memcpy(g, f, sizeof f);
    g[0][0] = 'X';
    dirscan_run(&d2, g);
    CHECK(!d2.formatted && d2.fingerprint != d.fingerprint, "not formatted");
    memcpy(g, f, sizeof f);
    g[0][127] ^= 1;
    dirscan_run(&d2, g);
    CHECK(!d2.formatted, "a wrong checksum of the header frame");

    memcpy(g, f, sizeof f);
    memset(g[1], 0, DIRSCAN_FRAME);
    g[1][0] = 0x51; g[1][5] = 0x20; g[1][8] = g[1][9] = 0xFF;                       /* a file of one block */
    memcpy(g[1] + 10, "BESCES-00000PSXXPK01", 20);
    fix(g[1]);
    dirscan_run(&d2, g);
    CHECK(d2.formatted && d2.used == 1 && !d2.boot && d2.bad_sums == 0 && d2.fingerprint != d.fingerprint, "a card with a file");
    g[1][10] ^= 1;
    dirscan_run(&d2, g);
    CHECK(d2.bad_sums == 1, "an entry with a wrong checksum is counted");

    /* the FreePSXBoot card of this project (frames 0 and 1 as the probe dumped them) */
    memcpy(g, f, sizeof f);
    memset(g[1], 0, DIRSCAN_FRAME);
    {
        static const uint8_t e[] = {0x51, 0, 0, 0, 0x00, 0x60, 0xc5, 0x0a, 0x7c, 0x1b, 'F', 'r', 'e', 'e', 'P', 'S', 'X', 'B', 'o', 'o', 't'};
        memcpy(g[1], e, sizeof e);
        g[1][127] = 0xc0;                                                         /* the checksum in the dump */
    }
    dirscan_run(&d2, g);
    CHECK(d2.boot && d2.used == 1, "the FreePSXBoot card: boot %d used %d bad sums %d", d2.boot, d2.used, d2.bad_sums);
    CHECK(d2.bad_sums == 0, "its checksum is right (%d bad)", d2.bad_sums);
    memset(g[1] + 10, 0, 11);
    memcpy(g[1] + 10, "SOMETHING", 9);
    fix(g[1]);
    dirscan_run(&d2, g);
    CHECK(d2.boot, "another name, but a size that no card has: still the boot card");
    g[1][4] = 0; g[1][5] = 0x20; g[1][6] = 0; g[1][7] = 0;
    fix(g[1]);
    dirscan_run(&d2, g);
    CHECK(!d2.boot, "a normal size and name: not a boot card");

    printf("card watch: %d checks, %d wrong\n", checks, fails);
    return fails != 0;
}
