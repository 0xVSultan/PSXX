#include "dirscan.h"
#include <string.h>
#include "hash/crc32.h"

static int sum_ok(const uint8_t *f)
{
    uint8_t x = 0;
    for (int i = 0; i < DIRSCAN_FRAME - 1; i++) x ^= f[i];
    return x == f[DIRSCAN_FRAME - 1];
}

void dirscan_run(dirscan *d, const uint8_t frames[DIRSCAN_FRAMES][DIRSCAN_FRAME])
{
    memset(d, 0, sizeof *d);
    d->fingerprint = crc32(&frames[0][0], DIRSCAN_FRAMES * DIRSCAN_FRAME);
    d->formatted = frames[0][0] == 'M' && frames[0][1] == 'C' && sum_ok(frames[0]);
    if (!d->formatted) return;
    for (int b = 1; b < DIRSCAN_FRAMES; b++) {
        const uint8_t *e = frames[b];
        uint32_t size = e[4] | ((uint32_t) e[5] << 8) | ((uint32_t) e[6] << 16) | ((uint32_t) e[7] << 24);

        if (!sum_ok(e)) d->bad_sums++;
        if (e[0] == 0x51) {
            d->used++;
            if (!memcmp(e + 10, "FreePSXBoot", 11) || size > 15u * 8192u) d->boot = 1;
        }
    }
}
