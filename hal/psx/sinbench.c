/* How long does it take the PSX to build the table of the 1024 Sinsemilla points of Orchard? Output goes to the TTY (printf).
 * Time base: the VSync counter (50 Hz PAL / 60 Hz NTSC). Run as a plain exe in an emulator or on hardware.
 *   1. the constants of the hash to curve (pallas_table_step),
 *   2. the 1024 points S_j = GroupHash("z.cash:SinsemillaS", j) in batches of 16 (as core/coin/orchard.c does), projective,
 *   3. the same points in the 32 byte Orchard encoding (x and the sign of y: one inversion each),
 *   4. the cost of getting y back from such an encoding (pl_decode, a square root) for the 109 points of one note commitment. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <psxgpu.h>
#include "ec/pallas.h"

static int hz;
static pl_pt pts[16];
static uint8_t enc[1024][32];                    /* the encoded table: 32 KB */

static int ms_since(int t0) { return (VSync(-1) - t0) * 1000 / hz; }

int main(void)
{
    static const char S_DOM[] = "z.cash:SinsemillaS";
    uint8_t msgs[16][4];
    int t0, t_all, t_hash = 0, t_enc = 0;

    ResetGraph(0);
    hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
    printf("psxx sinsemilla table bench (%d Hz frame counter)\n", hz);
    VSync(0);

    t0 = VSync(-1);
    while (pallas_table_step() < 100) {}
    printf("1. constants of the hash to curve: %d ms\n", ms_since(t0));

    t_all = VSync(-1);
    for (int base = 0; base < 1024; base += 16) {
        int a = VSync(-1);
        for (int j = 0; j < 16; j++) { uint32_t v = (uint32_t) (base + j); msgs[j][0] = (uint8_t) v; msgs[j][1] = (uint8_t) (v >> 8); msgs[j][2] = 0; msgs[j][3] = 0; }
        pl_group_hash_batch(pts, 16, (const uint8_t *) S_DOM, sizeof S_DOM - 1, &msgs[0][0], 4);
        t_hash += VSync(-1) - a;
        a = VSync(-1);
        for (int j = 0; j < 16; j++) pl_encode(enc[base + j], &pts[j]);
        t_enc += VSync(-1) - a;
        if (((base + 16) & 127) == 0) printf("   %4d of 1024 points, %d s so far\n", base + 16, ms_since(t_all) / 1000);
    }
    printf("2. 1024 points (hash to curve, batches of 16): %d ms (%d ms a point)\n", t_hash * 1000 / hz, t_hash * 1000 / hz / 1024);
    printf("3. their 32 byte encodings (an inversion each): %d ms\n", t_enc * 1000 / hz);
    printf("   total for the table: %d ms\n", ms_since(t_all));
    printf("   point 0 encoded: ");
    for (int i = 0; i < 32; i++) printf("%02x", enc[0][i]);
    printf("\n");

    t0 = VSync(-1);
    for (int i = 0; i < 109; i++) { pl_pt p; if (pl_decode(&p, enc[(i * 9) & 1023])) printf("decode failed\n"); }
    printf("4. y recovered from 109 encoded points: %d ms (%d ms a point)\n", ms_since(t0), ms_since(t0) / 109);
    printf("done\n");
    for (;;) VSync(0);
    return 0;
}
