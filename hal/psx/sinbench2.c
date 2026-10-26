/* A schedule for the table of the 1024 Sinsemilla points, built in stripes with gaps. Output goes to the TTY (printf).
 * Time base: the VSync counter (50 Hz PAL / 60 Hz NTSC). Run as a plain exe in an emulator or on hardware.
 *
 * A stripe is one point made on its own (no batch of 16 to share the inversions with): it costs about 125 ms (in a batch it is 83 ms a
 * point, but then the points come in groups of 16). The order of the stripes:
 *   0.  the point 0 (the value 0 is the most frequent chunk of a note commitment: the top bits of the amount and the padding),
 *   1.  from the middle of the table (j = 512) outwards, on both sides alternately, every second point: 512, 514, 510, 516, 508, ...
 *   2.  the gaps, again from the inside outwards on both sides: 513, 511, 515, 509, ...
 * The programme measures the real cost of a stripe, builds the whole table in this order (printing the progress), and counts, at every
 * milestone, how many of the chunks of 200 simulated note commitments (1086 bits: g_d, pk_d, the value, rho, psi; the value is a small
 * amount, so its top chunks are 0) are in the table already, for this order and for the plain order 0, 1, 2, ... with the same number of
 * points. Four of the points made are compared with the reference table. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <psxgpu.h>
#include "ec/pallas.h"

#define N 1024
#define NOTES 200
#define CHUNKS 109

static int hz;
static uint8_t tab[N][64];
static uint8_t done_sched[N], done_seq[N], placed[N];
static uint16_t order[N];
static uint16_t chunk[NOTES][CHUNKS];
static uint32_t rng = 0x2545F491u;

static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; }
static int ms_since(int t0) { return (VSync(-1) - t0) * 1000 / hz; }

static void make_point(unsigned j, uint8_t xy[64])
{
    static const char S_DOM[] = "z.cash:SinsemillaS";
    uint8_t msg[4];
    pl_pt p;
    msg[0] = (uint8_t) j; msg[1] = (uint8_t) (j >> 8); msg[2] = 0; msg[3] = 0;
    pl_group_hash(&p, (const uint8_t *) S_DOM, sizeof S_DOM - 1, msg, 4);
    pl_to_affine_le(xy, xy + 32, &p);
}

static int n_order;

static void put(int j)
{
    if (j >= 0 && j < N && !placed[j]) { placed[j] = 1; order[n_order++] = (uint16_t) j; }
}

/* the order of the stripes */
static void make_order(void)
{
    put(0);
    for (int k = 0; k <= 512; k += 2) { put(512 + k); put(512 - k); }          /* the stripes: even distance from the middle, both sides */
    for (int k = 1; k <= 512; k += 2) { put(512 + k); put(512 - k); }          /* the gaps: odd distance, from the inside outwards */
    for (int j = 0; j < N; j++) put(j);                                        /* whatever is left (none, as a safety) */
}

/* 200 note commitments: g_d and pk_d (256 bits each), the value (64 bits, an amount below 2^30), rho and psi (255 bits), 1086 bits, chunks of
 * 10 bits, the first bit the least significant */
static void make_chunks(void)
{
    for (int c = 0; c < NOTES; c++) {
        uint8_t bits[1090];
        int k = 0;
        uint32_t v;
        for (int i = 0; i < 512; i++) bits[k++] = (uint8_t) ((rnd() >> 7) & 1);
        v = rnd() & 0x3FFFFFFFu;
        for (int i = 0; i < 64; i++) bits[k++] = i < 30 ? (uint8_t) ((v >> i) & 1) : 0;
        for (int i = 0; i < 255; i++) bits[k++] = (uint8_t) ((rnd() >> 9) & 1);
        for (int i = 0; i < 255; i++) bits[k++] = (uint8_t) ((rnd() >> 11) & 1);
        for (; k < 1090; k++) bits[k] = 0;
        for (int i = 0; i < CHUNKS; i++) {
            int x = 0;
            for (int b = 0; b < 10; b++) x |= bits[10 * i + b] << b;
            chunk[c][i] = (uint16_t) x;
        }
    }
}

static int hits(const uint8_t *have)
{
    int h = 0;
    for (int c = 0; c < NOTES; c++) for (int i = 0; i < CHUNKS; i++) h += have[chunk[c][i]];
    return h;
}

static void pct(char *out, int h)
{
    int t = h * 1000 / (NOTES * CHUNKS);
    sprintf(out, "%d.%d%%", t / 10, t % 10);
}

int main(void)
{
    static const struct { int j; uint8_t x[8]; } REF[] = {
        {0, {0x5f, 0xea, 0x44, 0x20, 0x91, 0xeb, 0x91, 0x5a}}, {1, {0x91, 0xaf, 0x08, 0xa1, 0x3e, 0xe3, 0x4a, 0xce}},
        {512, {0x0c, 0xae, 0xbd, 0x3b, 0x50, 0x59, 0xed, 0xc7}}, {1023, {0xae, 0x9d, 0xb1, 0xd3, 0x47, 0xed, 0xc3, 0x2b}}};
    static const char S_DOM[] = "z.cash:SinsemillaS";
    int t0, t_start, ok = 1;
    uint8_t xy[64], msgs[16][4];
    pl_pt batch[16];

    ResetGraph(0);
    hz = (GetVideoMode() == MODE_PAL) ? 50 : 60;
    printf("psxx sinsemilla stripe bench (%d Hz frame counter)\n", hz);
    VSync(0);
    while (pallas_table_step() < 100) {}
    make_order();
    make_chunks();
    printf("order: %d points, the first 10: %d %d %d %d %d %d %d %d %d %d\n", n_order, order[0], order[1], order[2], order[3], order[4], order[5], order[6],
           order[7], order[8], order[9]);

    /* the cost of a stripe on its own, and of other points in a batch of 16 */
    t0 = VSync(-1);
    for (int i = 0; i < 16; i++) make_point(100 + (unsigned) i, xy);
    printf("a stripe (a point on its own, affine): %d ms each (16 samples)\n", ms_since(t0) / 16);
    for (int i = 0; i < 16; i++) { uint32_t v = 200 + (uint32_t) i; msgs[i][0] = (uint8_t) v; msgs[i][1] = (uint8_t) (v >> 8); msgs[i][2] = 0; msgs[i][3] = 0; }
    t0 = VSync(-1);
    pl_group_hash_batch(batch, 16, (const uint8_t *) S_DOM, sizeof S_DOM - 1, &msgs[0][0], 4);
    printf("a point in a batch of 16 (projective only): %d ms each\n", ms_since(t0) / 16);

    /* the whole table in the order of the stripes */
    printf("building the table in stripes; the share of the chunks of %d simulated note commitments that are in it:\n", NOTES);
    printf("  points  seconds  this order  plain order\n");
    t_start = VSync(-1);
    for (int i = 0; i < N; i++) {
        make_point(order[i], tab[order[i]]);
        done_sched[order[i]] = 1;
        done_seq[i] = 1;
        if (i == 0 || (i + 1) % 64 == 0) {
            char a[16], b[16];
            pct(a, hits(done_sched));
            pct(b, hits(done_seq));
            printf("  %6d  %7d  %10s  %11s\n", i + 1, ms_since(t_start) / 1000, a, b);
        }
    }
    printf("the table took %d ms in all (%d ms a stripe)\n", ms_since(t_start), ms_since(t_start) / N);
    for (int i = 0; i < 4; i++) {
        int good = memcmp(tab[REF[i].j], REF[i].x, 8) == 0;
        ok &= good;
        printf("point %4d: x starts %02x%02x%02x%02x%02x%02x%02x%02x %s\n", REF[i].j, tab[REF[i].j][0], tab[REF[i].j][1], tab[REF[i].j][2], tab[REF[i].j][3],
               tab[REF[i].j][4], tab[REF[i].j][5], tab[REF[i].j][6], tab[REF[i].j][7], good ? "ok" : "WRONG");
    }
    printf("%s\n", ok ? "done, the points match the reference" : "done, A POINT IS WRONG");
    for (;;) VSync(0);
    return 0;
}
