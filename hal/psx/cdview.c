#include "cdview.h"
#include "timer.h"

#define PAGE_X 640
#define PAGE_Y 0
#define CAP_MIN 360000u                /* 80 minutes */
#define START 150u                     /* first program sector (absolute) */

/* Geometry in half pixels of the texture (d2 = squared distance from the centre, x and y doubled). */
#define R_HOLE 14                      /* centre hole */
#define R_HUB 34                       /* clamping area */
#define R_IN 66                        /* start of the data area */
#define R_OUT 148                      /* end of the data area */
#define R_RIM 152                      /* edge of the disc */
#define D2_IN (R_IN * R_IN)
#define D2_SPAN (R_OUT * R_OUT - R_IN * R_IN)
/* The same radii in 1/16 pixel for the crosshair. */
#define Q_IN (R_IN * 8)
#define Q_OUT (R_OUT * 8)
#define Q2_IN (Q_IN * Q_IN)
#define Q2_SPAN (Q_OUT * Q_OUT - Q_IN * Q_IN)

static uint32_t cap_span, used_span;   /* data area capacity and written sectors, from sector 150 on */
static uint32_t f12_used;              /* written part as a fraction of the capacity, 12 bit */
static uint32_t bw;                    /* half width of the boundary line in d2 units */
static uint32_t d2_used;               /* squared radius (half pixels) of the written/empty boundary */
static uint32_t q_used;                /* radius (1/16 pixel) of the boundary */
static uint32_t rng;
static int32_t  cr, cvr;               /* crosshair radius (1/16 pixel) and speed */
static uint16_t ca, cva;               /* crosshair angle and angular speed (signed, wraps) */
static int      cturn;                 /* frames until the next change of course */

static const int16_t SIN[65] = {0,25,50,75,100,125,150,175,200,224,249,273,297,321,345,369,392,415,438,460,483,505,526,548,569,590,610,630,650,669,688,706,724,742,759,775,792,807,822,837,851,865,878,891,903,915,926,936,946,955,964,972,980,987,993,999,1004,1009,1013,1016,1019,1021,1023,1024,1024};

static int sine(unsigned a)                         /* a: 0..65535 = one turn, result -1024..1024 */
{
	unsigned i = (a >> 8) & 255, q = i >> 6, k = i & 63;
	int v;
	switch (q) {
	case 0:  v = SIN[k]; break;
	case 1:  v = SIN[64 - k]; break;
	case 2:  v = -SIN[k]; break;
	default: v = -SIN[64 - k]; break;
	}
	return v;
}

static uint32_t isqrt(uint32_t v)
{
	uint32_t r = 0, b = 1u << 30;
	while (b > v) b >>= 2;
	for (; b; b >>= 2) {
		if (v >= r + b) { v -= r + b; r = (r >> 1) + b; }
		else r >>= 1;
	}
	return r;
}

static uint32_t next_rand(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static uint32_t pack(int r, int g, int b) { return 0x8000u | (uint32_t) (r | (g << 5) | (b << 10)); }

static int clamp5(int v) { return v < 0 ? 0 : v > 31 ? 31 : v; }

static uint32_t pixel(int x, int y)
{
	int dx = 2 * x + 1 - CDV_TEX, dy = 2 * y + 1 - CDV_TEX;
	uint32_t d2 = (uint32_t) (dx * dx + dy * dy);
	int shine = (dy - dx) / 12;                         /* a soft diagonal light */
	int r, g, b;

	if (d2 <= (uint32_t) (R_HOLE * R_HOLE) || d2 > (uint32_t) (R_RIM * R_RIM)) return 0;
	if (d2 <= (uint32_t) (R_HUB * R_HUB)) return pack(15 + shine / 2, 15 + shine / 2, 17 + shine / 2);
	if (d2 < D2_IN) return pack(7, 8, 13);              /* lead-in mirror band */
	if (d2 > (uint32_t) (R_OUT * R_OUT)) return pack(20, 20, 22);   /* outer rim */

	uint32_t f12 = ((d2 - D2_IN) << 12) / D2_SPAN;
	if (d2 + bw >= d2_used && d2 <= d2_used + bw) return pack(31, 31, 31);   /* where the written part ends */
	if (f12 < f12_used) {                               /* written: gold and amber rings, one per 50 MB */
		uint32_t band = (f12 * cap_span >> 12) / (CDV_RING_MB * 1000000u / CDV_SECTOR_BYTES);
		if (band & 1) { r = 28; g = 20; b = 3; } else { r = 31; g = 25; b = 6; }
		r += shine / 3; g += shine / 3;
	} else {                                            /* empty: dark slate */
		r = 4; g = 6; b = 11;
		r += shine / 6; g += shine / 6; b += shine / 5;
	}
	return pack(clamp5(r), clamp5(g), clamp5(b));
}

static uint32_t pair(void *user, int x, int y)
{
	(void) user;
	return pixel(x, y) | (pixel(x + 1, y) << 16);
}

void cdview_init(uint32_t leadout)
{
	uint32_t cap = leadout > CAP_MIN ? leadout : CAP_MIN;

	cap_span = cap - START;
	used_span = leadout > START ? leadout - START : 0;
	f12_used = (used_span << 12) / cap_span;                         /* all products stay below 2^32 */
	d2_used = D2_IN + ((D2_SPAN * f12_used) >> 12);
	q_used = isqrt(Q2_IN + (((Q2_SPAN >> 2) * f12_used) >> 10));
	bw = isqrt(d2_used);
	gpu_upload_rows(PAGE_X, PAGE_Y, CDV_TEX + 2, CDV_TEX + 1, pair, 0);

	rng = ticks_cycles() | 1;
	cr = (int32_t) ((Q_IN + q_used) / 2);
	ca = (uint16_t) next_rand();
	cvr = 0;
	cva = 300;
	cturn = 0;
}

void cdview_step(void)
{
	int32_t lo = (int32_t) Q_IN + 40, hi = (int32_t) q_used - 40;

	if (hi < lo + 16) hi = lo + 16;
	if (--cturn <= 0) {                                 /* a new course every 0.4 to 1.2 s */
		uint32_t v = next_rand();
		cturn = 20 + (int) (v & 31);
		cvr = (int32_t) ((v >> 8) & 31) - 15;
		cva = (uint16_t) (150 + ((v >> 16) & 511));
		if (v & 0x80000000u) cva = (uint16_t) -cva;
	}
	ca = (uint16_t) (ca + cva);
	cr += cvr;
	if (cr < lo) { cr = lo; cvr = -cvr; }
	if (cr > hi) { cr = hi; cvr = -cvr; }
}

uint32_t cdview_target(void)
{
	uint32_t r = (uint32_t) cr, r2 = r * r, num = r2 > (uint32_t) Q2_IN ? r2 - Q2_IN : 0;
	uint32_t s = (num >> 4) * (cap_span >> 4) / (Q2_SPAN >> 8);     /* sectors from the start of the program area */
	uint32_t spr = 9 + (r > (uint32_t) Q_IN ? (r - Q_IN) * 12 / (Q_OUT - Q_IN) : 0);   /* sectors per turn here */

	s += ((uint32_t) ca * spr) >> 16;                   /* the angle picks the sector within the turn */
	if (s + 100 > used_span) s = used_span > 100 ? used_span - 100 : 0;
	return START + s;
}

void cdview_pos(uint16_t *r, uint16_t *a) { *r = (uint16_t) cr; *a = ca; }
uint32_t cdview_capacity(void) { return cap_span; }
uint32_t cdview_used(void) { return used_span; }

void cdview_draw(RenderContext *ctx, int x, int y)
{
	int cx = x + CDV_TEX, cy = y + CDV_TEX / 2;         /* centre on screen: the picture is 2 * CDV_TEX wide */
	int px = cx + (int) (((int32_t) cr * sine((unsigned) ca + 16384)) >> 13);   /* cos; 1/16 px, doubled width */
	int py = cy + (int) (((int32_t) cr * sine(ca)) >> 14);

	gpu_draw_stretched16(ctx, 8, x, y, CDV_TEX, CDV_TEX, 2 * CDV_TEX, PAGE_X, PAGE_Y);
	/* crosshair: a dark outline under a bright cross (a pixel is twice as high as wide) */
	gpu_draw_rect(ctx, 7, px - 16, py - 2, 32, 5, 0, 0, 0);
	gpu_draw_rect(ctx, 7, px - 3, py - 11, 7, 23, 0, 0, 0);
	gpu_draw_rect(ctx, 6, px - 14, py - 1, 28, 3, 255, 60, 60);
	gpu_draw_rect(ctx, 6, px - 1, py - 9, 3, 19, 255, 60, 60);
}
