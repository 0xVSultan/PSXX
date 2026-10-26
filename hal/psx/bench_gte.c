/* 256 bit field multiplication on the PSX: the CPU alone against CPU + GTE, and what that means for a vanity miner.
 *
 * The field is secp256k1's (p = 2^256 - 2^32 - 977). Two ways to get the 512 bit product of two 256 bit numbers:
 *   CPU      8 x 8 words of 32 bits, multu (HI / LO) and carries in C.
 *   GTE      13 bit limbs (20 of them): the product is a convolution, cut into 3 x 3 Toeplitz blocks that MVMVA (a 3x3
 *            matrix of 16 bit values times a 3 vector of 16 bit values, 9 products in ~8 cycles) evaluates; the three
 *            results of a block are the partial column sums, added up by the CPU. A column sum is at most 20 * (2^13)^2 <
 *            2^32, so the 32 bit MAC values are exact. Afterwards the carries are propagated and the limbs packed
 *            back into 32 bit words.
 * Both end in the same reduction mod p (done by the CPU), so the difference between the modes is the multiplication.
 * The programme checks that both modes give the same results before it times anything.
 *
 * Timing: root counter 2 (8 CPU cycles per tick), read after every batch of operations. Run it on real hardware for real
 * numbers: emulators do not model the cost of multu / the GTE exactly.
 *
 * Controls:  X  CPU only     Square  CPU and GTE (the two modes side by side)     SELECT  back to the menu */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include "hash/keccak.h"
#include "ec/bn_comba.h"
#include "../../tests/keccak_ref.h"
#include "hash/sha512.h"
#include "../../tests/sha512_ref.h"
void keccak_f1600_ram(uint64_t st[25]);     /* keccak_ram.c: the same with the state in main RAM */

static RenderContext ctx;
static input_state   in;

/* ---- the field ---- */

static const uint32_t P[8] = {0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};

/* 256 x 256 -> 512 bits, 32 bit words, little endian */
static void mul256_cpu(uint32_t r[16], const uint32_t a[8], const uint32_t b[8])
{
	for (int i = 0; i < 16; i++) r[i] = 0;
	for (int i = 0; i < 8; i++) {
		uint32_t carry = 0, ai = a[i];
		for (int j = 0; j < 8; j++) {
			uint64_t t = (uint64_t) ai * b[j] + r[i + j] + carry;
			r[i + j] = (uint32_t) t;
			carry = (uint32_t) (t >> 32);
		}
		r[i + 8] = carry;
	}
}

/* ---- the GTE product ---- */

#define LIMBS 20                  /* 13 bit limbs: 260 bits */
#define LB 13
#define LMASK ((1u << LB) - 1u)

static void split13(uint32_t l[LIMBS + 3], const uint32_t w[8])
{
	uint32_t x[9];
	for (int i = 0; i < 8; i++) x[i] = w[i];
	x[8] = 0;
	for (int k = 0; k < LIMBS; k++) {
		int pos = k * LB, wi = pos >> 5, s = pos & 31;
		uint32_t v = x[wi] >> s;
		if (s + LB > 32) v |= x[wi + 1] << (32 - s);
		l[k] = v & LMASK;
	}
	l[LIMBS] = l[LIMBS + 1] = l[LIMBS + 2] = 0;
}

static inline void gte_matrix(uint32_t c0, uint32_t c1, uint32_t c2, uint32_t c3, uint32_t c4)
{
	__asm__ volatile("ctc2 %0, $0\n ctc2 %1, $1\n ctc2 %2, $2\n ctc2 %3, $3\n ctc2 %4, $4\n nop"
	                 : : "r"(c0), "r"(c1), "r"(c2), "r"(c3), "r"(c4));
}

/* MAC = M * V (no translation, no shift); V = (xy & 0xFFFF, xy >> 16, z) */
static inline void gte_mv(uint32_t xy, uint32_t z, uint32_t *m1, uint32_t *m2, uint32_t *m3)
{
	__asm__ volatile("mtc2 %3, $0\n mtc2 %4, $1\n nop\n nop\n cop2 0x0406012\n"
	                 "mfc2 %0, $25\n mfc2 %1, $26\n mfc2 %2, $27\n nop"
	                 : "=&r"(*m1), "=&r"(*m2), "=&r"(*m3) : "r"(xy), "r"(z));
}

static void mul256_gte(uint32_t r[16], const uint32_t a[8], const uint32_t b[8])
{
	uint32_t al[LIMBS + 3], bl[LIMBS + 3], col[44], bxy[7], bz[7];

	split13(al, a);
	split13(bl, b);
	for (int q = 0; q < 7; q++) {                                  /* the vectors (b[3q], b[3q+1], b[3q+2]), packed once */
		bxy[q] = bl[3 * q] | (bl[3 * q + 1] << 16);
		bz[q] = bl[3 * q + 2];
	}
	for (int k = 0; k < 44; k++) col[k] = 0;
	for (int i0 = 0; i0 < LIMBS + 2; i0 += 3) {                    /* Toeplitz matrix of a around index i0: m[r][c] = a[i0 + r - c] */
		#define A_(k) ((int) (k) >= 0 && (int) (k) < LIMBS ? al[k] : 0u)
		uint32_t a_m2 = A_(i0 - 2), a_m1 = A_(i0 - 1), a_0 = A_(i0), a_p1 = A_(i0 + 1), a_p2 = A_(i0 + 2);
		#undef A_
		gte_matrix(a_0 | (a_m1 << 16),            /* RT11 RT12 */
		           a_m2 | (a_p1 << 16),           /* RT13 RT21 */
		           a_0 | (a_m1 << 16),            /* RT22 RT23 */
		           a_p2 | (a_p1 << 16),           /* RT31 RT32 */
		           a_0);                          /* RT33 */
		for (int q = 0; q < 7; q++) {
			uint32_t m1, m2, m3;
			int k = i0 + 3 * q;
			gte_mv(bxy[q], bz[q], &m1, &m2, &m3);
			col[k] += m1;
			col[k + 1] += m2;
			col[k + 2] += m3;
		}
	}
	{                                                              /* carries, then the limbs into 32 bit words */
		uint32_t carry = 0;
		uint64_t acc = 0;
		int bits = 0, o = 0;
		for (int k = 0; k < 41; k++) {
			uint32_t t = col[k] + carry;
			carry = t >> LB;
			acc |= (uint64_t) (t & LMASK) << bits;
			bits += LB;
			if (bits >= 32) {
				if (o < 16) r[o++] = (uint32_t) acc;
				acc >>= 32;
				bits -= 32;
			}
		}
		while (o < 16) { r[o++] = (uint32_t) acc; acc >>= 32; }
	}
}

/* ---- the GTE product in stages, and a version that overlaps the CPU work with the GTE ---- */

static uint32_t st_al[LIMBS + 3], st_bl[LIMBS + 3], st_col[44], st_bxy[7], st_bz[7];

static void stage_split(const uint32_t a[8], const uint32_t b[8])
{
	split13(st_al, a);
	split13(st_bl, b);
	for (int q = 0; q < 7; q++) {
		st_bxy[q] = st_bl[3 * q] | (st_bl[3 * q + 1] << 16);
		st_bz[q] = st_bl[3 * q + 2];
	}
}

#define A_(k) ((int) (k) >= 0 && (int) (k) < LIMBS ? st_al[k] : 0u)
#define LOAD_MATRIX(i0)                                                                                              	do {                                                                                                             		uint32_t a_m2 = A_((i0) - 2), a_m1 = A_((i0) - 1), a_0 = A_(i0), a_p1 = A_((i0) + 1), a_p2 = A_((i0) + 2);   		gte_matrix(a_0 | (a_m1 << 16), a_m2 | (a_p1 << 16), a_0 | (a_m1 << 16), a_p2 | (a_p1 << 16), a_0);          	} while (0)

/* as mul256_gte: each MVMVA is followed at once by reading its results (the CPU waits for the GTE) */
static void stage_conv(void)
{
	for (int k = 0; k < 44; k++) st_col[k] = 0;
	for (int i0 = 0; i0 < LIMBS + 2; i0 += 3) {
		LOAD_MATRIX(i0);
		for (int q = 0; q < 7; q++) {
			uint32_t m1, m2, m3;
			int k = i0 + 3 * q;
			gte_mv(st_bxy[q], st_bz[q], &m1, &m2, &m3);
			st_col[k] += m1;
			st_col[k + 1] += m2;
			st_col[k + 2] += m3;
		}
	}
}

/* issue a MVMVA (V = the vector of block q) and return at once; the memory clobber keeps the CPU's own work after it */
static inline void gte_issue(uint32_t xy, uint32_t z)
{
	__asm__ volatile("mtc2 %0, $0\n mtc2 %1, $1\n nop\n nop\n cop2 0x0406012" : : "r"(xy), "r"(z) : "memory");
}
/* read the three results: waits for the GTE if it is still busy */
static inline void gte_take(uint32_t *m1, uint32_t *m2, uint32_t *m3)
{
	__asm__ volatile("mfc2 %0, $25\n mfc2 %1, $26\n mfc2 %2, $27\n nop" : "=&r"(*m1), "=&r"(*m2), "=&r"(*m3) : : "memory");
}

/* software pipelined: while the GTE computes block q the CPU adds the results of block q - 1 into the columns */
static void stage_conv_il(void)
{
	for (int k = 0; k < 44; k++) st_col[k] = 0;
	for (int i0 = 0; i0 < LIMBS + 2; i0 += 3) {
		uint32_t p1, p2, p3;
		LOAD_MATRIX(i0);
		gte_issue(st_bxy[0], st_bz[0]);
		gte_take(&p1, &p2, &p3);
		for (int q = 1; q < 7; q++) {
			uint32_t n1, n2, n3;
			int k = i0 + 3 * (q - 1);
			gte_issue(st_bxy[q], st_bz[q]);
			st_col[k] += p1;                                       /* overlaps the GTE */
			st_col[k + 1] += p2;
			st_col[k + 2] += p3;
			gte_take(&n1, &n2, &n3);
			p1 = n1; p2 = n2; p3 = n3;
		}
		{
			int k = i0 + 18;
			st_col[k] += p1;
			st_col[k + 1] += p2;
			st_col[k + 2] += p3;
		}
	}
}

static void stage_norm(uint32_t r[16])
{
	uint32_t carry = 0;
	uint64_t acc = 0;
	int bits = 0, o = 0;
	for (int k = 0; k < 41; k++) {
		uint32_t t = st_col[k] + carry;
		carry = t >> LB;
		acc |= (uint64_t) (t & LMASK) << bits;
		bits += LB;
		if (bits >= 32) {
			if (o < 16) r[o++] = (uint32_t) acc;
			acc >>= 32;
			bits -= 32;
		}
	}
	while (o < 16) { r[o++] = (uint32_t) acc; acc >>= 32; }
}

static void mul256_gte_il(uint32_t r[16], const uint32_t a[8], const uint32_t b[8])
{
	stage_split(a, b);
	stage_conv_il();
	stage_norm(r);
}

/* ---- reduction mod p: lo + hi * (2^32 + 977), repeated, then one conditional subtraction ---- */

static void reduce_p(uint32_t out[8], const uint32_t r[16])
{
	uint32_t acc[10];
	uint64_t t, carry;

	for (int i = 0; i < 8; i++) acc[i] = r[i];
	acc[8] = acc[9] = 0;
	carry = 0;
	for (int i = 0; i < 8; i++) {
		t = (uint64_t) r[8 + i] * 977u + acc[i] + carry;
		acc[i] = (uint32_t) t;
		carry = t >> 32;
	}
	acc[8] = (uint32_t) carry;
	carry = 0;
	for (int i = 0; i < 8; i++) {
		t = (uint64_t) acc[i + 1] + r[8 + i] + carry;
		acc[i + 1] = (uint32_t) t;
		carry = t >> 32;
	}
	acc[9] = (uint32_t) carry;
	while (acc[8] | acc[9]) {                                       /* fold what is above 2^256 once more */
		uint64_t h = ((uint64_t) acc[9] << 32) | acc[8], hl;
		acc[8] = acc[9] = 0;
		hl = h * 977u;
		t = (uint64_t) acc[0] + (uint32_t) hl;
		acc[0] = (uint32_t) t;
		carry = (t >> 32) + (hl >> 32);
		t = (uint64_t) acc[1] + (uint32_t) h + carry;
		acc[1] = (uint32_t) t;
		carry = (t >> 32) + (h >> 32);
		for (int i = 2; i < 8; i++) {
			t = (uint64_t) acc[i] + carry;
			acc[i] = (uint32_t) t;
			carry = t >> 32;
		}
		acc[8] = (uint32_t) carry;
	}
	{                                                               /* >= p: subtract it (2^256 < 2p, once is enough) */
		int ge = 1;
		for (int i = 7; i >= 0; i--) {
			if (acc[i] != P[i]) { ge = acc[i] > P[i]; break; }
		}
		if (ge) {
			int64_t bw = 0;
			for (int i = 0; i < 8; i++) {
				int64_t d = (int64_t) acc[i] - P[i] + bw;
				acc[i] = (uint32_t) d;
				bw = d >> 32;
			}
		}
	}
	for (int i = 0; i < 8; i++) out[i] = acc[i];
}

static void fe_mul_cpu(uint32_t o[8], const uint32_t a[8], const uint32_t b[8]) { uint32_t r[16]; mul256_cpu(r, a, b); reduce_p(o, r); }
static void fe_mul_gte(uint32_t o[8], const uint32_t a[8], const uint32_t b[8]) { uint32_t r[16]; mul256_gte(r, a, b); reduce_p(o, r); }

/* ---- check, then time ---- */

static uint32_t rng = 0x12345678u;
static uint32_t next32(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static int selftest(int pairs)
{
	uint32_t a[8], b[8], r1[16], r2[16], o1[8], o2[8];

	for (int n = 0; n < pairs; n++) {
		for (int i = 0; i < 8; i++) {
			a[i] = n == 0 ? 0xFFFFFFFFu : n == 1 ? 0 : next32();
			b[i] = n == 0 ? 0xFFFFFFFFu : n == 2 ? 0xFFFFFFFFu : next32();
		}
		mul256_cpu(r1, a, b);
		mul256_gte(r2, a, b);
		if (memcmp(r1, r2, sizeof r1)) return n + 1;
		mul256_gte_il(r2, a, b);
		if (memcmp(r1, r2, sizeof r1)) return n + 1;
		reduce_p(o1, r1);
		reduce_p(o2, r2);
		if (memcmp(o1, o2, sizeof o1)) return n + 1;
	}
	{                                                               /* (p - 1)^2 = 1 */
		uint32_t m[8], one[8], o[8];
		memcpy(m, P, sizeof m);
		m[0] -= 1;
		fe_mul_gte(o, m, m);
		memset(one, 0, sizeof one);
		one[0] = 1;
		if (memcmp(o, one, sizeof o)) return -1;
		fe_mul_cpu(o, m, m);
		if (memcmp(o, one, sizeof o)) return -2;
	}
	return 0;
}

/* cycles per operation: `batches` batches of `per` operations, the counter is read after each (it must be at least every ~15 ms) */
#define MEASURE(res, batches, per, BODY) do {                                      \
	uint32_t t0_ = ticks_cycles();                                                  \
	for (int b_ = 0; b_ < (batches); b_++) {                                        \
		for (int k_ = 0; k_ < (per); k_++) { BODY; }                                \
		(void) ticks_cycles();                                                      \
	}                                                                               \
	(res) = (ticks_cycles() - t0_) / (uint32_t) ((batches) * (per));                \
} while (0)

typedef struct { uint32_t mul, fe, keccak; } result;

static uint32_t xa[8], xb[8], xr[16], xo[8];

static void run_cpu(result *r)
{
	for (int i = 0; i < 8; i++) { xa[i] = next32(); xb[i] = next32(); }
	MEASURE(r->mul, 400, 16, mul256_cpu(xr, xa, xb));
	MEASURE(r->fe, 400, 16, { fe_mul_cpu(xo, xa, xb); xa[0] ^= xo[0]; });
}

static void run_gte(result *r)
{
	for (int i = 0; i < 8; i++) { xa[i] = next32(); xb[i] = next32(); }
	MEASURE(r->mul, 400, 16, mul256_gte(xr, xa, xb));
	MEASURE(r->fe, 400, 16, { fe_mul_gte(xo, xa, xb); xa[0] ^= xo[0]; });
}

static uint32_t run_keccak(void)
{
	static uint8_t msg[64], dig[32];
	uint32_t c;
	for (int i = 0; i < 64; i++) msg[i] = (uint8_t) i;
	MEASURE(c, 100, 4, { keccak256(msg, 64, dig); msg[0] ^= dig[0]; });
	return c;
}

/* ---- screen ---- */

static char lines[14][72];
static int  nlines;

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
	va_list ap;
	if (nlines >= 14) return;
	va_start(ap, fmt);
	vsnprintf(lines[nlines], sizeof lines[0], fmt, ap);
	va_end(ap);
	printf("%s\n", lines[nlines]);
	nlines++;
}

#define CLOCK 33868800u
/* a vanity candidate: a point addition (about 6 field multiplications with batched inversions) and one Keccak-256 */
static uint32_t cand_per_s(uint32_t fe, uint32_t keccak) { return (uint32_t) ((uint64_t) CLOCK / (6u * fe + keccak)); }
static uint32_t cand_per_s2(uint32_t fe, uint32_t sq, uint32_t keccak) { return (uint32_t) ((uint64_t) CLOCK / (5u * fe + sq + keccak)); }
static uint64_t ks_[25];

static void report(const char *name, const result *r)
{
	say("%s: mul %u, fe_mul %u cycles (%u us)", name, (unsigned) r->mul, (unsigned) r->fe, (unsigned) (r->fe * 10u / 339u));
	say("   vanity: %u candidates/s (6 fe_mul + keccak %u)", (unsigned) cand_per_s(r->fe, r->keccak), (unsigned) r->keccak);
}

/* the CPU optimisations: unrolled product scanning (Comba) multiplication and squaring, a one pass reduction, and the
 * straight-line Keccak (now the permutation of core/hash/keccak.c) */
static void fe_fold(uint32_t r[8], uint64_t c, uint32_t *carry_out)
{
	uint64_t t = (uint64_t) r[0] + c * 977u;
	uint64_t cc;
	r[0] = (uint32_t) t;
	cc = t >> 32;
	t = (uint64_t) r[1] + (uint32_t) c + cc;
	r[1] = (uint32_t) t;
	cc = (t >> 32) + (c >> 32);
	for (int i = 2; i < 8; i++) { t = (uint64_t) r[i] + cc; r[i] = (uint32_t) t; cc = t >> 32; }
	*carry_out = (uint32_t) cc;
}

/* like fe_reduce_wide of core/ec/secp256k1.c: the result is below 2^256, not necessarily below p */
static void reduce_weak(uint32_t r[8], const uint32_t t[16])
{
	uint64_t carry = 0, s;
	uint32_t c;
	for (int i = 0; i < 8; i++) {
		s = (uint64_t) t[i] + (uint64_t) t[8 + i] * 977u + (i ? t[8 + i - 1] : 0) + carry;
		r[i] = (uint32_t) s;
		carry = s >> 32;
	}
	carry += t[15];
	fe_fold(r, carry, &c);
	fe_fold(r, c, &c);
}

static void fe_mul_fast(uint32_t o[8], const uint32_t a[8], const uint32_t b[8]) { uint32_t r[16]; bn_mul_wide_comba(r, a, b); reduce_weak(o, r); }
static void fe_sqr_fast(uint32_t o[8], const uint32_t a[8]) { uint32_t r[16]; bn_sqr_wide_comba(r, a); reduce_weak(o, r); }

static void bench_opt(void)
{
	uint32_t m0, m1, q1, red, red0, f0, f1, s1, kk, kr, ksp, c0, c1;
	uint64_t ref[2];
	int bad = 0;

	nlines = 0;
	say("CPU optimisations (cycles per operation)");
	for (int n = 0; n < 200 && !bad; n++) {                         /* the new code against the old, on this machine */
		uint32_t r0[16], r1[16], o0[8], o1[8];
		for (int i = 0; i < 8; i++) { xa[i] = next32(); xb[i] = next32(); }
		mul256_cpu(r0, xa, xb);
		bn_mul_wide_comba(r1, xa, xb);
		bad |= memcmp(r0, r1, sizeof r0) != 0;
		mul256_cpu(r0, xa, xa);
		bn_sqr_wide_comba(r1, xa);
		bad |= memcmp(r0, r1, sizeof r0) != 0;
		reduce_p(o0, r0);
		reduce_weak(o1, r1);
		for (int i = 0; i < 8; i++) { uint32_t t[16] = {0}, u[8]; memcpy(t, o1, sizeof o1); reduce_p(u, t); bad |= u[i] != o0[i]; }
	}
	{                                                              /* the scratchpad variant against the RAM one */
		static uint64_t a1[25], a2[25];
		for (int i = 0; i < 25; i++) a1[i] = a2[i] = ((uint64_t) next32() << 32) | next32();
		keccak_f1600(a1);
		keccak_f1600_ram(a2);
		bad |= memcmp(a1, a2, sizeof a1) != 0;
	}
	(void) ref;
	if (bad) { say("CHECK FAILED: the new code differs from the old"); return; }
	say("check: same results on 200 random values");
	for (int i = 0; i < 8; i++) { xa[i] = next32(); xb[i] = next32(); }
	MEASURE(m0, 400, 16, mul256_cpu(xr, xa, xb));
	MEASURE(m1, 400, 16, bn_mul_wide_comba(xr, xa, xb));
	MEASURE(q1, 400, 16, bn_sqr_wide_comba(xr, xa));
	MEASURE(red0, 400, 16, reduce_p(xo, xr));
	MEASURE(red, 400, 16, reduce_weak(xo, xr));
	MEASURE(f0, 400, 16, { fe_mul_cpu(xo, xa, xb); xa[0] ^= xo[0]; });
	MEASURE(f1, 400, 16, { fe_mul_fast(xo, xa, xb); xa[0] ^= xo[0]; });
	MEASURE(s1, 400, 16, { fe_sqr_fast(xo, xa); xa[0] ^= xo[0]; });
	MEASURE(kk, 200, 1, keccak_f1600_ram(ks_));          /* one permutation is 80000 cycles or more: keep each batch well below 15 ms */
	MEASURE(kr, 200, 1, ref_f1600(ks_));
	MEASURE(ksp, 200, 1, keccak_f1600(ks_));
	c0 = cand_per_s2(f0, f0, kr);
	c1 = cand_per_s2(f1, s1, kk);
	say("multiply   %u -> %u (product scanning)", (unsigned) m0, (unsigned) m1);
	say("square     %u (36 products instead of 64)", (unsigned) q1);
	say("reduce     %u -> %u (one pass)", (unsigned) red0, (unsigned) red);
	say("fe_mul     %u -> %u,  fe_sqr %u", (unsigned) f0, (unsigned) f1, (unsigned) s1);
	say("keccak %u -> %u (32 bit pairs) -> %u (scratchpad)", (unsigned) kr, (unsigned) kk, (unsigned) ksp);
	say("vanity candidates/s (5 mul + 1 sqr + keccak):");
	say("   before %u, now %u, with the scratchpad Keccak %u", (unsigned) c0, (unsigned) c1, (unsigned) cand_per_s2(f1, s1, ksp));
	say("Emulator timings are rough: use a real console.");
}

static void bench_gte_parts(void)
{
	uint32_t t_split, t_conv, t_il, t_norm, t_cpu, t_full, t_full_il;

	nlines = 0;
	say("Where the GTE product spends its cycles");
	for (int i = 0; i < 8; i++) { xa[i] = next32(); xb[i] = next32(); }
	MEASURE(t_cpu, 400, 16, mul256_cpu(xr, xa, xb));
	MEASURE(t_split, 400, 16, stage_split(xa, xb));
	MEASURE(t_conv, 400, 8, stage_conv());
	MEASURE(t_il, 400, 8, stage_conv_il());
	MEASURE(t_norm, 400, 16, stage_norm(xr));
	MEASURE(t_full, 400, 8, mul256_gte(xr, xa, xb));
	MEASURE(t_full_il, 400, 8, mul256_gte_il(xr, xa, xb));
	say("CPU product (schoolbook)       %u", (unsigned) t_cpu);
	say("GTE: split into 13 bit limbs   %u", (unsigned) t_split);
	say("GTE: 56 MVMVA, results read at once   %u", (unsigned) t_conv);
	say("GTE: 56 MVMVA, CPU work overlapped    %u", (unsigned) t_il);
	say("GTE: carries and packing       %u", (unsigned) t_norm);
	say("GTE product, whole: %u, overlapped %u", (unsigned) t_full, (unsigned) t_full_il);
	say("(56 MVMVA alone need 56 x 8 = 448 cycles)");
	say("Emulator timings are rough: use a real console.");
}

/* SHA-512 compression: the plain 64 bit code against the 32 bit pair versions (loop, eight rounds unrolled) */
static void bench_sha512(void)
{
	static uint64_t h0[8], h1[8], h2[8];
	static uint8_t blk[128];
	uint32_t tref, tloop, tx8;
	int bad = 0;

	nlines = 0;
	say("SHA-512 compression of one block (cycles)");
	for (int n = 0; n < 20 && !bad; n++) {
		for (int i = 0; i < 8; i++) h0[i] = h1[i] = h2[i] = ((uint64_t) next32() << 32) | next32();
		for (int i = 0; i < 128; i++) blk[i] = (uint8_t) next32();
		ref_sha512_block(h0, blk);
		sha512_block_loop(h1, blk);
		sha512_block_x8(h2, blk);
		bad = memcmp(h0, h1, sizeof h0) || memcmp(h0, h2, sizeof h0);
	}
	if (bad) { say("CHECK FAILED: the variants differ"); return; }
	say("check: all three agree on 20 random blocks");
	MEASURE(tref, 100, 4, ref_sha512_block(h0, blk));
	MEASURE(tloop, 100, 4, sha512_block_loop(h1, blk));
	MEASURE(tx8, 100, 4, sha512_block_x8(h2, blk));
	say("plain 64 bit code   %u", (unsigned) tref);
	say("32 bit pairs, loop  %u  (%u.%02ux)", (unsigned) tloop, (unsigned) (tref * 100u / tloop / 100u), (unsigned) (tref * 100u / tloop % 100u));
	say("32 bit pairs, x8    %u  (%u.%02ux)", (unsigned) tx8, (unsigned) (tref * 100u / tx8 / 100u), (unsigned) (tref * 100u / tx8 % 100u));
	say("PBKDF2 2048 rounds = 4096 blocks: plain %u ms, loop %u ms, x8 %u ms",
	    (unsigned) ((uint64_t) 4096 * tref * 1000u / CLOCK), (unsigned) ((uint64_t) 4096 * tloop * 1000u / CLOCK),
	    (unsigned) ((uint64_t) 4096 * tx8 * 1000u / CLOCK));
	say("Emulator timings are rough: use a real console.");
}

static void bench(int with_gte)
{
	result c, g;
	int bad;

	nlines = 0;
	say("256 bit field multiplication (secp256k1 p)");
	c.keccak = g.keccak = run_keccak();
	run_cpu(&c);
	report("CPU", &c);
	if (with_gte) {
		bad = selftest(300);
		if (bad) {
			say("CHECK FAILED (pair %d): the GTE product differs", bad);
			return;
		}
		say("check: CPU = GTE on 300 pairs, (p-1)^2 = 1");
		run_gte(&g);
		report("GTE", &g);
		say("speed-up: product %u.%02ux, fe_mul %u.%02ux", (unsigned) (c.mul * 100u / g.mul / 100u),
		    (unsigned) (c.mul * 100u / g.mul % 100u), (unsigned) (c.fe * 100u / g.fe / 100u), (unsigned) (c.fe * 100u / g.fe % 100u));
		say("(below 1.00x: the GTE is slower)");
	}
	say("Emulator timings are rough: use a real console.");
}

int main(void)
{
	int last_frame = -1, mode = 0;                  /* 0 menu, 1 run CPU, 2 run both, 3 results */
	int pending = 0;

	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	__asm__ volatile("mfc0 $8, $12\n lui $9, 0x4000\n or $8, $8, $9\n mtc0 $8, $12\n nop\n nop" ::: "$8", "$9");   /* enable COP2 (the GTE) */
	nlines = 0;

	for (;;) {
		input_poll(&in, NULL);
		int f = VSync(-1);
		if (f == last_frame) continue;
		last_frame = f;
		uint16_t pr = input_take_pressed(&in);

		if (mode == 0) {
			font_draw(&ctx, 0, 16, 16, "256 bit multiplication benchmark", 255, 255, 255);
			font_draw(&ctx, 0, 16, 56, ICO_CROSS " CPU only", 255, 220, 80);
			font_draw(&ctx, 0, 16, 86, ICO_SQUARE " CPU and GTE, compared", 255, 220, 80);
			font_draw(&ctx, 0, 16, 146, ICO_CIRCLE " GTE: where the cycles go", 255, 220, 80);
			font_draw(&ctx, 0, 16, 176, ICO_L1 " SHA-512 block (plain / loop / x8)", 255, 220, 80);
			font_draw(&ctx, 0, 16, 116, ICO_TRIANGLE " CPU optimisations (before / after)", 255, 220, 80);
			if (pr & PAD_CROSS) { mode = 1; pending = 2; }
			if (pr & PAD_SQUARE) { mode = 2; pending = 2; }
			if (pr & PAD_TRIANGLE) { mode = 4; pending = 2; }
			if (pr & PAD_CIRCLE) { mode = 5; pending = 2; }
			if (pr & PAD_L1) { mode = 6; pending = 2; }
		} else if (pending) {
			font_draw(&ctx, 0, 16, 16, "Running...", 255, 220, 80);
			if (--pending == 0) {
				if (mode == 6) bench_sha512();
				else if (mode == 5) {
					if (selftest(300)) { nlines = 0; say("CHECK FAILED: the GTE products differ"); }
					else bench_gte_parts();
				}
				else if (mode == 4) bench_opt();
				else bench(mode == 2);
				mode = 3;
			}
		} else {
			for (int i = 0; i < nlines; i++) font_draw(&ctx, 0, 8, 6 + i * 22, lines[i], i == 0 ? 255 : 220, i == 0 ? 255 : 230, 255);
			font_draw(&ctx, 0, 8, ctx.yres - 24, ICO_SELECT " menu", 150, 160, 200);
			if (pr & PAD_SELECT) mode = 0;
		}
		gpu_present(&ctx);
	}
	return 0;
}
