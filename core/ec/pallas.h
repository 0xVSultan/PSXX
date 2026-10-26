#pragma once
#include <stddef.h>
#include <stdint.h>

/* The Pallas curve y^2 = x^3 + 5 over Fp, p = 2^254 + 45560315531419706090280762371685220353 (Zcash Orchard), with the
 * group hash of ZIP-224 / the hash-to-curve draft (BLAKE2b, simplified SWU on the 3-isogenous curve) and the point
 * encoding used by Orchard: the x coordinate, 32 bytes little-endian, with bit 255 = the parity of y.
 * Points are complete projective (Renes-Costello-Batina), so scalar multiplication has no data dependent branches. */

typedef uint32_t pl_fp[8];                  /* a field element, Montgomery form, < p */
typedef struct { pl_fp X, Y, Z; } pl_pt;    /* x = X/Z, y = Y/Z; the identity is (0 : 1 : 0) */

void pl_identity(pl_pt *p);
/* a point from its affine coordinates, 32 bytes little-endian each (must be on the curve) */
void pl_from_affine(pl_pt *p, const uint8_t x[32], const uint8_t y[32]);
/* r = a + b, r = 2a (complete: any inputs). r may alias an input. */
void pl_add(pl_pt *r, const pl_pt *a, const pl_pt *b);
void pl_dbl(pl_pt *r, const pl_pt *a);
/* r = k * a for the scalar k (32 bytes little-endian, any value below 2^256), constant time. */
void pl_mul(pl_pt *r, const pl_pt *a, const uint8_t k[32]);

/* Orchard encoding of a point: 32 bytes (the identity is all zero). Needs one inversion. */
void pl_encode(uint8_t out[32], const pl_pt *p);
/* Decode (the inverse); returns 0, or -1 if the bytes are not a point. */
int  pl_decode(pl_pt *p, const uint8_t in[32]);
/* The affine x coordinate as 32 bytes little-endian (0 for the identity). */
void pl_x_bytes(uint8_t out[32], const pl_pt *p);

/* GroupHash^P(domain, msg) of the Orchard protocol (ZIP-224): hash to curve with the DST
 * domain || "-pallas_XMD:BLAKE2b_SSWU_RO_". */
void pl_group_hash(pl_pt *out, const uint8_t *domain, size_t dlen, const uint8_t *msg, size_t mlen);
/* The same for the fixed generators (Orchard has a handful: the spend authorization base, the nullifier base, the Q and R points of the
 * commitments): a hash to curve costs about 100 ms on the PSX, so the result is kept (domain and message of at most 32 bytes each; up to
 * 8 different ones; a longer or ninth one is simply computed every time). */
void pl_group_hash_cached(pl_pt *out, const uint8_t *domain, size_t dlen, const uint8_t *msg, size_t mlen);

/* n group hashes with the same domain; the n messages of mlen bytes each follow one another in msgs. Same results as n calls of
 * pl_group_hash, but the field inversions are shared (much cheaper). */
void pl_group_hash_batch(pl_pt *out, size_t n, const uint8_t *domain, size_t dlen, const uint8_t *msgs, size_t mlen);

/* Reduce 64 little-endian bytes modulo the scalar field order q (32 byte result) or the field prime p (32 bytes, plain). */
void pl_reduce_scalar(uint8_t out[32], const uint8_t in[64]);
void pl_reduce_base(uint8_t out[32], const uint8_t in[64]);
/* 32 byte little-endian value (< p) mod q, and q - x for x < q. */
void pl_scalar_from_base(uint8_t out[32], const uint8_t in[32]);

/* The constants and tables of the hash-to-curve are set up on first use, or in advance with this: every call does a part of the work
 * and returns the progress in percent, 100 when done. */
int pallas_table_step(void);

/* Arithmetic modulo the scalar order q on 32 byte little-endian values below q: out = a + b, a * b, -a (out may alias an input). */
void pl_sc_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
void pl_sc_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);
void pl_sc_neg(uint8_t out[32], const uint8_t a[32]);

/* Field elements of the base field for Poseidon: from / to 32 bytes little-endian (Montgomery form inside), a + b, a * b, a^2. */
void pl_fp_from_le(pl_fp r, const uint8_t in[32]);
void pl_fp_to_le(uint8_t out[32], const pl_fp a);
void pl_fp_add(pl_fp r, const pl_fp a, const pl_fp b);
void pl_fp_mul(pl_fp r, const pl_fp a, const pl_fp b);
void pl_fp_sqr(pl_fp r, const pl_fp a);

/* The table of the 1024 Sinsemilla points S_j = GroupHash("z.cash:SinsemillaS", j), built in the background: pl_stable_step() does about
 * `ops` field multiplications of the work (a multiplication is about 0.1 ms on the PSX; the whole table is about 800 000 of them) and
 * returns the number of points in the table (1024 when complete); pl_stable_get() gives point j (x, y: 32 bytes little-endian each) when it
 * is there (0), else -1. The points may come in any order (pl_stable_add): the builder skips the groups of 16 that are complete. 64 KB of RAM. */
void pl_stable_reset(void);
int  pl_stable_step(int ops);
int  pl_stable_built(void);
int  pl_stable_get(unsigned j, uint8_t xy[64]);
/* put points computed elsewhere into the table: n <= 16 projective points, their indices j[] (affine conversion with one inversion) */
void pl_stable_add(const unsigned *j, const pl_pt *p, size_t n);

/* the affine coordinates of a point, 32 bytes little-endian each (one inversion) */
void pl_to_affine_le(uint8_t x[32], uint8_t y[32], const pl_pt *p);
