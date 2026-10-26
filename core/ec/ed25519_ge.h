#pragma once
#include <stddef.h>
#include <stdint.h>

/* The group of Ed25519 for protocols that need more than RFC 8032 signatures (Monero: key images, CLSAG, Pedersen commitments).
 * Points in extended coordinates; encoding as in RFC 8032. All scalars are 32 byte little-endian values below the group order. */

typedef uint32_t ed_fe[8];
typedef struct { ed_fe X, Y, Z, T; } ed_ge;

/* 0, or -1 when the bytes are not a point on the curve */
int  ed_ge_decode(ed_ge *p, const uint8_t in[32]);
void ed_ge_encode(uint8_t out[32], const ed_ge *p);
void ed_ge_identity(ed_ge *p);
void ed_ge_add(ed_ge *r, const ed_ge *p, const ed_ge *q);      /* r may alias p or q */
void ed_ge_neg(ed_ge *r, const ed_ge *p);
void ed_ge_sub(ed_ge *r, const ed_ge *p, const ed_ge *q);
void ed_ge_mul8(ed_ge *r, const ed_ge *p);
int  ed_ge_is_identity(const ed_ge *p);
int  ed_ge_equal(const ed_ge *p, const ed_ge *q);

/* r = k * p, constant time (secret k); all 256 bits of k are used */
void ed_ge_mul(ed_ge *r, const ed_ge *p, const uint8_t k[32]);
/* r = k * B with the table of the base point (built on first use) */
void ed_ge_mul_base(ed_ge *r, const uint8_t k[32]);
/* r = k1 * p1 + k2 * p2, NOT constant time: only for public scalars */
void ed_ge_mul2_vt(ed_ge *r, const uint8_t k1[32], const ed_ge *p1, const uint8_t k2[32], const ed_ge *p2);

/* Monero's hash to point: ge_fromfe_frombytes_vartime (Elligator 2) of the 32 byte hash h, multiplied by the cofactor 8.
 * Hp(P) of key images is this with h = keccak256(P). */
void ed_hash_to_point(ed_ge *r, const uint8_t h[32]);

/* r = a - b, r = -a (mod the group order) */
void ed25519_sc_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);
