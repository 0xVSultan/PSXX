#pragma once
#include <stdint.h>

/* Ed25519 group and scalar helpers. Secret-dependent paths are constant time.
 * Scalars and points are 32 byte little-endian, as in RFC 8032 / Monero. */

/* RFC 8032 public key from a 32 byte seed (SHA-512, clamp, scalar multiplication). */
void ed25519_pubkey_from_seed(uint8_t pub[32], const uint8_t seed[32]);

/* out = encode(scalar * B) with the scalar used as is (no clamping): Monero's ge_scalarmult_base. */
void ed25519_scalarmult_base(uint8_t out[32], const uint8_t scalar[32]);

/* Scalars modulo the group order L = 2^252 + 27742317777372353535851937790883648493. */
void ed25519_sc_reduce32(uint8_t s[32]);                          /* in place */
void ed25519_sc_reduce64(uint8_t out[32], const uint8_t in[64]);
void ed25519_sc_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);   /* a, b < L */
/* Monero subaddress keys: D = B + m*G, C = a*D (B the 32 byte encoded spend public key, m and a scalars < L).
 * Returns -1 if B is not a valid point. Constant time in a and m. */
int ed25519_subaddress_keys(uint8_t D[32], uint8_t C[32], const uint8_t B[32], const uint8_t a[32], const uint8_t m[32]);
void ed25519_sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]);

/* Ristretto255 encoding of scalar * B (the Ristretto basepoint is the Ed25519 one); scalar as is, 32 byte little-endian.
 * This is the public key of Schnorrkel / sr25519 (Polkadot). */
void ed25519_ristretto_basemul(uint8_t out[32], const uint8_t scalar[32]);

/* The fixed base table of ed25519_scalarmult_base (33 KB of RAM) is built on first use, or in advance with this: every call does a
 * few milliseconds of work and returns the progress in percent, 100 when the table is ready. Call it after the secp256k1 table
 * is ready (they share a work area). */
int ed25519_table_step(void);

/* ---- signing (core/ec/ed25519_sign.c) ---- */
#include <stddef.h>
/* RFC 8032 signature (64 bytes) of a message of any length with a 32 byte seed. */
void ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *msg, size_t len);
/* The same with the expanded key: the scalar a (little-endian, used as is, e.g. the clamped half of the SHA-512 of a seed, or the
 * kL of a Cardano BIP32-Ed25519 key), the 32 byte nonce prefix (the other half; kR for Cardano) and the public key a * B. */
void ed25519_sign_scalar(uint8_t sig[64], const uint8_t a[32], const uint8_t prefix[32], const uint8_t pub[32], const uint8_t *msg, size_t len);
