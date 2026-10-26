#pragma once
#include <stddef.h>
#include <stdint.h>

/* secp256k1 (y^2 = x^3 + 7). Secret-dependent paths are constant time. Keys are 32 byte big-endian. */

/* 1 if 1 <= k < n, else 0. */
int secp256k1_privkey_verify(const uint8_t k[32]);
/* Compressed (33 B, 02/03||x) public key. Returns 0, or -1 if the key is invalid. */
int secp256k1_pubkey_create(uint8_t out[33], const uint8_t priv[32]);
/* Uncompressed (65 B, 04||x||y) public key. */
int secp256k1_pubkey_create_uncompressed(uint8_t out[65], const uint8_t priv[32]);
/* key = (key + tweak) mod n  (BIP32 child key). Returns 0, or -1 if tweak >= n or the result is 0 (key unchanged). */
int secp256k1_privkey_tweak_add(uint8_t key[32], const uint8_t tweak[32]);

/* key = key * factor mod n (a product of two secret keys: the MWEB scan key of an address). Returns 0, or -1 if factor is not in
 * 1 .. n-1 or the result is 0 (key unchanged). */
int secp256k1_privkey_mul(uint8_t key[32], const uint8_t factor[32]);

/* The fixed base table of secp256k1_pubkey_create* (33 KB of RAM) is built on first use (about a second on a PSX), or in
 * advance with this: every call does a few milliseconds of work and returns the progress in percent, 100 when the table is
 * ready (and from then on). Lets a start screen show a progress bar. */
int secp256k1_table_step(void);

/* Affine public point (x, y big endian) of a private key. Returns 0, or -1 if the key is not in 1 .. n-1. */
int secp256k1_pubkey_xy(uint8_t x[32], uint8_t y[32], const uint8_t priv[32]);

/* ---- signing (core/ec/secp256k1_sign.c) ---- */
/* ECDSA over a 32 byte hash with the deterministic nonce of RFC 6979 (HMAC-SHA256), low S (s <= n/2) like libsecp256k1.
 * sig = r || s (64 B, big endian); *recid (may be NULL) is the recovery id 0..3 (bit 0: y of R odd, bit 1: x >= n).
 * Returns 0, or -1 for a bad key. */
int secp256k1_ecdsa_sign(uint8_t sig[64], int *recid, const uint8_t priv[32], const uint8_t hash[32]);
/* The DER encoding of r || s (at most 72 bytes); returns the length. */
int secp256k1_sig_to_der(uint8_t *der, const uint8_t sig[64]);
/* BIP340 Schnorr signature over a 32 byte message; aux is 32 bytes of auxiliary randomness or NULL (zeros). Returns 0 or -1. */
int secp256k1_schnorr_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t msg[32], const uint8_t *aux);
/* BIP340 verification of a signature over a 32 byte message against an x only public key. Returns 0 if it is valid, else -1. Estimated 0.2 seconds on a PSX (two double-and-add multiplications, not measured on hardware). */
int secp256k1_schnorr_verify(const uint8_t sig[64], const uint8_t msg[32], const uint8_t pub[32]);
/* x only public key (BIP340) of a private key; *odd (may be NULL) tells whether the y of the key is odd. */
int secp256k1_xonly_pubkey(uint8_t x[32], int *odd, const uint8_t priv[32]);
/* BIP341 key path: the private key of the output key Q = P + t G, t = TapTweak(P.x || merkle) (merkle_len 0 or 32). Returns 0,
 * or -1 for a bad key. The x only key of out is Q. */
int secp256k1_taproot_tweak_seckey(uint8_t out[32], const uint8_t priv[32], const uint8_t *merkle, size_t merkle_len);

/* ---- the field arithmetic modulo p for code outside secp256k1.c (the vanity search, core/ec/secp_van.c). Values are weak (< 2^256), secp_fe_norm reduces fully. ---- */
void secp_fe_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
void secp_fe_sqr(uint32_t r[8], const uint32_t a[8]);
void secp_fe_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
void secp_fe_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
void secp_fe_mul_small(uint32_t r[8], const uint32_t a[8], uint32_t k);
void secp_fe_inv(uint32_t r[8], const uint32_t a[8]);
void secp_fe_norm(uint32_t a[8]);
