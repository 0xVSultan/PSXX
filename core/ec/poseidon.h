#pragma once
#include <stdint.h>

/* Poseidon over the Pallas base field as Orchard uses it (P128Pow5T3: width 3, x^5, 8 full + 56 partial rounds), for the nullifier PRF.
 * Field elements are 32 byte little-endian values below the prime. */

/* the permutation, in place */
void poseidon_perm(uint8_t st[3][32]);
/* hash(x, y) = perm([x, y, 2^65])[0] (ConstantLength<2>) */
void poseidon_hash2(uint8_t out[32], const uint8_t x[32], const uint8_t y[32]);
