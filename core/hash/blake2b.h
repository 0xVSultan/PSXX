#pragma once
#include <stddef.h>
#include <stdint.h>

/* BLAKE2b (RFC 7693) with the parameter block fields that the coins and Argon2 use: digest length 1..64, key, salt and
 * personalization (16 bytes each, NULL = zeros). Used for Cardano (224 bit), SS58 (512 bit), Zcash (personalized). */
typedef struct {
    uint64_t h[8];
    uint64_t t0, t1;
    uint8_t  buf[128];
    uint32_t fill, outlen;
} blake2b_ctx;

/* Returns 0, or -1 for a bad digest or key length. */
int  blake2b_init(blake2b_ctx *c, size_t outlen, const uint8_t *key, size_t keylen, const uint8_t *salt16,
                  const uint8_t *person16);
void blake2b_update(blake2b_ctx *c, const uint8_t *in, size_t len);
void blake2b_final(blake2b_ctx *c, uint8_t *out);
/* One shot, unkeyed. */
void blake2b(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
