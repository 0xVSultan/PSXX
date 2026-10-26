#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t h[8];
    uint8_t  buf[128];
    uint64_t len;       /* message length in bytes (low 64 bits; messages < 2^61 B) */
    uint32_t fill;
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *msg, size_t len);
void sha512_final(sha512_ctx *c, uint8_t out[64]);
void sha512(const uint8_t *msg, size_t len, uint8_t out[64]);

void hmac_sha512(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[64]);

/* PBKDF2-HMAC-SHA512 (BIP39 uses 2048 iterations, 64 byte output). */
void pbkdf2_hmac_sha512(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                        uint32_t iterations, uint8_t *out, size_t outlen);
/* The same with a progress callback every 1024 iterations: it gets (done, total) and returns nonzero to cancel; the call
 * then returns -1 (the output is not valid). Returns 0 when finished. */
typedef int (*pbkdf2_progress_fn)(uint32_t done, uint32_t total, void *user);
int pbkdf2_hmac_sha512_cb(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                          uint32_t iterations, uint8_t *out, size_t outlen, pbkdf2_progress_fn cb, void *user);

/* The compression function on the state h (little endian 64 bit words) for one 128 byte block; the two variants of
 * sha512_fast.c (loop / eight rounds unrolled), sha512_block_fast is the one the library uses. */
void sha512_block_fast(uint64_t h[8], const uint8_t *p);
void sha512_block_loop(uint64_t h[8], const uint8_t *p);
void sha512_block_x8(uint64_t h[8], const uint8_t *p);
/* One PBKDF2-HMAC-SHA512 step: u = HMAC(key, u), u (the 64 byte message and the result) as eight 64 bit words, with the HMAC
 * midstates of the key (the state after the block key ^ ipad, key ^ opad). */
void sha512_hmac64(const uint64_t istate[8], const uint64_t ostate[8], uint64_t u[8]);
