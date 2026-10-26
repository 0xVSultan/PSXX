#pragma once
#include <stddef.h>
#include <stdint.h>

/* ChaCha20-Poly1305 (RFC 8439), with no additional data. The ciphertext carries the 16 byte tag at its end. Used by the Zcash note
 * encryption (nonce all zero). */

/* out: ctlen - 16 bytes. Returns 0, or -1 when the tag is wrong (nothing is written then). */
int chacha20poly1305_decrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ct, size_t ctlen);
/* out: len + 16 bytes. */
void chacha20poly1305_encrypt(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *in, size_t len);
/* The bare ChaCha20 stream (RFC 8439) xored into in (out may be the same buffer): the first block has the counter `counter`. NIP-44 uses it with counter 0. */
void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]);
