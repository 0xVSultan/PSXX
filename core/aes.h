#pragma once
/* AES (128/192/256) with the modes the project needs, portable C without heap and without data dependent branches.
 *
 *  - raw block encrypt / decrypt, ECB-free: the modes below are the only intended users;
 *  - CBC without padding, any IV, in place allowed: this is exactly what CTAP2 PIN protocol 1 (zero IV) and 2 (random
 *    IV in front of the ciphertext) and the hmac-secret extension use, so the same code serves the Token2 keys later;
 *  - CTR with a 32 bit big endian counter (the GCM counter);
 *  - GCM with a 96 bit nonce and a 128 bit tag (also what CTAP 2.1 large blobs use).
 *
 * The S-box is computed at first use (no 512 byte tables in the image). Table look-ups indexed by secret bytes are
 * used; the R3000 has no data cache, so they take constant time on the target, but a host build is not hardened
 * against cache timing. */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t rk[240];          /* round keys, 16 bytes each */
    int     rounds;           /* 10, 12 or 14 */
} aes_ctx;

/* keybits: 128, 192 or 256. Returns 0, or -1 for another size. */
int  aes_init(aes_ctx *c, const uint8_t *key, int keybits);
void aes_wipe(aes_ctx *c);

void aes_encrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* CBC, `len` a multiple of 16 (no padding is added or removed). `in` and `out` may be the same buffer. */
void aes_cbc_encrypt(const aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);
void aes_cbc_decrypt(const aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);

/* CTR: XOR the key stream into `in`; `ctr` is the first counter block and is advanced (last 4 bytes, big endian). */
void aes_ctr_xor(const aes_ctx *c, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t len);

/* GCM with a 12 byte nonce. Encrypt writes `len` bytes of ciphertext and a 16 byte tag. */
void aes_gcm_encrypt(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *ct, uint8_t tag[16]);
/* Returns 0 and the plaintext if the tag is valid, -1 (and a zeroed output) if not. */
int  aes_gcm_decrypt(const aes_ctx *c, const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt);
