#pragma once
#include <stddef.h>
#include <stdint.h>

/* The two encryptions of Nostr direct messages.
 *
 * NIP-44 (version 2): the conversation key is HKDF-extract(salt "nip44-v2", ECDH x). A message gets a 32 byte nonce; HKDF-expand(conversation key, nonce, 76) gives the ChaCha20 key (32),
 * the ChaCha20 nonce (12) and the HMAC key (32). The text is padded (2 bytes of length, then zeros to the padded length), encrypted with ChaCha20 (counter 0) and authenticated with
 * HMAC-SHA256 over nonce || ciphertext. The message is base64(0x02 || nonce || ciphertext || mac).
 *
 * NIP-04 (old): AES-256-CBC with PKCS#7 padding, the key is the ECDH x itself, no authentication; the message is base64(ciphertext) "?iv=" base64(iv).
 *
 * The work buffers are the caller's (a signer has little stack). A message is at most NIP_PT_MAX bytes of text; the base64 text of it at most NIP_B64_MAX characters. A request
 * of the signer is one card block (7936 bytes), which is why 4096 bytes is also about the most a request can carry. */
#define NIP_PT_MAX 4096
#define NIP_B64_MAX 5552
#define NIP44_WORK (1 + 32 + 2 + NIP_PT_MAX + 32 + 64)          /* work buffer of nip44_encrypt and nip44_decrypt */
#define NIP04_WORK (NIP_PT_MAX + 32)

enum { NIP_OK = 0, NIP_ERR_ARG = -1, NIP_ERR_SIZE = -2, NIP_ERR_MAC = -3, NIP_ERR_FORMAT = -4, NIP_ERR_KEY = -5 };

/* The conversation key of NIP-44 from our private key and the other side's x only public key. */
int nip44_conv_key(uint8_t ck[32], const uint8_t priv[32], const uint8_t pub[32]);
/* Encrypt len bytes; `out` gets the base64 text. pt may be work + 35 (in place). Returns its length, or a NIP_ERR_ code. */
int nip44_encrypt(char *out, size_t cap, uint8_t *work, const uint8_t ck[32], const uint8_t nonce[32], const uint8_t *pt, size_t len);
/* Decrypt: the text is left in work at *pt (not terminated); returns its length, or a NIP_ERR_ code. work may be the payload itself (decoded in place; the payload is lost). */
int nip44_decrypt(const uint8_t **pt, uint8_t *work, const uint8_t ck[32], const char *payload);

/* The key of NIP-04: the ECDH x. */
int nip04_key(uint8_t key[32], const uint8_t priv[32], const uint8_t pub[32]);
int nip04_encrypt(char *out, size_t cap, uint8_t *work, const uint8_t key[32], const uint8_t iv[16], const uint8_t *pt, size_t len);
int nip04_decrypt(const uint8_t **pt, uint8_t *work, const uint8_t key[32], char *payload);       /* with work = payload it is decoded in place */
