#pragma once
/* HKDF-SHA256 (RFC 5869) and the encrypted blob used for texts now and for the Token2 key backup later.
 *
 * Blob layout (all integers big endian):
 *   "PSXT" | ver u8 (1) | kdf u8 | flags u8 | 0 u8 | iter u32 | salt[16] | nonce[12] | clen u16 | ciphertext | tag[16]
 *   kdf 1 = PBKDF2-HMAC-SHA512 over the password (iter rounds); flags bit 0 = a second secret (the 32 byte FIDO2
 *   hmac-secret output of a Token2 key) went into the key as well.
 * Key:  K = HKDF-SHA256(salt, ikm = [extra secret] || kdf output, info = "psx-blob-v1"), AES-256-GCM, the 42 header bytes
 * are the additional data, so nothing in the header can be changed without the tag failing.
 *
 * `rnd` (28 bytes: salt then nonce) must be fresh random data from the entropy pool; every blob gets its own key. */
#include <stddef.h>
#include <stdint.h>

#define BLOB_HDR 42
#define BLOB_TAG 16
#define BLOB_OVERHEAD (BLOB_HDR + BLOB_TAG)
#define BLOB_FLAG_EXTRA 1
#define BLOB_ITER_DEFAULT 4096
#define BLOB_ITER_TEXT 8192               /* text encryption of the generator */
#define BLOB_ITER_KEY 16384               /* key files of the key stores */
#define BLOB_ITER_MAX 1000000             /* a file that asks for more is refused (the count is read before the tag can be checked): about 15 minutes on the console */

void hkdf_sha256(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen, const uint8_t *info, size_t infolen,
                 uint8_t *out, size_t olen);

/* The PBKDF2 rounds a blob asks for (0 if it is not a blob): to tell the user how long opening it will take (about 0.9 ms a round on the console). */
uint32_t blob_iterations(const uint8_t *blob, size_t len);

/* Returns the blob length, or -1 (bad arguments / buffer too small). `extra` may be NULL (extralen 0 or 32). */
int blob_seal(const uint8_t *pw, size_t pwlen, const uint8_t *extra, size_t extralen, uint32_t iter, const uint8_t rnd[28],
              const uint8_t *pt, size_t ptlen, uint8_t *out, size_t outcap);
/* Returns the plaintext length, -1 for a malformed blob, -2 if the password / secret is wrong or the blob was changed. */
int blob_open(const uint8_t *pw, size_t pwlen, const uint8_t *extra, size_t extralen, const uint8_t *blob, size_t len,
              uint8_t *pt, size_t ptcap);
