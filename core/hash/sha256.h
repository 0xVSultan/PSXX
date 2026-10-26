#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t len;
    uint32_t fill;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *msg, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]);

/* BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data...). Start it with the tag, then update and final as usual. */
void sha256_tagged_init(sha256_ctx *c, const char *tag);
