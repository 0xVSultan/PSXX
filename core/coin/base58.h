#pragma once
#include <stddef.h>
#include <stdint.h>

/* Bitcoin Base58. Return length of the string written (without NUL), or -1 if `outcap` is too small. */
int base58_encode(const uint8_t *in, size_t len, char *out, size_t outcap);
/* Base58Check: payload + first 4 bytes of double-SHA256 appended. */
int base58check_encode(const uint8_t *payload, size_t len, char *out, size_t outcap);

/* Monero Base58: 8 byte blocks -> 11 chars, last block padded by its own table. */
int base58_monero_encode(const uint8_t *in, size_t len, char *out, size_t outcap);
