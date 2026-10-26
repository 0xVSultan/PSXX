#pragma once
#include <stddef.h>
#include <stdint.h>

void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]);
/* Bitcoin HASH160 = RIPEMD160(SHA256(x)) */
void hash160(const uint8_t *msg, size_t len, uint8_t out[20]);
