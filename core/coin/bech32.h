#pragma once
#include <stddef.h>
#include <stdint.h>

/* Encode 5-bit `data` with human readable part `hrp`. m = 1 selects bech32m. Returns length or -1. */
int bech32_encode(char *out, size_t outcap, const char *hrp, const uint8_t *data5, size_t n5, int m);
/* Regroup bits (8->5 with pad=1, 5->8 with pad=0). Returns number of output values, or -1. */
int bech32_convert_bits(uint8_t *out, size_t outcap, const uint8_t *in, size_t inlen, int frombits, int tobits, int pad);
/* SegWit address: witness version 0..16 and program bytes. Returns length or -1. */
int segwit_addr_encode(char *out, size_t outcap, const char *hrp, int witver, const uint8_t *prog, size_t proglen);
