#pragma once
#include <stddef.h>
#include <stdint.h>

/* BLAKE3, the 32 byte hash of a message of at most 1024 bytes (one chunk: no tree, no key). Used by Litecoin MWEB, whose
 * hashes are all short. Returns 0, or -1 for a longer message. */
int blake3_hash(uint8_t out[32], const uint8_t *in, size_t len);
