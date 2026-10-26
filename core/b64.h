#pragma once
#include <stddef.h>
#include <stdint.h>

/* Standard Base64 (RFC 4648, with '=' padding). The decoder ignores spaces and line breaks. */

/* Returns the length of the text (without the terminating 0), or -1 if `cap` is too small (needs 4 * ceil(n / 3) + 1). */
int b64_encode(const uint8_t *in, size_t n, char *out, size_t cap);
/* Returns the number of bytes, or -1 for an invalid character, bad padding or a too small buffer. */
int b64_decode(const char *in, uint8_t *out, size_t cap);
