#pragma once
#include <stddef.h>
#include <stdint.h>

/* Blockchain Commons UR (uniform resources, BCR-2020-005 / BCR-2020-012) for the generic type "ur:bytes":
 * the payload is the CBOR byte string of the data, written as minimal bytewords (first and last letter of the word of
 * every byte, CRC-32 appended).  A payload that fits one part is "ur:bytes/<bytewords>"; a longer one is split into
 * equal fragments "ur:bytes/<seq>-<parts>/<bytewords of CBOR [seq, parts, length, crc32, fragment]>" for an animated
 * QR code.  Only the pure fragments 1..parts are produced (the encoder just starts over; a receiver collects every
 * fragment once, so no mixed fountain fragments are needed).  No heap, no libc. */

typedef struct {
	size_t   data_len;     /* bytes given by the caller */
	size_t   cbor_len;     /* length of the whole message (CBOR byte string header + data) */
	size_t   frag_len;     /* bytes per fragment (the last one is zero padded) */
	unsigned parts;        /* number of fragments, 1 = single part */
	uint32_t crc;          /* CRC-32 of the whole message */
} ur_plan;

uint32_t ur_crc32(const uint8_t *p, size_t n);

/* `max_frag`: most message bytes per fragment (a part text is about 2 * max_frag + 40 characters).
 * Returns the number of parts, or -1 for empty data or max_frag < 8. */
int ur_plan_make(ur_plan *p, const uint8_t *data, size_t n, size_t max_frag);

/* Characters of the longest part text (without the 0). */
size_t ur_part_chars(const ur_plan *p);

/* Text of part `seq` (1, 2, ...; wraps around after `parts`) into out. Returns its length, or -1 if cap is too small. */
int ur_part(const ur_plan *p, const uint8_t *data, unsigned seq, char *out, size_t cap);

/* Decoding of a single bytewords payload back to bytes, used by the tests and by the self-check: returns the length,
 * or -1 if the text is not valid minimal bytewords with a correct CRC. */
int ur_bytewords_decode(const char *s, size_t n, uint8_t *out, size_t cap);
