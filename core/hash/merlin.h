#pragma once
#include <stddef.h>
#include <stdint.h>

/* Merlin transcripts (STROBE-128 over Keccak-f[1600]), the way Schnorrkel uses them. The state is little-endian lanes,
 * so the byte view below is the lane memory on a little-endian CPU (the PlayStation, x86). */
typedef struct {
    uint64_t st[25];
    uint8_t  pos, pos_begin, cur_flags;
} merlin;

/* New transcript with the domain label (Transcript::new). */
void merlin_init(merlin *m, const char *label);
/* append_message(label, message) */
void merlin_append(merlin *m, const char *label, const uint8_t *msg, size_t len);
/* challenge_bytes(label, out[len]) */
void merlin_challenge(merlin *m, const char *label, uint8_t *out, size_t len);
