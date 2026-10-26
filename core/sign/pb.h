#pragma once
/* A minimal protobuf reader (wire format only): Tron, Cosmos and the like. */
#include <stddef.h>
#include <stdint.h>

typedef struct { const uint8_t *p, *end; } pb_reader;

static inline void pb_init(pb_reader *r, const uint8_t *p, size_t n) { r->p = p; r->end = p + n; }

int pb_varint(pb_reader *r, uint64_t *v);

/* The next field. Returns 1 for a field, 0 at the end, -1 for an error. For wire type 0 the value is in *v; for 2 (bytes, string,
 * message) *data / *dlen; for 1 and 5 the fixed value is in *v. */
int pb_next(pb_reader *r, uint32_t *field, int *wt, uint64_t *v, const uint8_t **data, size_t *dlen);

/* the varint encoding of v; returns the bytes written */
static inline size_t pb_put_varint(uint8_t *o, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) { o[n++] = (uint8_t) (v | 0x80); v >>= 7; }
    o[n++] = (uint8_t) v;
    return n;
}
