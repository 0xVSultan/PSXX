#include "sign/pb.h"

int pb_varint(pb_reader *r, uint64_t *v)
{
    uint64_t x = 0;
    for (int i = 0; i < 10; i++) {
        if (r->p >= r->end) return -1;
        uint8_t b = *r->p++;
        x |= (uint64_t) (b & 0x7f) << (7 * i);
        if (!(b & 0x80)) { *v = x; return 0; }
    }
    return -1;
}

int pb_next(pb_reader *r, uint32_t *field, int *wt, uint64_t *v, const uint8_t **data, size_t *dlen)
{
    uint64_t tag, len;
    if (r->p >= r->end) return 0;
    if (pb_varint(r, &tag)) return -1;
    *field = (uint32_t) (tag >> 3);
    *wt = (int) (tag & 7);
    *data = NULL; *dlen = 0; *v = 0;
    switch (*wt) {
    case 0: return pb_varint(r, v) ? -1 : 1;
    case 1: if (r->end - r->p < 8) return -1; for (int i = 0; i < 8; i++) *v |= (uint64_t) r->p[i] << (8 * i); r->p += 8; return 1;
    case 5: if (r->end - r->p < 4) return -1; for (int i = 0; i < 4; i++) *v |= (uint64_t) r->p[i] << (8 * i); r->p += 4; return 1;
    case 2:
        if (pb_varint(r, &len) || (uint64_t) (r->end - r->p) < len) return -1;
        *data = r->p; *dlen = (size_t) len; r->p += len;
        return 1;
    default: return -1;
    }
}
