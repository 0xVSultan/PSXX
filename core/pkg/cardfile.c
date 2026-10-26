#include "cardfile.h"
#include <string.h>
#include "tr.h"

static unsigned rd16(const uint8_t *p) { return p[0] | ((unsigned) p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | ((uint32_t) rd16(p + 2) << 16); }

static int xor_ok(const uint8_t *e)
{
    uint8_t x = 0;
    for (int i = 0; i < CF_FRAME - 1; i++) x ^= e[i];
    return x == e[CF_FRAME - 1];
}

static int name_is(const uint8_t *e, const char *name, size_t n)
{
    if (memcmp(e + 10, name, n)) return 0;
    for (size_t i = n; i < 21; i++) if (e[10 + i]) return 0;     /* the name field is 20 characters and a 0 */
    return 1;
}

int cf_open(cf_file *f, cf_frame_fn rd, void *ctx, const char *name)
{
    uint8_t e[CF_FRAME];
    size_t nl = strlen(name);
    unsigned first = 0, seen = 0, n, next;

    memset(f, 0, sizeof *f);
    f->cached = -1;
    if (!rd || nl == 0 || nl > 20) return CF_ERR_NOTFOUND;
    if (rd(ctx, 0, e)) return CF_ERR_READ;
    if (e[0] != 'M' || e[1] != 'C' || !xor_ok(e)) return CF_ERR_FORMAT;
    for (unsigned b = 1; b <= 15 && !first; b++) {
        if (rd(ctx, (int) b, e)) return CF_ERR_READ;
        if (e[0] == 0x51 && name_is(e, name, nl)) first = b;
    }
    if (!first) return CF_ERR_NOTFOUND;
    if (!xor_ok(e)) return CF_ERR_CHAIN;
    f->blocks[0] = (uint8_t) first;
    seen = 1u << first;
    n = 1;
    next = rd16(e + 8);
    {
        uint32_t size = rd32(e + 4);
        while (next != 0xFFFF) {
            unsigned nb = next + 1;
            if (nb < 1 || nb > 15 || (seen >> nb & 1) || n >= CF_MAX_BLOCKS) return CF_ERR_CHAIN;
            if (rd(ctx, (int) nb, e)) return CF_ERR_READ;
            if ((e[0] != 0x52 && e[0] != 0x53) || !xor_ok(e)) return CF_ERR_CHAIN;
            next = rd16(e + 8);
            if ((e[0] == 0x53) != (next == 0xFFFF)) return CF_ERR_CHAIN;         /* the last block ends the chain, the others go on */
            seen |= 1u << nb;
            f->blocks[n++] = (uint8_t) nb;
        }
        if (size != 8192u * n) return CF_ERR_CHAIN;
    }
    if (rd(ctx, 64 * (int) first, e)) return CF_ERR_READ;
    if (e[0] != 'S' || e[1] != 'C' || e[2] < 0x11 || e[2] > 0x13) return CF_ERR_HEADER;
    f->rd = rd;
    f->ctx = ctx;
    f->nblocks = (uint8_t) n;
    f->start = (uint8_t) (1 + (e[2] & 3));                          /* the header frame, then the icon frames */
    f->size = 8192u * n - (uint32_t) f->start * CF_FRAME;
    return CF_OK;
}

int cf_read(cf_file *f, uint32_t off, uint8_t *buf, uint32_t len)
{
    uint32_t first_bytes = (64u - f->start) * CF_FRAME;

    if (!f->rd || (uint64_t) off + len > f->size) return CF_ERR_RANGE;
    while (len) {
        uint32_t bi, fr, within, chunk;
        int abs;

        if (off < first_bytes) { bi = 0; fr = f->start + off / CF_FRAME; within = off % CF_FRAME; }
        else {
            uint32_t d = off - first_bytes;
            bi = 1 + d / 8192;
            fr = d % 8192 / CF_FRAME;
            within = d % CF_FRAME;
        }
        abs = 64 * (int) f->blocks[bi] + (int) fr;
        if (f->cached != abs) {
            if (f->rd(f->ctx, abs, f->buf)) { f->cached = -1; return CF_ERR_READ; }
            f->cached = abs;
        }
        chunk = CF_FRAME - within < len ? CF_FRAME - within : len;
        memcpy(buf, f->buf + within, chunk);
        buf += chunk;
        off += chunk;
        len -= chunk;
    }
    return CF_OK;
}

const char *cf_strerror(int rc)
{
    switch (rc) {
    case CF_OK: return "ok";
    case CF_ERR_READ: return T(TXT_CARD_READ_ERROR);
    case CF_ERR_FORMAT: return T(TXT_CARD_NOT_FORMATTED);
    case CF_ERR_NOTFOUND: return T(TXT_NO_SUCH_FILE_ON_THE_CARD);
    case CF_ERR_CHAIN: return T(TXT_DAMAGED_FILE_ENTRY);
    case CF_ERR_HEADER: return T(TXT_NOT_A_SAVE_FILE);
    case CF_ERR_RANGE: return T(TXT_READ_BEYOND_THE_END_OF_THE);
    default: return T(TXT_CARD_ERROR);
    }
}
