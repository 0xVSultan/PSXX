#include "hash/merlin.h"
#include <string.h>
#include "hash/keccak.h"

#define STROBE_R 166
enum { FLAG_I = 1, FLAG_A = 2, FLAG_C = 4, FLAG_T = 8, FLAG_M = 16, FLAG_K = 32 };

static uint8_t *bytes(merlin *m) { return (uint8_t *) m->st; }

static void run_f(merlin *m)
{
    uint8_t *s = bytes(m);
    s[m->pos] ^= m->pos_begin;
    s[m->pos + 1] ^= 0x04;
    s[STROBE_R + 1] ^= 0x80;
    keccak_f1600(m->st);
    m->pos = 0;
    m->pos_begin = 0;
}

static void absorb(merlin *m, const uint8_t *d, size_t n)
{
    uint8_t *s = bytes(m);
    while (n--) {
        s[m->pos++] ^= *d++;
        if (m->pos == STROBE_R) run_f(m);
    }
}

static void squeeze(merlin *m, uint8_t *d, size_t n)
{
    uint8_t *s = bytes(m);
    while (n--) {
        *d++ = s[m->pos];
        s[m->pos++] = 0;
        if (m->pos == STROBE_R) run_f(m);
    }
}

static void begin_op(merlin *m, uint8_t flags, int more)
{
    uint8_t hdr[2];
    if (more) return;                                 /* same operation continues (flags are equal by construction) */
    hdr[0] = m->pos_begin;
    m->pos_begin = (uint8_t) (m->pos + 1);
    m->cur_flags = flags;
    hdr[1] = flags;
    absorb(m, hdr, 2);
    if ((flags & (FLAG_C | FLAG_K)) && m->pos != 0) run_f(m);
}

static void meta_ad(merlin *m, const uint8_t *d, size_t n, int more)
{
    begin_op(m, FLAG_M | FLAG_A, more);
    absorb(m, d, n);
}

static void ad(merlin *m, const uint8_t *d, size_t n)
{
    begin_op(m, FLAG_A, 0);
    absorb(m, d, n);
}

static void prf(merlin *m, uint8_t *d, size_t n)
{
    begin_op(m, FLAG_I | FLAG_A | FLAG_C, 0);
    squeeze(m, d, n);
}

static void len_le(uint8_t b[4], size_t n)
{
    b[0] = (uint8_t) n;
    b[1] = (uint8_t) (n >> 8);
    b[2] = (uint8_t) (n >> 16);
    b[3] = (uint8_t) (n >> 24);
}

void merlin_append(merlin *m, const char *label, const uint8_t *msg, size_t len)
{
    uint8_t l[4];
    len_le(l, len);
    meta_ad(m, (const uint8_t *) label, strlen(label), 0);
    meta_ad(m, l, 4, 1);
    ad(m, msg, len);
}

void merlin_challenge(merlin *m, const char *label, uint8_t *out, size_t len)
{
    uint8_t l[4];
    len_le(l, len);
    meta_ad(m, (const uint8_t *) label, strlen(label), 0);
    meta_ad(m, l, 4, 1);
    prf(m, out, len);
}

void merlin_init(merlin *m, const char *label)
{
    static const uint8_t proto[] = "Merlin v1.0";
    uint8_t *s;
    memset(m, 0, sizeof *m);
    s = bytes(m);
    s[0] = 1;
    s[1] = STROBE_R + 2;
    s[2] = 1;
    s[3] = 0;
    s[4] = 1;
    s[5] = 96;
    memcpy(s + 6, "STROBEv1.0.2", 12);
    keccak_f1600(m->st);
    meta_ad(m, proto, sizeof proto - 1, 0);
    merlin_append(m, "dom-sep", (const uint8_t *) label, strlen(label));
}
