#include "ec/fbtab.h"
#include <string.h>

uint32_t fb_buf[2560];                                              /* 10 KB: 64 points and 64 field elements */

static void normalize_group(fb_state *s, const fb_ops *o, uint32_t (*tab)[8][16])
{
    uint32_t *pts = fb_buf, *pre = fb_buf + 64 * o->pt_words;
    uint32_t inv[8];
    int n = (s->w - s->g0) * 8;

#define Z(k) (pts + (k) * o->pt_words + 16)
    memcpy(pre, Z(0), 32);
    for (int k = 1; k < n; k++) o->mul(pre + 8 * k, pre + 8 * (k - 1), Z(k));
    o->inv(inv, pre + 8 * (n - 1));                                  /* one inversion serves the group */
    for (int k = n - 1; k >= 0; k--) {
        uint32_t zi[8], *x = pts + k * o->pt_words, *y = x + 8, *dst = tab[s->g0 + k / 8][k % 8];
        if (k) o->mul(zi, inv, pre + 8 * (k - 1)); else memcpy(zi, inv, 32);
        o->mul(inv, inv, Z(k));
        o->mul(dst, x, zi); o->mul(dst + 8, y, zi);
        o->norm(dst); o->norm(dst + 8);
    }
#undef Z
}

int fb_step(fb_state *s, const fb_ops *o, uint32_t (*tab)[8][16])
{
    uint32_t *pts = fb_buf;

    if (s->ready) return 100;
    if (!s->started) { o->set_base(s->base); s->started = 1; }
    if (s->pending) {
        normalize_group(s, o, tab);
        s->pending = 0;
        s->norm++;
        s->g0 = s->w;
        if (s->w >= FB_WINDOWS) { s->ready = 1; return 100; }
    } else {
        uint32_t *row = pts + (size_t) (s->w - s->g0) * 8 * o->pt_words;
        memcpy(row, s->base, o->pt_words * 4);
        for (int j = 1; j < 8; j++) o->add(row + j * o->pt_words, row + (j - 1) * o->pt_words, s->base);
        for (int d = 0; d < 4; d++) o->dbl(s->base, s->base);          /* the next window: 16 * base */
        s->w++;
        if (s->w - s->g0 == 8 || s->w == FB_WINDOWS) s->pending = 1;
    }
    return (s->w + 3 * s->norm) * 100 / 92;
}
