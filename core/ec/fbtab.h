#pragma once
/* The fixed base tables of secp256k1 and Ed25519 (65 windows of 4 bits, d * 16^i * G for d = 1..8, affine, x then y) are built in small steps by one
 * routine; a curve only supplies its point operations. The points are X, Y, Z (and for Edwards T) of 8 words each, Z at word 16; the work area of eight
 * windows (fb_buf, 10 KB) is shared by the curves, which are built one after the other. */
#include <stddef.h>
#include <stdint.h>

#define FB_WINDOWS 65

typedef struct {
    size_t pt_words;                                                  /* words of a point: 24 (X Y Z) or 32 (X Y Z T) */
    void (*set_base)(void *p);                                        /* the generator, Z = 1 */
    void (*add)(void *r, const void *p, const void *q);
    void (*dbl)(void *r, const void *p);
    void (*mul)(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
    void (*inv)(uint32_t r[8], const uint32_t a[8]);
    void (*norm)(uint32_t a[8]);                                      /* fully reduced */
} fb_ops;

typedef struct {
    int ready, started, w, g0, pending, norm;
    uint32_t base[32];
} fb_state;

/* One unit of work: a window costs 1, the conversion of a group of eight windows 3. Returns the progress in percent (100: ready). */
int fb_step(fb_state *s, const fb_ops *o, uint32_t (*tab)[8][16]);
