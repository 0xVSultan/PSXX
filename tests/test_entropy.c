/* Unit tests for the entropy pool / estimator (timing behaviour, flags, determinism). */
#include <stdio.h>
#include <string.h>
#include "entropy.h"

static int fails, total;
#define CHECK(c) do { total++; if (!(c)) { fails++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

/* tiny deterministic PRNG for synthetic "jitter" */
static uint32_t rng(uint32_t *s) { *s = *s * 1664525u + 1013904223u; return *s >> 8; }

int main(void)
{
    entropy_pool p, q;
    uint8_t a[32], b[32];

    /* empty pool: nothing credited, extraction refused */
    entropy_init(&p, 0);
    CHECK(entropy_bits(&p) == 0 && !entropy_ready(&p) && entropy_extract(&p, a) == -1);

    /* constant counter value: no credit */
    for (int i = 0; i < 100; i++) entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, 12345);
    CHECK(entropy_bits(&p) == 0);

    /* perfectly regular events (constant, linear and quadratic predictions): no credit */
    entropy_init(&p, 0);
    for (uint32_t i = 0; i < 200; i++) entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, 1000000u + i * 50000u);
    CHECK(entropy_bits(&p) == 0);
    entropy_init(&p, 0);
    for (uint32_t i = 0; i < 200; i++) entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, 7u * i * i + 3u * i);
    CHECK(entropy_bits(&p) == 0);

    /* irregular "human" timing earns credit, capped at 2 bits per event */
    uint32_t s = 1, t = 0;
    entropy_init(&p, 0);
    for (int i = 0; i < 150; i++) { t += 300000u + (rng(&s) % 5000000u); entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, t); }
    CHECK(entropy_bits(&p) > 100 && entropy_bits(&p) <= 2 * 150);

    /* sources are tracked separately: two interleaved regular streams must not look random */
    entropy_init(&p, 0);
    for (uint32_t i = 0; i < 100; i++) {
        entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, 100000u * i);
        entropy_add_timing(&p, ENTROPY_SRC_PAD_RELEASE, 5000000u + 77777u * i);
    }
    CHECK(entropy_bits(&p) == 0);

    /* emulated: timing is hashed but earns nothing */
    entropy_init(&p, ENTROPY_EMULATED);
    for (int i = 0; i < 150; i++) { t += 300000u + (rng(&s) % 5000000u); entropy_add_timing(&p, ENTROPY_SRC_CD, t); }
    CHECK(entropy_bits(&p) == 0 && !entropy_ready(&p));
    /* ... but manual input still counts there */
    for (int i = 0; i < 100; i++) entropy_add_dice(&p, 1 + (unsigned)(i % 6));
    CHECK(entropy_ready(&p) && entropy_extract(&p, a) == 0);

    /* manual only: timing events are ignored entirely, so the output depends on the dice alone */
    entropy_init(&p, ENTROPY_MANUAL_ONLY);
    entropy_init(&q, ENTROPY_MANUAL_ONLY);
    for (int i = 0; i < 100; i++) {
        entropy_add_timing(&p, ENTROPY_SRC_PAD_PRESS, rng(&s));   /* noise only in p */
        entropy_add_dice(&p, 1 + (unsigned)((i * 7) % 6));
        entropy_add_dice(&q, 1 + (unsigned)((i * 7) % 6));
    }
    CHECK(entropy_ready(&p) && entropy_ready(&q));
    CHECK(entropy_extract(&p, a) == 0 && entropy_extract(&q, b) == 0 && !memcmp(a, b, 32));

    /* dice are checked */
    CHECK(entropy_add_dice(&p, 0) == -1 && entropy_add_dice(&p, 7) == -1);
    CHECK(entropy_add_symbol(&p, 4, 4) == -1 && entropy_add_symbol(&p, 0, 1) == -1 && entropy_add_symbol(&p, 0, 17) == -1);

    /* a different roll gives a different seed; extraction does not disturb the pool */
    entropy_add_dice(&q, 3);
    CHECK(entropy_extract(&q, b) == 0 && memcmp(a, b, 32) != 0);
    CHECK(entropy_extract(&q, a) == 0 && !memcmp(a, b, 32));

    /* context is hashed but earns nothing, and is ignored in manual-only mode */
    entropy_init(&p, 0);
    for (int i = 0; i < 100; i++) entropy_add_dice(&p, 1 + (unsigned)(i % 6));
    CHECK(entropy_extract(&p, a) == 0);
    entropy_add_context(&p, 0xCAFE);
    CHECK(entropy_bits(&p) == 258 && entropy_extract(&p, b) == 0 && memcmp(a, b, 32) != 0);
    entropy_init(&q, ENTROPY_MANUAL_ONLY);
    for (int i = 0; i < 100; i++) entropy_add_dice(&q, 1 + (unsigned)(i % 6));
    CHECK(entropy_extract(&q, a) == 0);
    entropy_add_context(&q, 0xCAFE);
    CHECK(entropy_extract(&q, b) == 0 && !memcmp(a, b, 32));

    /* wipe */
    entropy_wipe(&q);
    CHECK(entropy_bits(&q) == 0);

    {   /* the digest of a pool that only runs along: no threshold, no disturbance, bound to what it saw */
        entropy_pool d, e;
        uint8_t d1[32], d2[32], d3[32], x[32];

        entropy_init(&d, 0);
        entropy_init(&e, 0);
        entropy_digest(&d, d1);
        entropy_digest(&e, d2);
        CHECK(!memcmp(d1, d2, 32));                       /* the same (empty) history */
        for (uint32_t i = 0; i < 40; i++) { entropy_add_timing(&d, 0, 100000u + i * 77777u + (i * i) * 4099u); entropy_add_context(&d, i); }
        entropy_digest(&d, d1);
        entropy_digest(&d, d3);
        CHECK(!memcmp(d1, d3, 32) && memcmp(d1, d2, 32));  /* the history shows, asking twice changes nothing */
        entropy_add_context(&d, 7);
        entropy_digest(&d, d3);
        CHECK(memcmp(d1, d3, 32));                         /* one more event changes it */
        CHECK(entropy_extract(&d, x) == -1 || entropy_ready(&d));   /* and the pool is not "ready" because of it */
    }
    printf("%s: %d checks, %d failed\n", fails ? "ENTROPY TESTS FAILED" : "ENTROPY OK", total, fails);
    return fails != 0;
}
