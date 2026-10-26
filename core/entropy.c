#include "entropy.h"
#include "util.h"
#include <string.h>

static const char POOL_TAG[] = "psx-entropy-pool-v1";
static const char EXTRACT_TAG[] = "psx-entropy-extract-v1";

/* floor(log2(n) * 256) for n = 2..16 */
static const uint16_t LOG2_X256[17] = {0, 0, 256, 405, 512, 594, 661, 718, 768, 811, 850, 885, 917, 947, 974, 1000, 1024};

enum { EV_TIMING = 0, EV_SYMBOL = 1, EV_CONTEXT = 2 };

void entropy_init(entropy_pool *p, uint32_t flags)
{
    memset(p, 0, sizeof *p);
    p->flags = flags;
    sha256_init(&p->ctx);
    sha256_update(&p->ctx, (const uint8_t *)POOL_TAG, sizeof POOL_TAG - 1);
}

void entropy_wipe(entropy_pool *p) { secure_zero(p, sizeof *p); }

/* event record: type u8 | source/nsym u8 | value u32 LE */
static void hash_event(entropy_pool *p, uint8_t type, uint8_t src, uint32_t value)
{
    uint8_t rec[6] = {type, src, (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    sha256_update(&p->ctx, rec, sizeof rec);
    p->events++;
}

static uint32_t iabs32(uint32_t x) { return (x & 0x80000000u) ? 0u - x : x; }

/* Credit (1/256 bit) for one timing sample: the smallest of the first, second and third difference must be
 * clearly non-zero, otherwise the sample is predictable from its predecessors. */
static uint32_t timing_credit(entropy_timing *e, uint32_t sample)
{
    uint32_t d1 = sample - e->last;
    uint32_t d2 = d1 - e->d1;
    uint32_t d3 = d2 - e->d2;
    uint32_t credit = 0;

    if (e->n >= 3) {
        uint32_t m = iabs32(d1), a2 = iabs32(d2), a3 = iabs32(d3);
        if (a2 < m) m = a2;
        if (a3 < m) m = a3;
        if (m >= 65536u)      credit = 2 * 256;     /* > ~2 ms of unexplained deviation at 33.87 MHz */
        else if (m >= 1024u)  credit = 1 * 256;
    }
    e->last = sample;
    e->d1 = d1;
    e->d2 = d2;
    e->n++;
    return credit;
}

void entropy_add_timing(entropy_pool *p, int source, uint32_t counter)
{
    if ((p->flags & ENTROPY_MANUAL_ONLY) || source < 0 || source >= ENTROPY_SRC_COUNT) return;
    uint32_t c = timing_credit(&p->t[source], counter);
    hash_event(p, EV_TIMING, (uint8_t)source, counter);
    if (!(p->flags & ENTROPY_EMULATED)) p->credit += c;
}

void entropy_add_context(entropy_pool *p, uint32_t value)
{
    if (p->flags & ENTROPY_MANUAL_ONLY) return;
    hash_event(p, EV_CONTEXT, 0, value);
}

int entropy_add_symbol(entropy_pool *p, unsigned symbol, unsigned nsym)
{
    if (nsym < 2 || nsym > 16 || symbol >= nsym) return -1;
    hash_event(p, EV_SYMBOL, (uint8_t)nsym, symbol);
    p->credit += LOG2_X256[nsym];
    return 0;
}

unsigned entropy_symbol_credit(unsigned nsym) { return nsym >= 2 && nsym <= 16 ? LOG2_X256[nsym] : 0; }

int entropy_add_dice(entropy_pool *p, unsigned face)
{
    return (face >= 1 && face <= 6) ? entropy_add_symbol(p, face - 1, 6) : -1;
}

int entropy_add_coin(entropy_pool *p, unsigned heads)
{
    return entropy_add_symbol(p, heads ? 1 : 0, 2);
}

uint32_t entropy_bits(const entropy_pool *p) { return p->credit >> 8; }

int entropy_ready(const entropy_pool *p) { return entropy_bits(p) >= ENTROPY_MIN_BITS; }

static const char DIGEST_TAG[] = "psx-entropy-digest-v1";

void entropy_digest(const entropy_pool *p, uint8_t out[32])
{
    sha256_ctx c = p->ctx;
    uint8_t h[32], b[4] = {(uint8_t)(p->credit >> 24), (uint8_t)(p->credit >> 16), (uint8_t)(p->credit >> 8), (uint8_t)p->credit};

    sha256_final(&c, h);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)DIGEST_TAG, sizeof DIGEST_TAG - 1);
    sha256_update(&c, h, 32);
    sha256_update(&c, b, 4);
    sha256_final(&c, out);
    secure_zero(h, sizeof h);
    secure_zero(&c, sizeof c);
}

int entropy_extract(const entropy_pool *p, uint8_t out[32])
{
    sha256_ctx c = p->ctx;                  /* copy: extraction does not disturb the pool */
    uint8_t h[32];
    uint32_t bits = entropy_bits(p);
    if (bits < ENTROPY_MIN_BITS) return -1;
    sha256_final(&c, h);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)EXTRACT_TAG, sizeof EXTRACT_TAG - 1);
    sha256_update(&c, h, 32);
    uint8_t b[4] = {(uint8_t)(bits >> 24), (uint8_t)(bits >> 16), (uint8_t)(bits >> 8), (uint8_t)bits};
    sha256_update(&c, b, 4);
    sha256_final(&c, out);
    secure_zero(h, sizeof h);
    secure_zero(&c, sizeof c);
    return 0;
}
