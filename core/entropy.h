#pragma once
/* Entropy pool and conservative entropy estimator (spec section 7).
 *
 * Every event is hashed into a running SHA-256; the estimator decides how many bits to *credit* for it.
 * Sources are independent and optional: jitter (button press/release timing), manual (dice, coin, directions),
 * and CD seek timing. A seed may only be extracted once the credited entropy reaches ENTROPY_MIN_BITS,
 * in any combination of sources.
 *
 * Credits are kept in 1/256 bit units. The estimator is intentionally conservative:
 *  - jitter / CD timing samples earn 0, 1 or 2 bits depending on how much the sample deviates from a
 *    constant, linear and quadratic prediction (Linux add_interrupt_randomness style "stuck" test);
 *  - manual symbols earn log2(number of symbols) bits (fractional, rounded down to 1/256 bit: a d6 earns 661/256 = 2.58
 *    bits, a coin 1 bit), assuming a fair device.
 * The thresholds are meant to be tuned on real hardware.
 */
#include <stddef.h>
#include <stdint.h>
#include "hash/sha256.h"

#define ENTROPY_MIN_BITS 256

enum {
    ENTROPY_MANUAL_ONLY = 1,     /* ignore jitter/CD events completely: same manual input => same output */
    ENTROPY_EMULATED    = 2      /* timing is deterministic here: hash timing events but credit nothing for them */
};

/* Independent timing estimators. */
enum { ENTROPY_SRC_PAD_PRESS = 0, ENTROPY_SRC_PAD_RELEASE = 1, ENTROPY_SRC_CD = 2, ENTROPY_SRC_PAD_STICK = 3, ENTROPY_SRC_COUNT = 4 };

typedef struct {
    uint32_t last, d1, d2;
    uint32_t n;                   /* samples seen */
} entropy_timing;

typedef struct {
    sha256_ctx     ctx;           /* running hash of all events */
    uint32_t       credit;        /* credited entropy, 1/256 bit units */
    uint32_t       events;
    uint32_t       flags;
    entropy_timing t[ENTROPY_SRC_COUNT];
} entropy_pool;

void entropy_init(entropy_pool *p, uint32_t flags);
void entropy_wipe(entropy_pool *p);

/* Free-running counter value taken at an input event (button press/release, CD seek completion). */
void entropy_add_timing(entropy_pool *p, int source, uint32_t counter);
/* Extra data that belongs to an event (e.g. which buttons changed): hashed into the pool, credits nothing. */
void entropy_add_context(entropy_pool *p, uint32_t value);
/* Manual input: a symbol in 0..nsym-1 from a fair device with nsym (2..16) outcomes. Dice: face-1 with nsym 6. */
int  entropy_add_symbol(entropy_pool *p, unsigned symbol, unsigned nsym);
/* Credit (1/256 bit units) of one symbol of a fair device with nsym outcomes, 0 if nsym is not 2..16. */
unsigned entropy_symbol_credit(unsigned nsym);
int  entropy_add_dice(entropy_pool *p, unsigned face);          /* 1..6 */
int  entropy_add_coin(entropy_pool *p, unsigned heads);         /* 0/1 */

uint32_t entropy_bits(const entropy_pool *p);                   /* whole credited bits */
int      entropy_ready(const entropy_pool *p);                  /* credited >= ENTROPY_MIN_BITS */
/* 32 byte output bound to the pool state and the credited bits. Returns 0, or -1 if the pool is not ready. */
int      entropy_extract(const entropy_pool *p, uint8_t out[32]);
/* The same without the credit threshold: a digest of everything the pool has seen so far (and of how much it credited), whatever that is. For a pool that only runs along (the
 * background pool of the generator): it is mixed into other secrets as a salt, where it can only add to them, and nothing is claimed for it. Does not disturb the pool. */
void     entropy_digest(const entropy_pool *p, uint8_t out[32]);
