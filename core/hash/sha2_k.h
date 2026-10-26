#pragma once
#include <stdint.h>

/* The constants of SHA-2, made at run time instead of 1 KB of tables: K of SHA-512 is the first 64 bits of the fraction of the cube roots of
 * the first 80 primes, its initial value those of the square roots of the first 8. SHA-256 takes the high words of both (its K is the first 64 of them); the initial value of
 * BLAKE2b is the one of SHA-512. SHA2_TABLES() makes them on the first use (about 0.3 s on the PSX, an estimate); every compression function calls it. */
extern uint32_t sha2_kh[80], sha2_kl[80], sha2_ivh[8], sha2_ivl[8];

void sha2_tables(void);
#define SHA2_TABLES() do { if (!sha2_kh[0]) sha2_tables(); } while (0)
