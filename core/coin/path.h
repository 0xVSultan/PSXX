#pragma once
#include <stddef.h>
#include <stdint.h>

/* BIP32 style derivation paths: m/44'/0'/0'/0/0. An index with bit 31 set is hardened (written ' h or H). */

#define PATH_MAX_DEPTH 10
#define PATH_HARD 0x80000000u

typedef struct {
    uint8_t  n;
    uint32_t idx[PATH_MAX_DEPTH];
} hd_path;

enum { PATH_OK = 0, PATH_ERR_SYNTAX = -1, PATH_ERR_RANGE = -2, PATH_ERR_DEPTH = -3 };

/* "m/44'/0'/0'/0/0", "44h/0h", "m" (empty path), upper or lower case m. Returns PATH_OK or a PATH_ERR_ code
 * (SYNTAX: bad character or empty segment, RANGE: an index above 2^31 - 1, DEPTH: more than PATH_MAX_DEPTH levels). */
int path_parse(hd_path *p, const char *s);
/* Writes the canonical form (apostrophes). Returns the length, or -1 if cap is too small (needs 4 + 12 * n). */
int path_format(const hd_path *p, char *out, size_t cap);
/* 1 if every index is hardened (SLIP-10 ed25519 needs this). */
int path_all_hardened(const hd_path *p);
