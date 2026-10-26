#pragma once
/* Vanity address search (offline, on the console): looks for a private key whose address starts and/or ends with a chosen text. The candidates are the keys
 * s + k of a random start key s: the kernel of core/ec/secp_van.c makes their public points in batches (about 4 000 cycles a candidate), the address hash is
 * taken and compared with what was asked for in a cheap form (nibbles, 5 bit groups, or a range of numbers for Base58), and a hit is checked again from the
 * key alone with the address code of the wallet. The result is a raw secp256k1 key (no mnemonic). CREATE2 is different: no curve, the salt of a contract
 * deployment is searched, keccak256(0xff || deployer || salt || init code hash) shaped to the address.
 * A prefix or a suffix is the text of the address from its first or up to its last character: for the kinds with a fixed beginning that includes the head
 * (vanity_head), which the caller shows and prefills. */
#include <stddef.h>
#include <stdint.h>
#include "ec/secp_van.h"

enum { VK_ETH, VK_BECH32, VK_P2PKH, VK_P2SH, VK_NPUB, VK_KASPA, VK_CREATE2, VK_KINDS };

enum {
    VE_OK = 0,
    VE_KIND = -1,                       /* a kind or version that is not supported */
    VE_HEAD = -2,                       /* the prefix does not start with the head of that kind */
    VE_CHAR = -3,                       /* a character that cannot occur in these addresses */
    VE_LONG = -4,                       /* too long */
    VE_RANGE = -5,                      /* no address starts like that */
    VE_SEED = -6                        /* the start key is unusable (one in 2^240) */
};

typedef struct {
    int        kind;
    uint8_t    version;                 /* VK_P2PKH, VK_P2SH: the version byte of the address (0x00 Bitcoin, 0x05 nested, 0x30 Litecoin, 0x1e Dogecoin, 0x4c Dash) */
    const char *hrp;                    /* VK_BECH32: "bc", "ltc"; VK_KASPA: "kaspa" */
    char       prefix[24], suffix[24];  /* the text; empty: no condition */
    uint8_t    deployer[20], init_hash[32];   /* VK_CREATE2 */
} vanity_cfg;

#define VAN_ADDR 96

typedef struct {
    vanity_cfg cfg;
    van_ctx    *ctx;                    /* the kernel's tables (about 100 KB), provided by the caller */
    int        c, prepared;             /* the next candidate of the batch: 2 * (i) + neg */
    uint64_t   tried;                   /* candidates looked at */
    uint64_t   expected;                /* the number of candidates after which a hit is as likely as not, about (saturating) */
    int        slow;                    /* 1: every candidate is encoded in full (a suffix without a prefix) */
    /* compiled conditions */
    uint8_t    pn[40], sn[40];          /* hex: prefix and suffix as nibbles */
    int        npn, nsn;
    uint8_t    pg[44];                  /* 5 bit groups of the prefix, after the head */
    int        npg, goff;
    uint8_t    lo[2][26], hi[2][26];    /* Base58: ranges of version || HASH160 (big endian) */
    int        nrange, rlen, zeros;     /* rlen: bytes compared; zeros: leading zero bytes of the version (each is a '1') */
    uint8_t    salt[32];                /* CREATE2: the start salt; the counter is added to its last 8 bytes */
    /* the result */
    int        found;
    uint8_t    key[32];                 /* the private key, or the salt of CREATE2 */
    uint8_t    a20[20];                 /* EVM address bytes (ETH, CREATE2) */
    char       addr[VAN_ADDR];
    int        rejected;                /* hits that failed the check from the key (a bug, should stay 0) */
} vanity;

/* the fixed beginning of the addresses ("0x", "bc1q", "npub1", "kaspa:q", "1", "3", "L"..); returns its length */
int vanity_head(const vanity_cfg *c, char *out, size_t cap);
/* 1 if `ch` may be typed after the head (prefix) or at the end (suffix) */
int vanity_char_ok(const vanity_cfg *c, char ch);
/* Whether the conditions can be met, and the median number of candidates they take (no kernel is touched). VE_OK or a VE_ code. */
int vanity_check(const vanity_cfg *c, uint64_t *expected);
/* Starts a search from the random start key `seed` (32 bytes, must be full entropy). VE_OK or a VE_ code. */
int vanity_start(vanity *v, const vanity_cfg *c, van_ctx *ctx, const uint8_t seed[32]);
/* Looks at up to `n` candidates. Returns 1 when one is found (v->key, v->addr), else 0. */
int vanity_step(vanity *v, int n);
/* The hit test of one candidate of the current (prepared) batch, for the tests: 1 if it satisfies the quick condition. */
int vanity_probe(vanity *v, int i, int neg);
/* The address of a key (the kind, version and hrp of the configuration decide which): its length, or -1 */
int vanity_address(const vanity_cfg *c, const uint8_t key[32], char *out, size_t cap);
/* The EIP-55 text of an EVM address */
int vanity_eth_text(char *out, const uint8_t a20[20]);
