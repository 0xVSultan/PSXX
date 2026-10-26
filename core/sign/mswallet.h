#pragma once
/* Registered multisig wallets (a wallet policy): the output descriptor of a multisig wallet, wsh(sortedmulti(2, [fp/48h/0h/0h/2h]xpub.../<0;1>/ *, ...)), kept on the card of
 * the signer. With the extended public keys of all the cosigners the signer can derive the script of any address of the wallet, so it recognises the inputs it spends and the
 * change that comes back to the wallet by its script alone, instead of trusting the derivation records of a PSBT (which anybody can write).
 *
 * Supported: wsh(multi / sortedmulti), sh(wsh(multi / sortedmulti)), sh(multi / sortedmulti); 2..8 keys, each with its origin [fingerprint/path], the extended key, and the
 * suffix /<0;1>/ * (or /0/ *, /1/ *, / **: the receiving and the change chain are 0 and 1 in all cases).
 *
 * A policy on the card carries a MAC keyed with a secret derived from the seed (ms_mac): only someone who holds the seed can have registered it, a card that was changed
 * is detected. Registration is accepted only if one key of the descriptor is ours: the extended public key at its origin path, derived from the seed, must be the one
 * written in the descriptor. */
#include <stddef.h>
#include <stdint.h>
#include "coin/bip32.h"

#define MS_MAXKEYS 8
#define MS_MAXPATH 8
#define MS_SCRIPT_MAX (3 + 34 * MS_MAXKEYS)

enum { MS_WSH = 1, MS_SH_WSH = 2, MS_SH = 3 };

enum {
    MSE_OK = 0,
    MSE_SYNTAX = -1,                /* not a descriptor of the supported forms */
    MSE_CHECKSUM = -2,              /* the #checksum does not fit */
    MSE_KEY = -3,                   /* an extended key that cannot be read, or a private one */
    MSE_ORIGIN = -4,                /* a key without origin, or the origin does not fit the key (depth) */
    MSE_LIMIT = -5,                 /* more than MS_MAXKEYS keys, m > n, a path that is too long */
    MSE_NOTOURS = -6,               /* none of the keys is ours */
    MSE_FORMAT = -7,                /* a record of the card that cannot be read */
    MSE_MAC = -8                    /* a record that was not made with this seed */
};

typedef struct {
    uint8_t  fp[4];                 /* fingerprint of the master key of that cosigner */
    uint8_t  depth;
    uint32_t path[MS_MAXPATH];      /* origin path (hardened indices carry 0x80000000) */
    uint8_t  pub[33], cc[32];       /* the extended public key at that path */
} ms_key;

typedef struct {
    uint8_t type, sorted, m, n;
    ms_key  key[MS_MAXKEYS];
} ms_policy;

/* the keys of the two chains (receive 0, change 1) derived once: the first step of every address */
typedef struct {
    uint8_t pub[2][MS_MAXKEYS][33], cc[2][MS_MAXKEYS][32];
    uint8_t have[2][MS_MAXKEYS];
} ms_cache;

/* Reads a descriptor (white space is ignored; a #checksum must fit if there is one). Returns MSE_OK or an error. */
int ms_parse(ms_policy *p, const char *text);
/* The script of address (chain 0 or 1, index) and its output script (scriptPubKey). cache may be NULL (slower). Returns 0, or -1. */
int ms_script(const ms_policy *p, ms_cache *cache, unsigned chain, unsigned index, uint8_t *script, size_t *slen, uint8_t *spk, size_t *spklen);
/* The index of the key that is ours (its extended key at the origin path, derived from `master`, equals the one in the descriptor), or MSE_NOTOURS. */
int ms_ours(const ms_policy *p, const bip32_node *master);
/* a short identifier of the policy: 4 bytes of the hash of its keys and form (shown to the user as 8 hex digits) */
void ms_id(const ms_policy *p, uint8_t id[4]);
/* the card record: the policy and its MAC. ms_load checks the MAC against `master`. Sizes: MS_REC_MAX bytes at most. */
#define MS_REC_MAX 900
size_t ms_save(const ms_policy *p, const bip32_node *master, uint8_t *out, size_t cap);
int ms_load(ms_policy *p, const uint8_t *rec, size_t len, const bip32_node *master);
