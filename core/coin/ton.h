#pragma once
#include <stddef.h>
#include <stdint.h>

/* TON. Two key sources:
 *  - the TON phrase (24 words of the BIP39 list, no BIP39 checksum; accepted when its entropy is a "basic seed"):
 *      entropy = HMAC-SHA512(key = the phrase with single spaces, data = password),
 *      accepted if PBKDF2-HMAC-SHA512(entropy, "TON seed version", 390 rounds)[0] == 0,
 *      private key seed = PBKDF2-HMAC-SHA512(entropy, "TON default seed", 100000 rounds), its first 32 bytes.
 *    The 100000 rounds take minutes on a PlayStation, and a random phrase is accepted with probability 1/256.
 *  - a BIP39 phrase with SLIP-10 ed25519 (m/44'/607'/0', the Ledger way): see the chain table, kind K_TON.
 * The address is the hash of the wallet contract's StateInit: the contract code (only its hash and depth are needed) and
 * the data cell with the public key. */

enum { TON_V3R1 = 0, TON_V3R2 = 1, TON_V4R2 = 2, TON_V5R1 = 3 };

void ton_entropy(uint8_t e[64], const char *phrase, const char *password);
int  ton_entropy_is_basic(const uint8_t e[64]);                         /* 390 PBKDF2 rounds */
void ton_private_seed(uint8_t seed[64], const uint8_t e[64]);           /* 100000 rounds */
/* The same with progress (see pbkdf2_hmac_sha512_cb); returns 0, or -1 if the callback cancelled. */
int  ton_private_seed_cb(uint8_t seed[64], const uint8_t e[64], int (*cb)(uint32_t done, uint32_t total, void *user), void *user);

/* Base64 url address of the wallet for a public key: workchain 0, bounceable ("EQ...") or not ("UQ..."). Returns the
 * length (48) or -1. out needs 49 bytes. */
int ton_address(char *out, size_t cap, int version, int bounceable, const uint8_t pub[32]);
