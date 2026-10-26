#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/path.h"

/* Cardano (Shelley era addresses, Icarus master key, BIP32-Ed25519 "V2" derivation, CIP-1852 paths).
 * A node is 96 bytes: kL (32, the clamped scalar) | kR (32) | chain code (32). Secret: the caller wipes it. */

/* Icarus master node from the BIP39 *entropy* (16..32 bytes), not from the seed: PBKDF2-HMAC-SHA512(password, entropy,
 * 4096 iterations, 96 bytes), then the clamp of the Ed25519 scalar. `password` is empty in the standard wallets. */
void cardano_icarus_master(uint8_t node[96], const uint8_t *entropy, size_t entlen, const char *password);
/* One child step. Hardened indices (bit 31) use the private key, others the public key. */
void cardano_derive(uint8_t node[96], uint32_t index);
void cardano_derive_path(uint8_t node[96], const hd_path *p);
/* Public key kL * B (32 bytes). */
void cardano_pubkey(uint8_t pub[32], const uint8_t node[96]);
/* Shelley base address on the main net: bech32 "addr" of 0x01 | blake2b224(payment key) | blake2b224(stake key).
 * Returns the length (103) or -1. out needs 110 bytes. */
int cardano_base_address(char *out, size_t cap, const uint8_t pay_pub[32], const uint8_t stake_pub[32]);
/* Shelley enterprise address (no staking part) on the main net: bech32 "addr" of 0x61 | blake2b224(payment key). Returns the length or -1. */
int cardano_enterprise_address(char *out, size_t cap, const uint8_t pay_pub[32]);
