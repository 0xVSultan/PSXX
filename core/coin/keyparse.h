#pragma once
#include <stdint.h>

/* Secret keys as people have them in text: 64 hex digits, a Nostr nsec (NIP-19, bech32) and a WIF (Base58Check: version byte, 32 bytes, an optional 0x01 for a compressed key). Used by the
 * raw key import of the signer overlay. The text is the caller's to wipe. */
enum { KP_OK = 0, KP_ERR_FORMAT = -1, KP_ERR_CHECKSUM = -2, KP_ERR_RANGE = -3 };

/* exactly 64 hex digits (either case), with or without a leading 0x */
int keyparse_hex32(const char *s, uint8_t out[32]);
/* a secp256k1 secret key from hex, nsec1... or WIF (any version byte: the network does not matter for the key); the key has to be 1 .. n - 1 */
int keyparse_secp256k1(const char *s, uint8_t out[32]);
/* an ed25519 seed (32 bytes) from hex (also with 0x), a Stellar "S..." secret, a Solana or NEAR base58 keypair (64 bytes: the seed and its public key, which is checked; also "ed25519:" in
 * front for NEAR) or a base58 seed of 32 bytes */
int keyparse_ed25519(const char *s, uint8_t out[32]);
/* a Cardano extended key (kL | kR, 64 bytes) from 128 hex digits or a bech32 *_xsk (96 bytes, the chain code dropped); KP_ERR_RANGE when kL is not a clamped scalar */
int keyparse_cardano(const char *s, uint8_t out[64]);
