#pragma once
#include <stddef.h>
#include <stdint.h>

/* Substrate / Polkadot sr25519 (Schnorrkel on Ristretto255), keys from a BIP39 mnemonic the Substrate way:
 *   mini secret = first 32 bytes of PBKDF2-HMAC-SHA512(entropy, "mnemonic" + password, 2048), expanded Ed25519 style.
 * A key here is the secret scalar (32 bytes, little-endian); the caller wipes it.
 * Derivation junctions as in the secret URI: "//hard", "/soft", numbers as u64, other names as SCALE strings:
 *   "//polkadot//0/1". */

/* Mini secret from the entropy (16..32 bytes) and the passphrase ("" for none). */
void substrate_mini_secret(uint8_t mini[32], const uint8_t *entropy, size_t entlen, const char *password);
/* The secret scalar of a mini secret (SHA-512, clamp, divide by the cofactor). */
void sr25519_expand(uint8_t scalar[32], const uint8_t mini[32]);
/* Public key = Ristretto encoding of scalar * B. */
void sr25519_pubkey(uint8_t pub[32], const uint8_t scalar[32]);
/* One junction with its 32 byte chain code. */
void sr25519_derive_hard(uint8_t scalar[32], const uint8_t cc[32]);
void sr25519_derive_soft(uint8_t scalar[32], const uint8_t cc[32]);
/* Apply a path of junctions ("" for none). Returns 0, or -1 for a bad path. */
int substrate_derive_path(uint8_t scalar[32], const char *path);

/* Schnorrkel signature (64 bytes, the "sr25519" format of Substrate: the high bit of the last byte set) of a message in the
 * signing context "substrate", with the secret scalar of sr25519_expand / the derivations. The nonce is derived from the key and
 * the transcript (the reference code uses random bytes there; any nonce gives a valid signature). */
void sr25519_sign(uint8_t sig[64], const uint8_t scalar[32], const uint8_t *msg, size_t len);
