#pragma once
#include <stddef.h>
#include <stdint.h>

/* Address / key encodings for the secp256k1 coins. All functions return the string length, or -1 on error. */

/* P2PKH: Base58Check(version || HASH160(compressed pubkey)). Bitcoin 0x00, Dogecoin 0x1e. */
int addr_p2pkh(char *out, size_t cap, uint8_t version, const uint8_t pub33[33]);
/* Wallet Import Format, compressed. Bitcoin 0x80, Dogecoin 0x9e. */
int addr_wif(char *out, size_t cap, uint8_t version, const uint8_t priv[32]);
/* Native SegWit v0 (P2WPKH), e.g. hrp "bc". */
int addr_p2wpkh(char *out, size_t cap, const char *hrp, const uint8_t pub33[33]);
/* Ethereum / Ethereum Classic: 0x + EIP-55 checksummed hex of keccak256(pub64)[12..]. out needs 43 bytes. */
int addr_eth(char *out, size_t cap, const uint8_t priv[32]);
/* the same from the 20 address bytes */
int addr_eth20(char *out, size_t cap, const uint8_t a[20]);
/* Nostr (NIP-19): bech32 "npub" of the x-only public key, "nsec" of the secret key. */
int addr_npub(char *out, size_t cap, const uint8_t priv[32]);
int addr_nsec(char *out, size_t cap, const uint8_t priv[32]);
