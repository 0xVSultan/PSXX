#pragma once
#include <stddef.h>
#include <stdint.h>

#define BIP32_HARDENED 0x80000000u

/* Private-key-only BIP32 node (secp256k1). */
typedef struct {
    uint8_t key[32];
    uint8_t chain[32];
} bip32_node;

/* Master node from a seed (16..64 bytes). Returns 0, or -1 if the seed is unusable (invalid key, ~2^-127). */
int bip32_master(bip32_node *n, const uint8_t *seed, size_t seedlen);
/* CKDpriv for one index (>= BIP32_HARDENED is hardened). Returns 0, or -1 for the (practically impossible) invalid child. */
int bip32_derive(bip32_node *n, uint32_t index);
/* Walk a path of `len` indices. */
int bip32_derive_path(bip32_node *n, const uint32_t *path, size_t len);
/* First 4 bytes of HASH160(compressed public key): the parent fingerprint. */
int bip32_fingerprint(const bip32_node *n, uint8_t fp[4]);
/* Base58Check xprv / xpub (version bytes 0x0488ADE4 / 0x0488B21E). Returns length or -1. */
int bip32_serialize(const bip32_node *n, int is_public, uint8_t depth, const uint8_t parent_fp[4], uint32_t child_index,
                    char *out, size_t outcap);
/* The public key of the node with any version (0x0488B21E xpub, 0x049D7CB2 ypub, 0x04B24746 zpub). */
int bip32_serialize_ver(const bip32_node *n, uint32_t version, uint8_t depth, const uint8_t parent_fp[4], uint32_t child_index, char *out, size_t outcap);
