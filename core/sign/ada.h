#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Cardano: the request is the transaction body (the CBOR map, exactly as it is hashed). The transaction id is its BLAKE2b-256 hash,
 * the witness is an Ed25519 signature of that hash with the (extended) key of the address, made with kL and kR of the BIP32-Ed25519
 * node. Shown: outputs (Shelley addresses in bech32, Byron in Base58, lovelace and the number of native tokens), the fee, the validity
 * interval, withdrawals of rewards, certificates and minting are counted and flagged. */
enum { ADA_OK = 0, ADA_ERR_PARSE = -1 };

int ada_summary(const uint8_t *body, size_t len, tx_view *v);
/* node: kL | kR | chain code (96 bytes, as cardano_derive gives it); vkey = the public key; hash = the transaction id. */
int ada_sign(const uint8_t *body, size_t len, const uint8_t node[96], uint8_t vkey[32], uint8_t sig[64], uint8_t hash[32]);
/* The witness set {0: [[vkey, signature], ...]} for n (at most 4) signatures; returns its length (3 + 102 n). */
size_t ada_witness_set(uint8_t *out, int n, const uint8_t (*vkey)[32], const uint8_t (*sig)[64]);
