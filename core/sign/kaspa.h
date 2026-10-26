#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Kaspa (transaction version 0, native subnetwork, no payload, signature hash type SIGHASH_ALL). The request is not the network transaction (a node would be needed to look up
 * the spent outputs) but the transaction with what the signature hash commits to, little endian:
 *   version u16 (0) | nin u8 | nout u8 | lock_time u64
 *   nin x    [ txid[32] | index u32 | sequence u64 | sig_op_count u8 | amount u64 | script version u16 | script length u8 | script | flags u8 | (flags & 1: change u32 | index u32) ]
 *   nout x   [ value u64 | script version u16 | script length u8 | script | flags u8 | (flags & 1: change u32 | index u32) ]
 * Input flag 1: the input is ours, its key is the one at (change, index) of the account (m/44'/111111'/account'); the signer derives the key and the input is signed only if the spent
 * script is the schnorr script of that key. Output flag 1: this is change; it is shown as ours only if its script is the schnorr script of the key at (change, index).
 * The amounts and scripts of the spent outputs are part of what is hashed, so a wrong one gives a signature that no node accepts, and cannot make the signer sign something else.
 *
 * The signature hash is BLAKE2b-256 keyed with "TransactionSigningHash" (the fields and their order are those of rusty-kaspa consensus/core/src/hashing/sighash.rs, version 0), the
 * signature is BIP340 schnorr. The result is "KSIG" | 1 | n u8 | n x [ input index u8 | length u8 (66) | 0x41 | signature[64] | 0x01 ]: the signature scripts of the signed inputs. */

enum { KAS_OK = 0, KAS_ERR_PARSE = -1, KAS_ERR_UNSUPPORTED = -2, KAS_ERR_KEY = -3, KAS_ERR_SPACE = -4 };

#define KAS_MAX_IN 32
#define KAS_MAX_OUT 32

/* The secret key of address (change, index) of the account; 0, or non-zero for an error. */
typedef int (*kas_key_fn)(void *ctx, uint32_t change, uint32_t index, uint8_t key[32]);

int kaspa_summary(const uint8_t *tx, size_t len, kas_key_fn kf, void *ctx, tx_view *v);
int kaspa_sign(const uint8_t *tx, size_t len, kas_key_fn kf, void *ctx, uint8_t *out, size_t cap, size_t *outlen);
/* the signature hash of input `i` (for the tests) */
int kaspa_sighash(const uint8_t *tx, size_t len, int i, uint8_t hash[32]);
