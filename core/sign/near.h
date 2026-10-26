#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* NEAR: the request is the borsh serialised Transaction (signer id, public key, nonce, receiver id, block hash, actions). What is
 * signed is SHA-256 of those bytes. The public key in the transaction must be ours. Shown: transfers, function calls (method, size
 * of the arguments, gas, deposit), key additions (a full access key is flagged loudly), key deletions, account deletion. Anything
 * else is signed blind (flagged). */
enum { NEAR_OK = 0, NEAR_ERR_PARSE = -1, NEAR_ERR_KEY = -2, NEAR_ERR_SPACE = -3 };

int near_summary(const uint8_t *tx, size_t len, tx_view *v);
/* out = the SignedTransaction (the transaction followed by key type 0 and the 64 byte signature); sig = the signature. */
int near_sign(const uint8_t *tx, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t *out, size_t cap, size_t *outlen);
