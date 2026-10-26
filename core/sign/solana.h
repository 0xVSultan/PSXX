#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Solana: the request is the serialised message (legacy, or version 0 with address table lookups) exactly as it is signed. The key
 * is the SLIP-10 ed25519 key of the path (m/44'/501'/0'/0'), its public key must be one of the signers of the message.
 * Shown: SOL transfers (System program), SPL token transfers (the Token and Token-2022 programs), the memo, the priority fee of the
 * ComputeBudget program. Any other instruction is listed by its program and signed blind (flagged). */
enum { SOL_OK = 0, SOL_ERR_PARSE = -1, SOL_ERR_NOT_SIGNER = -2, SOL_ERR_SPACE = -3 };

int solana_summary(const uint8_t *msg, size_t len, tx_view *v);
/* sig = the signature; tx (may be NULL) = the transaction for sendTransaction: the signature slots (ours filled, the others zero)
 * followed by the message. */
int solana_sign(const uint8_t *msg, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t *tx, size_t cap, size_t *txlen);
