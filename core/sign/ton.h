#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* TON wallet messages: the request is a BOC (bag of cells) with the signing message of the wallet, the root cell whose hash the wallet
 * contract checks: wallet v4R2 (subwallet id, valid until, seqno, op 0, then mode + message per reference) or wallet v5R1 (op "sign",
 * wallet id, valid until, seqno, the linked list of send actions). What is signed is the 32 byte representation hash of the root cell
 * with Ed25519; the host puts the signature into the message body. Shown: every internal message with its recipient (as the base64
 * address), amount in TON, text comment, and jetton transfers (amount in the units of the token, recipient). Anything else is signed
 * blind (flagged). */
enum { TON_SIGN_OK = 0, TON_SIGN_ERR_PARSE = -1 };

int ton_summary(const uint8_t *boc, size_t len, tx_view *v);
int ton_sign(const uint8_t *boc, size_t len, const uint8_t seed[32], uint8_t sig[64], uint8_t hash[32]);
