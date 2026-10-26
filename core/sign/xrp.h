#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* XRP Ledger: the request is the unsigned transaction in the canonical binary form (what the libraries call the signing blob
 * without the prefix), with SigningPubKey = the compressed public key of our key and no TxnSignature. The signature hash is the
 * first half of SHA-512 over the prefix 0x53545800 and that blob. The result is the signed blob (tx_blob) with the TxnSignature
 * field in its place. Payments are shown in full (XRP and issued currencies); every other transaction type is signed blind. */
enum { XRP_OK = 0, XRP_ERR_PARSE = -1, XRP_ERR_SPACE = -2, XRP_ERR_KEY = -3, XRP_ERR_PUBKEY = -4 };

int xrp_summary(const uint8_t *tx, size_t len, tx_view *v);
int xrp_sign(const uint8_t *tx, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap, size_t *outlen);
