#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Cosmos SDK chains (Cosmos Hub, Osmosis ...), SIGN_MODE_DIRECT: the request is the SignDoc (protobuf: body_bytes, auth_info_bytes,
 * chain_id, account_number), the signature is ECDSA over its SHA-256, 64 bytes r || s with low S. Bank sends are shown with their
 * recipients and amounts; every other message is listed by its type and signed blind. */
enum { COS_OK = 0, COS_ERR_PARSE = -1, COS_ERR_SPACE = -2, COS_ERR_KEY = -3 };

int cosmos_summary(const uint8_t *signdoc, size_t len, tx_view *v);
/* sig64 = r || s; txraw (may be NULL) = the TxRaw (body_bytes, auth_info_bytes, signature) ready for broadcasting. */
int cosmos_sign(const uint8_t *signdoc, size_t len, const uint8_t priv[32], uint8_t sig64[64], uint8_t *txraw, size_t cap, size_t *txlen);
