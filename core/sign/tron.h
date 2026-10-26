#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Tron: the request is the raw_data of a transaction (protobuf, as the full node builds it); what is signed is its SHA-256, the
 * transaction id. Shown: TRX transfers, TRC-10 transfers and TRC-20 transfer() calls; every other contract is signed blind
 * (flagged) because its parameters cannot be told here. One contract per transaction (the network allows no more). */
enum { TRON_OK = 0, TRON_ERR_PARSE = -1, TRON_ERR_UNSUPPORTED = -2, TRON_ERR_KEY = -3 };

int tron_summary(const uint8_t *raw, size_t len, tx_view *v);
/* sig65 = r || s || recovery id (0 / 1), the form TronWeb produces; txid = SHA-256 of raw_data. */
int tron_sign(const uint8_t *raw, size_t len, const uint8_t priv[32], uint8_t sig65[65], uint8_t txid[32]);
