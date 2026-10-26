#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Polkadot and Kusama (Substrate): the request is the signing payload of an extrinsic (call, extra, additional signed data); a
 * payload longer than 256 bytes is hashed with BLAKE2b-256 first, as the runtime verifies it. The call cannot be decoded without
 * the metadata of the runtime, so everything is signed blind (flagged); a Balances transfer is recognised by its call indices of the
 * current runtimes and shown with that caveat. The signature is the MultiSignature: 0x00 + 64 bytes (ed25519) or 0x01 + 64 (sr25519). */
enum { DOT_OK = 0, DOT_ERR_PARSE = -1 };

enum { DOT_CHAIN_POLKADOT = 0, DOT_CHAIN_KUSAMA = 1 };

int polkadot_summary(const uint8_t *payload, size_t len, int chain, tx_view *v);
void polkadot_sign_ed25519(uint8_t sig65[65], const uint8_t seed[32], const uint8_t *payload, size_t len);
void polkadot_sign_sr25519(uint8_t sig65[65], const uint8_t scalar[32], const uint8_t *payload, size_t len);
