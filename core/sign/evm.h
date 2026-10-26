#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Ethereum and the EVM chains (Ethereum Classic, BNB Chain, Polygon, Arbitrum, Optimism, Base, Avalanche ... by chain id).
 *
 * The request is the unsigned transaction exactly as it is hashed for signing: a legacy transaction (RLP list of 6 fields, or the
 * 9 fields of EIP-155 with chain id, 0, 0), or a typed one: 0x01 || RLP (EIP-2930) or 0x02 || RLP (EIP-1559). Types that carry
 * more than the user can check here (blobs) are refused. EIP-7702 set-code transactions (0x04 || RLP) are signed, with every authorization listed and a warning. The signature hash is Keccak-256 of those bytes, so
 * nothing the user sees can differ from what is signed. */

enum { EVM_OK = 0, EVM_ERR_PARSE = -1, EVM_ERR_UNSUPPORTED = -2, EVM_ERR_SPACE = -3, EVM_ERR_KEY = -4 };

int evm_summary(const uint8_t *tx, size_t len, tx_view *v);

/* Sign it: out is the signed transaction (for eth_sendRawTransaction), sig65 the signature r || s || v with v the recovery id
 * (0 / 1), the same value as the yParity of typed transactions. */
int evm_sign_tx(const uint8_t *tx, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap, size_t *outlen, uint8_t sig65[65]);

/* An EIP-7702 authorization on its own: the payload is rlp([chain_id, address, nonce]); the hash is Keccak-256(0x05 || payload) and sig65 is r || s || y_parity (0 / 1). The summary
 * says, with a strong warning, that the account's code will point to `address` (chain id 0: on every chain; address 0: the delegation is cleared). */
int evm_auth_summary(const uint8_t *payload, size_t len, tx_view *v);
int evm_auth_sign(const uint8_t *payload, size_t len, const uint8_t priv[32], uint8_t sig65[65]);

/* EIP-191 personal_sign: the hash is Keccak-256("\x19Ethereum Signed Message:\n" || decimal length || message); v = 27 + recovery id. */
void evm_message_summary(const uint8_t *msg, size_t len, tx_view *v);
int evm_personal_sign(const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t sig65[65]);

/* EIP-712: Keccak-256(0x19 0x01 || domain separator || struct hash). Only the two hashes are known here: a blind signature. */
void evm_typed_summary(tx_view *v);
int evm_typed_sign(const uint8_t domain[32], const uint8_t struct_hash[32], const uint8_t priv[32], uint8_t sig65[65]);

/* EIP-55 checksummed address "0x..." of 20 bytes into out (43 bytes with the NUL). */
void evm_checksum_address(char out[43], const uint8_t a[20]);
