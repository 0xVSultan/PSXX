#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/chains.h"
#include "sign/btc.h"
#include "sign/txview.h"

/* "Sign message" of the Bitcoin family (Bitcoin Core's signmessage, BIP137 headers): the hash is SHA-256d of  varint(len(magic)) || magic || varint(len(message)) || message,
 * with the magic "Bitcoin Signed Message:\n" ("Litecoin ...", "Dogecoin ...", "DarkCoin ..." for the others, Bitcoin Cash uses Bitcoin's), the signature is the compact form
 * header || r || s (65 bytes) and the text a wallet takes is its Base64. The header says what kind of address the key is: 31 + recovery id for P2PKH (compressed key),
 * 35 + id for P2SH-P2WPKH, 39 + id for P2WPKH. Taproot addresses (BIP322) are not supported. */

enum { BMSG_OK = 0, BMSG_ERR_UNSUPPORTED = -1, BMSG_ERR_KEY = -2, BMSG_ERR_SPACE = -3 };

/* The hash that is signed. */
void btcmsg_hash(const btc_net *net, const uint8_t *msg, size_t len, uint8_t hash[32]);
/* `address` is the address of the key as text (shown, so that the user sees which address signs). */
void btcmsg_summary(const btc_net *net, const char *address, const uint8_t *msg, size_t len, tx_view *v);
/* `kind` is the K_* of the chain table entry (K_P2PKH, K_P2SH_WPKH, K_P2WPKH, K_CASHADDR). sig65 = header || r || s. */
int btcmsg_sign(const btc_net *net, int kind, const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t sig65[65]);

/* BIP322, the "simple" variant, for native SegWit single key addresses: K_P2WPKH and K_P2TR (key path, the key tweaked with no script tree). The signature is the witness of the
 * to_sign transaction, consensus encoded (P2WPKH: 02 <DER signature + 01> <public key>; P2TR: 01 40 <BIP340 signature>); a wallet takes it as "smp" followed by its Base64.
 * Returns the witness length, or a BMSG_ERR_ code. `priv` is the untweaked key of the address. */
int btcmsg_sign322(int kind, const uint8_t *msg, size_t len, const uint8_t priv[32], uint8_t *out, size_t cap);
/* the pieces, public for the tests: the tagged hash of the message, and the txid of the to_spend transaction of a message hash and the script of the address */
void btcmsg322_hash(const uint8_t *msg, size_t len, uint8_t hash[32]);
void btcmsg322_spend_txid(const uint8_t *spk, size_t spklen, const uint8_t mh[32], uint8_t txid[32]);
