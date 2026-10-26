#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Stellar: the request is the XDR of the Transaction (the body of an envelope of type ENVELOPE_TYPE_TX) and the network passphrase
 * ("Public Global Stellar Network ; September 2015"). What is signed is SHA-256(SHA-256(passphrase) || 00 00 00 02 || XDR).
 * Shown: payments and account creation (with their assets), account merges, trust lines, the memo and the fee; the first operation
 * of another kind is listed by its type and the transaction is signed blind from there on (flagged). */
enum { XLM_OK = 0, XLM_ERR_PARSE = -1 };

int stellar_summary(const uint8_t *tx, size_t len, tx_view *v);
/* sig = the 64 byte signature, hint = the last four bytes of the public key (for the DecoratedSignature). */
int stellar_sign(const uint8_t *tx, size_t len, const char *passphrase, const uint8_t seed[32], uint8_t sig[64], uint8_t hint[4]);
/* The G... address of a public key (56 characters + NUL; cap at least 57). */
int stellar_address(char *out, size_t cap, const uint8_t pub[32]);
