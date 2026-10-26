#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Monero transaction signing (RingCT, CLSAG; bulletproofs+ are made by the host).
 *
 * The cold-signing split: the online wallet (view key only) chooses the ring members, makes the transaction secret key r of every
 * output and the range proof, and sends all of it to the signer. The signer
 *   - recomputes every output (one time key, view tag, commitment, encrypted amount, transaction public key, payment id) from the
 *     destination address, the amount and r, and refuses the request unless the transaction prefix and the data it signs carry exactly
 *     those values, so the screen shows what is really paid;
 *   - recomputes for every input the one time key of the output being spent from its own keys, the key image, the amount and the
 *     commitment, and refuses unless they match the ring and the key image in the prefix;
 *   - checks that the inputs equal the outputs plus the fee;
 *   - picks the pseudo output commitments and makes one CLSAG signature per input (nonces are derived deterministically from the
 *     secrets and the message, so no random source is needed).
 * What it cannot check: that the ring members are real outputs of the chain (the host could pick decoys it knows: privacy, not funds),
 * and that the range proof is valid (the transaction is then rejected by the network).
 *
 * Request payload ("XMRQ", all integers little endian):
 *     "XMRQ" | version 1 | rct type (5 CLSAG, 6 CLSAG with bulletproofs+) | inputs (u8) | outputs (u8) | fee (u64)
 *     | prefix length (u16) | transaction prefix (as serialised for the transaction hash)
 *     | proof length (u16, a multiple of 32) | the range proof as it enters the signed message: A, A1, B, r1, s1, d1, L..., R... (bulletproofs+)
 *     per output:  netbyte (u8) | spend public key (32) | view public key (32) | flags (u8) | amount (u64) | r (32)
 *                  | [payment id (8) if flags & 2] | [account (u32), index (u32) if flags & 4]
 *                  flags: 1 the transaction public key of this output is in the additional keys of the extra (else the main one),
 *                  2 an encrypted payment id goes to this destination, 4 the destination claims to be our own (sub)address
 *     per input:   ring size (u8) | real index (u8) | ring: (one time key, commitment) x ring size
 *                  | transaction public key R of the output being spent (32) | its index in that transaction (u32)
 *                  | account, index of our (sub)address that received it (u32, u32) | the encrypted amount (8)
 * Result ("XMRS"): "XMRS" | 1 | inputs (u8), then per input: ring size (u8) | pseudo output commitment (32) | key image (32)
 *                  | D / 8 (32) | c1 (32) | s (32 x ring size). */

enum {
    XMR_OK = 0,
    XMR_ERR_PARSE = -1,
    XMR_ERR_UNSUPPORTED = -2,
    XMR_ERR_KEY = -3,            /* an input is not ours, or its key image does not match */
    XMR_ERR_AMOUNT = -4,         /* the amount of an input does not fit its commitment */
    XMR_ERR_OUTPUT = -5,         /* the prefix or the extra does not carry what the outputs should */
    XMR_ERR_BALANCE = -6,        /* inputs != outputs + fee */
    XMR_ERR_SPACE = -7
};

#define XMR_MAXIN 8
#define XMR_MAXOUT 16
#define XMR_MAXRING 16

/* spend_seed: the 32 bytes of the 25 word mnemonic */
/* The summary keeps its checks for the signature of the same request; this wipes them (the signature does it too). */
void xmr_tx_forget(void);
int xmr_tx_summary(const uint8_t *req, size_t len, const uint8_t spend_seed[32], tx_view *v);
int xmr_tx_sign(const uint8_t *req, size_t len, const uint8_t spend_seed[32], uint8_t *out, size_t cap, size_t *outlen);
