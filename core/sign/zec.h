#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/bip32.h"
#include "sign/txview.h"

/* Zcash transparent transactions (t-addresses): version 5 (ZIP-244, NU5 and later) and version 4 (Sapling, ZIP-243), without any
 * shielded part. Shielded (Sapling, Orchard) parts are refused: this device cannot check what they send.
 *
 * The request is a small container:
 *     "ZTXR" | consensus branch id (u32 LE) | length of the transaction (u32 LE) | the unsigned transaction (empty scriptSigs)
 *     then, for every input: amount (u64 LE) | scriptPubKey (compact size, bytes) | depth (u8) | path (depth u32 LE)
 * For version 5 the branch id must be the one in the transaction. The signature hash commits to every amount and script, so a wrong
 * amount makes the signatures useless instead of hiding a fee. Only P2PKH inputs of our own keys, signature hash type "all". The
 * result is the signed transaction (scriptSig = signature, public key).
 *
 * Orchard (version 5): the transaction may carry Orchard actions. The "transaction" of the request then has the tail
 *     00 (Sapling spends) | 00 (Sapling outputs) | compact size n | n actions of 820 bytes (ZIP-225: cv, nullifier, rk, cmx, ephemeral key,
 *     580 bytes of encrypted note, 80 bytes of outgoing ciphertext) | flags (u8) | value balance (i64 LE) | anchor (32)
 * with no proof and no signature (the signature hash does not cover them). After the inputs the request lists the spends to authorize:
 *     count (u8) | per spend: action index (u8) | alpha (32 bytes), the randomizer of the action
 * The signer checks that rk = [ask + alpha] G for every one of them (the action spends from this account) and shows the transparent
 * outputs and the fee (which follows from the value balance). It opens the shielded outputs with the outgoing viewing keys of the account
 * (external and internal) and checks each against its action (shared secret, ephemeral key, note commitment), so the recipients and
 * amounts shown are those the transaction commits to; for the spent notes it checks that the note the host describes has the nullifier
 * of the action (so that its value is true). Outputs it cannot open (padding, or made with another key) are counted. If the notes spent
 * are not all described, or the value spent exceeds what the readable outputs and the value balance account for, the request is blind. The result is
 *     "ZORS" | transparent inputs (u8) | per input: scriptSig length (u8), scriptSig | spends (u8) | per spend: action index (u8), RedPallas
 *     signature (64) */
enum {
    ZEC_OK = 0,
    ZEC_ERR_PARSE = -1,
    ZEC_ERR_UNSUPPORTED = -2,       /* version, shielded parts, a script that is not P2PKH */
    ZEC_ERR_NOKEY = -3,             /* an input is not ours */
    ZEC_ERR_KEY = -4,
    ZEC_ERR_SPACE = -5,
    ZEC_ERR_MISMATCH = -6           /* an Orchard output or spent note does not fit its action */
};

/* The keys that may sign a request: the BIP32 master of the transparent inputs, the Orchard spending key (32 bytes, ZIP-32) of the
 * account for the spends. Either may be NULL. */
typedef struct {
    const bip32_node *master;
    const uint8_t    *orchard_sk;
    const uint8_t    *raw;          /* a raw secp256k1 key instead of the master: every transparent input must pay to it (no path is used) */
} zec_keys;

int zec_summary(const uint8_t *req, size_t len, const zec_keys *k, tx_view *v);
int zec_sign(const uint8_t *req, size_t len, const zec_keys *k, uint8_t *out, size_t cap, size_t *outlen);
