#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/chains.h"
#include "sign/txview.h"

/* One entry point for every coin: a request in the container format below is summarised for the screen and, once the user has
 * confirmed, signed. The container is what a host program writes to the memory card (tools/psxx_tx.py):
 *     "PSXQ" | version (1) | kind | chain id (8 bytes, NUL padded: "btc84", "eth", "sol" ...) | length of the path text (u8) | the
 *     path text | payload length (u32 LE) | payload
 * The path is the BIP32 path of the account key ("m/44'/60'/0'/0/0"), the junctions of the sr25519 coins ("//polkadot//0"), or for
 * Cardano the payment path, optionally followed by ";" and the stake key path. Bitcoin family and Zcash requests carry their own
 * derivation paths inside the payload; the path text may be empty there.
 * kind: 0 a transaction (the payload as its module describes it), 1 a message (EIP-191), 2 EIP-712 hashes (domain, struct hash).
 * The payload of Stellar is: passphrase length (u8), the network passphrase, the XDR of the transaction.
 * Zcash Orchard is the chain "zecu" with the path of the account (m/32'/133'/0'), Monero the chain "xmr" (it signs with the 25 word
 * Monero seed, hd_secret.xmr_seed, not with the BIP39 seed): their payloads are described in sign/zec.h and sign/xmr.h. */

enum { SREQ_TX = 0, SREQ_MSG = 1, SREQ_TYPED = 2, SREQ_AUTH = 3 };

enum {
    SIGN_OK = 0,
    SIGN_ERR_FORMAT = -1,           /* not a request */
    SIGN_ERR_CHAIN = -2,            /* unknown coin */
    SIGN_ERR_PATH = -3,             /* bad path */
    SIGN_ERR_KIND = -4,             /* this coin cannot do that */
    SIGN_ERR_PARSE = -5,            /* the payload is not a valid transaction of the coin */
    SIGN_ERR_KEY = -6,              /* the key could not be derived, or it is not the one the transaction names */
    SIGN_ERR_NOTMINE = -7,          /* nothing in the transaction belongs to this seed */
    SIGN_ERR_SPACE = -8,
    SIGN_ERR_UNSUPPORTED = -9,      /* a transaction feature that is refused (shielded Zcash, blob transactions ...) */
    SIGN_ERR_UTXO = -10,            /* Bitcoin: a previous transaction is missing or is not the one spent */
    SIGN_ERR_MISMATCH = -11,        /* Monero: the outputs or amounts do not match what the request says */
    SIGN_ERR_NOSEED = -12,          /* the request needs a seed that was not loaded (BIP39 words, or the 25 Monero words) */
    SIGN_ERR_MSGSIZE = -13          /* a Nostr message over 4096 bytes: it is neither encrypted nor decrypted here */
};

typedef struct {
    const chain_def *chain;
    int              kind;
    char             path[64];
    const uint8_t   *payload;
    size_t           plen;
} sign_req;

typedef struct {
    uint8_t *buf;  size_t cap;      /* the result goes here */
    uint8_t *scratch; size_t scap;  /* temporary space (4 KB and more; 8 KB for large Bitcoin transactions) */
    size_t   len;
    int      text;                  /* 1: the result is JSON text */
    const char *label;
} sign_result;

int sign_req_parse(sign_req *q, const uint8_t *b, size_t n);
/* The summary for the screen. */
int sign_summary(const sign_req *q, const hd_secret *s, tx_view *v);
/* Sign. */
int sign_execute(const sign_req *q, const hd_secret *s, sign_result *r);
/* A readable name of an error. */
const char *sign_error_text(int err);
