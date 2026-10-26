#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/path.h"

/* A table of coins and how to turn a BIP39 secret into their first address; the same table drives the chain list and the
 * path editor of the wallet. Everything it outputs is public. The secrets stay in hd_secret, which the caller wipes. */

enum chain_curve {
    CV_SECP256K1,       /* BIP32 */
    CV_ED25519,         /* SLIP-10: hardened indices only */
    CV_ICARUS,          /* Cardano: BIP32-Ed25519 from the BIP39 entropy */
    CV_SR25519,         /* Substrate: Schnorrkel from the BIP39 entropy, junction path */
    CV_ORCHARD,         /* Zcash Orchard: ZIP-32 */
    CV_TON              /* TON: its own mnemonic -> key rule, or SLIP-10 */
};

enum chain_kind {
    K_P2PKH, K_P2SH_WPKH, K_P2WPKH, K_P2TR, K_CASHADDR, K_ZEC_T,
    K_EVM, K_TRON, K_XRP, K_COSMOS, K_NOSTR, K_KASPA,
    K_SOLANA, K_STELLAR, K_NEAR, K_SS58_ED,
    K_CARDANO, K_SS58_SR, K_TON, K_ORCHARD,
    K_PUBHEX,           /* the public key in hex (33 bytes compressed for secp256k1, 32 for ed25519), for custom coins */
    K_MONERO,           /* Monero: only in signing requests (its own 25 word seed, not a BIP39 secret) */
    K_MWEB              /* Litecoin MimbleWimble stealth address: the path is the scan key m/0'/100'/0' (the spend key is its sibling /1'),
                           an optional fourth level is the address index (default 2, the first receiving address) */
};

typedef struct {
    const char *id;         /* short, unique: "btc84", "sol" */
    uint16_t    name;       /* what the list shows: the identifier of the text (core/tr.h), T(c->name) is the text */
    uint8_t     curve, kind;
    uint16_t    param;      /* P2PKH / P2SH version (one byte, or two above 255), SS58 prefix, ... */
    const char *hrp;        /* bech32 prefix or CashAddr prefix, else NULL */
    const char *path;       /* the usual first account, e.g. "m/84'/0'/0'/0/0" */
    uint8_t     group;      /* the section of the chain list (CHAIN_GROUPS) */
} chain_def;

extern const chain_def CHAINS[];
extern const int NCHAINS;
#define NCHAIN_GROUPS 5               /* the last one ("Custom") holds only the user defined coin of the wallet */
extern const uint16_t CHAIN_GROUPS[NCHAIN_GROUPS];      /* the identifiers of the names of the sections (T(CHAIN_GROUPS[g])) */

typedef struct {
    uint8_t     seed[64];       /* BIP39 seed (with the passphrase) */
    uint8_t     entropy[32];    /* BIP39 entropy: Cardano, Substrate and TON start from this, not from the seed */
    int         entlen;         /* 0 when unknown */
    const char *passphrase;     /* the BIP39 passphrase used for the seed ("" for none) */
    uint8_t     xmr_seed[32];   /* the 32 bytes of a Monero 25 word mnemonic (signer only) */
    int         xmr_ok;         /* xmr_seed holds a key */
    int         no_bip;         /* seed[] and entropy[] are not set (only the Monero words were typed) */
    uint8_t     raw[64];        /* a single key without derivation (TON, an imported key), signer only; 64 bytes for a Cardano extended key */
    int         raw_curve;      /* 0: none, 1: ed25519 seed, 2: secp256k1 secret key, 3: sr25519 mini secret (the junctions of a request still apply), 4: Orchard spending key (32 bytes),
                                 * 5: Cardano extended key kL | kR (64 bytes, no derivation); then the path of a request is not used (the sr25519 junctions are) */
} hd_secret;

enum {
    CHAIN_ERR_PATH = -2,        /* the path does not suit the coin (not hardened enough, too short) */
    CHAIN_ERR_UNSUPPORTED = -3,
    CHAIN_ERR_DERIVE = -4,      /* a key could not be derived (practically never) */
    CHAIN_ERR_NOENTROPY = -5,
    CHAIN_ERR_SPACE = -1
};

const chain_def *chain_find(const char *id);
/* Whether the raw key of `s` can sign for coin `c`: the curve fits and the coin takes one plain key (not the PSBT families, Zcash, Monero). */
int chain_raw_ok(const chain_def *c, const hd_secret *s);   /* (not Zcash transparent, Monero, MWEB, custom coins) */
/* Parses the coin's usual path into p. */
int chain_default_path(const chain_def *c, hd_path *p);
/* The address of path p. Returns the string length or a CHAIN_ERR_ code. */
int chain_address(char *out, size_t cap, const chain_def *c, const hd_secret *s, const hd_path *p);

/* The same with the path as text: a BIP32 path ("m/44'/0'/0'/0/0") or, for the sr25519 coins, junctions ("//polkadot//0/1"). */
int chain_address_str(char *out, size_t cap, const chain_def *c, const hd_secret *s, const char *path);

/* Building blocks, public for the tests. */
int slip10_ed25519(uint8_t key[32], const uint8_t *seed, size_t seedlen, const hd_path *p);    /* 0, or CHAIN_ERR_PATH */
int base32_encode(const uint8_t *in, size_t len, char *out, size_t cap);                       /* RFC 4648, no padding */
uint16_t crc16_xmodem(const uint8_t *p, size_t n);
int cashaddr_p2pkh(char *out, size_t cap, const char *prefix, const uint8_t h160[20]);
int kaspa_address(char *out, size_t cap, const char *prefix, const uint8_t xonly[32]);
/* any address version: 0 schnorr public key (32 bytes), 1 ECDSA public key (33), 8 script hash (32) */
int kaspa_address_v(char *out, size_t cap, const char *prefix, int version, const uint8_t *data, size_t dlen);                      /* kaspa:q... of a schnorr x-only public key */
int xrp_address(char *out, size_t cap, const uint8_t h160[20]);                                         /* classic r... address of an account id */
int cashaddr_encode(char *out, size_t cap, const char *prefix, int type, const uint8_t h160[20]);     /* type 0 P2PKH, 1 P2SH */
int ss58_encode(char *out, size_t cap, uint16_t prefix, const uint8_t pub[32]);

/* The secret key of the address of path p (junctions for the sr25519 coins), in the form wallets import:
 * WIF (Bitcoin family), nsec (Nostr), hex (Ethereum family, Tron, XRP, Cosmos), base58 keypair (Solana), S... (Stellar),
 * "ed25519:" key (NEAR), addr_xsk (Cardano), secret URI (Substrate). *label names the form. Zcash Orchard returns
 * CHAIN_ERR_UNSUPPORTED (restore it from the words). Returns the string length or a CHAIN_ERR_ code. */
int chain_secret(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p, const char *junctions);

/* View-only keys of a chain: what lets another program see the incoming payments of the address but not spend (Litecoin MWEB: the scan secret and the spend public key, one string,
 * two hex numbers with a space between them). chain_has_view_keys says whether the chain has them; chain_view_keys returns the string length, or CHAIN_ERR_UNSUPPORTED. The
 * secret key of chain_secret for MWEB is the pair that spends: the scan secret and the spend secret. */
int chain_has_view_keys(const chain_def *c);
/* The default path of the second wallet family of a chain (MWEB: Cake Wallet and Electrum-LTC, m/1000'/0'/1), or NULL when there is none. */
const char *chain_alt_path(const chain_def *c);
int chain_view_keys(char *out, size_t cap, const char **label, const chain_def *c, const hd_secret *s, const hd_path *p);

/* The key that signs for the address of path p (junctions for the sr25519 coins): secp256k1 chains the 32 byte private key, ed25519
 * chains (SLIP-10) the 32 byte seed, Cardano the 96 byte node (kL | kR | chain code), sr25519 the 32 byte secret scalar. Returns the
 * length of the key or a CHAIN_ERR_ code. The caller wipes it. */
int chain_signing_key(uint8_t key[96], const chain_def *c, const hd_secret *s, const hd_path *p, const char *junctions);
