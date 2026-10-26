#pragma once
#include <stddef.h>
#include <stdint.h>
#include "coin/bip32.h"
#include "coin/chains.h"
#include "sign/txview.h"
#include "sign/mswallet.h"

/* Bitcoin family transactions as PSBTs (BIP174, version 0): Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Cash.
 *
 * What is signed: inputs that pay to P2PKH, P2WPKH, P2SH-P2WPKH, P2TR (key path), and the script hash forms P2SH / P2WSH /
 * P2SH-P2WSH when the redeem / witness script is in the PSBT and holds one of our keys. Signature hash type "all" only (the
 * default; taproot also "default"). An input is ours if its BIP32 derivation record carries the fingerprint of our master key, the
 * path leads to the public key of the record, and that key fits the script of the spent output.
 *
 * Before anything is signed the previous transactions are checked: the txid of the full previous transaction must be the one the
 * input spends (for taproot the witness UTXO of the PSBT is enough, the signature hash commits to all the amounts and scripts).
 *
 * The result is a PSBT that carries only the new signatures (a combiner merges it with the original), and, when every input is a
 * single key kind of ours, the finished network transaction. */

typedef struct {
    const char *name, *sym;
    uint8_t     p2pkh, p2sh;        /* Base58 version bytes */
    const char *hrp;                /* bech32 prefix, NULL: no SegWit */
    const char *cash;               /* CashAddr prefix, NULL: Base58 only */
    uint8_t     forkid;             /* Bitcoin Cash: BIP143 digest with the fork id flag for every input */
    uint8_t     decimals;
} btc_net;

/* The network of a chain table entry ("btc84" ...), NULL for coins that are not of this family. */
const btc_net *btc_net_for(const chain_def *c);

#define PSBT_MAXIN 64
#define PSBT_MAXOUT 64

typedef struct {
    const uint8_t *buf;
    size_t         len;
    uint32_t       version, locktime;
    int            nin, nout;
    const uint8_t *vin;             /* the first input record of the unsigned transaction (41 bytes each) */
    const uint8_t *vout, *vout_end; /* the output records (value, script) */
    const uint8_t *in_map[PSBT_MAXIN];
    const uint8_t *out_map[PSBT_MAXOUT];
    const uint8_t *tx;              /* the unsigned transaction */
    size_t         txlen;
} psbt;

enum {
    BTC_OK = 0,
    BTC_ERR_PARSE = -1,             /* not a PSBT, or damaged */
    BTC_ERR_UNSUPPORTED = -2,       /* PSBT version 2, too many inputs ... */
    BTC_ERR_UTXO = -3,              /* previous transaction missing or not the one spent */
    BTC_ERR_SIGHASH = -4,           /* a signature hash type that is not "all" */
    BTC_ERR_NOKEY = -5,             /* nothing in it that we can sign */
    BTC_ERR_SPACE = -6,             /* output buffer too small */
    BTC_ERR_KEY = -7,               /* key derivation failed */
    BTC_ERR_NOSIG = -8              /* finishing: an input has no signature */
};

int psbt_parse(psbt *p, const uint8_t *buf, size_t len);

/* A raw secp256k1 key (WIF, nsec...) instead of the master of a seed: a PSBT of such a wallet has no BIP32 records. With the key set, an input is ours when the output it spends pays
 * to one of the four single key scripts of the key (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR with the key tweaked and no script tree), and an output is ours (change) by the same test. Then
 * psbt_summary and psbt_sign are called with a node of depth 0 whose key is the raw key (`master`). NULL clears the mode; call it again when the PSBT is done. */
int psbt_raw_key(const uint8_t priv[32]);

/* The summary for the screen. `master` may be NULL (then nothing is recognised as change). Returns BTC_OK or an error. */
int psbt_summary(const psbt *p, const btc_net *net, const bip32_node *master, tx_view *v);

/* Signs every input that is ours. out: the PSBT with the signatures; tx (may be NULL): the network transaction when it can be
 * finished, its length in *txlen (0 when it cannot). *nsigned counts the signatures. Returns BTC_OK, or BTC_ERR_NOKEY if no input
 * was ours, or another error. */
int psbt_sign(const psbt *p, const btc_net *net, const bip32_node *master, uint8_t *out, size_t cap, size_t *outlen,
              uint8_t *tx, size_t txcap, size_t *txlen, int *nsigned);

/* The registered multisig wallets (core/sign/mswallet.h; the records are checked against the seed by the caller): their addresses are recognised by their script, the
 * inputs and the change of a registered wallet are named in the summary, a multisig input of any other wallet is warned about (TXW_UNREG_MULTISIG). The list must stay
 * valid while PSBTs are summarised or signed; at most 4 wallets are used. NULL / 0 clears it. */
void psbt_set_wallets(const ms_policy *w, int n);
/* the address (or a description) of an output script, as the summary writes it */
void btc_spk_text(const btc_net *net, const uint8_t *spk, size_t n, char *out, size_t cap);
