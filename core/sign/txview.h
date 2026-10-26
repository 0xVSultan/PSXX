#pragma once
#include <stddef.h>
#include <stdint.h>

/* What a signer shows the user before it signs: the same record for every coin, filled by the parser of the coin. */

#define TXV_OUTS 16                 /* outputs listed one by one */
#define TXV_NOTES 6                 /* extra lines */

enum {
    TXW_UNKNOWN_SCRIPT = 1u << 0,   /* an output or input script of a kind the parser does not know */
    TXW_NO_FEE         = 1u << 1,   /* the fee cannot be told (an input amount is missing) */
    TXW_HIGH_FEE       = 1u << 2,   /* the fee is more than 10 % of what goes out, or the fee rate looks absurd */
    TXW_UNVERIFIED     = 1u << 3,   /* an amount was taken from data that could not be checked */
    TXW_BLIND          = 1u << 4,   /* only a hash is signed: the content cannot be shown */
    TXW_DATA           = 1u << 5,   /* the transaction carries data / calls a contract */
    TXW_NOT_MINE       = 1u << 6,   /* no input of ours */
    TXW_NONSTD_SIGHASH = 1u << 7,   /* a signature hash type other than "all" */
    TXW_TRUNCATED      = 1u << 8,   /* more outputs than the list holds */
    TXW_DELEGATION     = 1u << 9,   /* control of an account is handed over: EIP-7702 (its code becomes a contract's), Tron permissions (other keys may sign) */
    TXW_UNREG_MULTISIG = 1u << 10   /* an input is a multisig of a wallet that is not registered on this device: the other keys of the script are not known to be the owner's */
};

typedef struct {
    char    to[112];                /* address or description */
    char    amount[128];            /* "0.001 BTC"; a 256 bit token amount needs 78 digits, an IBC denom 68 characters */
    uint8_t mine;                   /* change back to our own key (verified), shown but not part of what is sent */
} txv_out;

typedef struct {
    char     title[48];             /* "Bitcoin PSBT" */
    int      nout;                  /* entries of out[] in use */
    int      nmore;                 /* outputs not listed */
    txv_out  out[TXV_OUTS];
    char     fee[44];               /* "" when unknown */
    char     total[44];             /* what leaves the wallet to other addresses, "" when unknown */
    int      ninputs, nsign;        /* inputs in all / inputs that we can sign */
    uint32_t warn;                  /* TXW_ flags */
    char     note[TXV_NOTES][96];   /* extra lines: chain id, nonce, memo, call data, fee rate, lock time ... */
    int      nnote;
    int      text_len;              /* a long text (a message, a note) for pages of its own: it is in txv_text, text_len bytes; 0 when there is none */
} tx_view;

/* Buffers that the signer lends to the summaries (both may be NULL, as in the tests): txv_text receives a long text for the text pages (txv_set_text), txv_work is room for a parser
 * that needs more than its stack (the Nostr summaries: a request of one card block, 4096 bytes of text). */
extern char *txv_text;
extern size_t txv_text_cap;
extern uint8_t *txv_work;
extern size_t txv_work_cap;
/* The text for the text pages: the bytes with the control characters (a line break, a tab) as spaces, ended by 0. Returns 0, or -1 when there is no buffer or it is too small (no text pages then). */
int txv_set_text(tx_view *v, const uint8_t *s, size_t n);

/* one view that the signers use to check a request before they sign (they call their own summary): shared to save RAM */
extern tx_view txv_shared;

/* "value / 10^decimals" with the trailing zeros cut off, then " SYM" (sym may be NULL). value is `n` bytes, big endian (n <= 32).
 * Returns the length. */
int txv_amount_be(char *out, size_t cap, const uint8_t *value, size_t n, int decimals, const char *sym);
int txv_amount_u64(char *out, size_t cap, uint64_t value, int decimals, const char *sym);
void txv_note(tx_view *v, const char *s);
void txv_clear(tx_view *v);
/* append an output line (to, amount); past TXV_OUTS it counts the rest and warns */
void txv_add_out(tx_view *v, const char *to, const char *amount);
/* byte helpers of the parsers: a little endian u64, and a Bitcoin compact size (0 or -1 at the end of the data) */
uint64_t rd64(const uint8_t *p);
int rd_cs(const uint8_t **pp, const uint8_t *end, uint64_t *v);
