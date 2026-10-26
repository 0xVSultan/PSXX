#pragma once
#include <stdint.h>
#include "coin/orchard.h"

/* Reading an Orchard action with the keys of the wallet: what a signer needs to show the recipients and amounts of a shielded
 * transaction instead of signing blind.
 * An action is 820 bytes (ZIP-225): cv (32) | nullifier (32) | rk (32) | cmx (32) | ephemeral key (32) | encrypted note (580) |
 * outgoing ciphertext (80). */
#define ORCHARD_ACTION_LEN 820

typedef struct {
    uint8_t  d[11];
    uint8_t  pk_d[32];          /* the encoding of the point */
    uint64_t v;
    uint8_t  rseed[32];
} orch_note;

enum {
    ORCH_OK = 0,
    ORCH_NOT_OURS = -1,         /* the outgoing ciphertext does not open with this key: padding, or an output made with another key */
    ORCH_BAD = -2           /* it opens, but the note does not match the action (a host that lies): refuse the transaction */
};

/* The output of an action, opened with an outgoing viewing key (ovk) and checked completely: the shared secret and the ephemeral key,
 * the note commitment against cmx. About 8 seconds on the PSX. */
int orchard_open_output(orch_note *n, const uint8_t *action, const uint8_t ovk[32]);

/* A note we spend: from the plaintext the host gives, check that it has the nullifier of the action (so its value is the true one).
 * ivk: the incoming viewing key the note was received with, nk the nullifier key. 0 when it matches. */
int orchard_check_spend(const uint8_t *action, const uint8_t d[11], uint64_t v, const uint8_t rseed[32], const uint8_t rho[32],
                        const uint8_t ivk[32], const uint8_t nk[32]);

/* 1 when the address (d, pk_d) is the one of the incoming viewing key ivk */
int orchard_is_address_of(const uint8_t d[11], const uint8_t pk_d[32], const uint8_t ivk[32]);
