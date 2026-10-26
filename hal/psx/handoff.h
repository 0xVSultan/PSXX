#pragma once
#include "coin/chains.h"

/* The seed that the generator (the base image) hands to the signer (the overlay) when the user chooses "sign with this seed" on an address page. The overlay
 * region is the signer's alone while it runs, so the language module cannot be loaded with it: whatever list the seed was typed in, it is typed (and checked) in the generator, and
 * the signer receives the result: the BIP39 seed and entropy, the Monero key, or a raw key, with the passphrase. The signer takes it at its start and wipes it; the generator wipes
 * it when the signer was not loaded and when it restarts. */
typedef struct {
    int       valid;
    hd_secret hs;                  /* hs.passphrase is not valid here: the text is in pass */
    char      pass[64];
} psxx_handoff_t;

extern psxx_handoff_t psxx_handoff;
