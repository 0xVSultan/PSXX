#pragma once
#include <stdint.h>

/* First receiving address of the standard accounts, derived from a BIP39 seed (64 bytes). Everything here is public.
 *  - Bitcoin legacy  m/44'/0'/0'/0/0   P2PKH (1...)
 *  - Bitcoin segwit  m/84'/0'/0'/0/0   P2WPKH (bc1q...)
 *  - Ethereum / ETC  m/44'/60'/0'/0/0  EIP-55
 *  - Dogecoin        m/44'/3'/0'/0/0   P2PKH (D...)
 *  - Nostr (NIP-06)  m/44'/1237'/0'/0/0 npub1...
 */
#define WALLET_STEPS 5

typedef struct {
    char btc_legacy[40];
    char btc_segwit[48];
    char eth[48];
    char doge[40];
    char npub[72];
} wallet_addrs;

typedef void (*wallet_progress_fn)(int step, int total, void *user);

/* Returns 0, or -1 if a derivation failed (astronomically unlikely). `progress` (optional) is called before each coin. */
int wallet_derive(wallet_addrs *out, const uint8_t seed[64], wallet_progress_fn progress, void *user);
