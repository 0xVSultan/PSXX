#include "coin/wallet.h"
#include "coin/addr.h"
#include "coin/bip32.h"
#include "ec/secp256k1.h"
#include "util.h"
#include <string.h>

#define H BIP32_HARDENED

/* Derive m/purpose'/coin'/0'/0/0 and return the private key (in n). */
static int derive_leaf(bip32_node *n, const uint8_t seed[64], uint32_t purpose, uint32_t coin)
{
    const uint32_t path[5] = {purpose | H, coin | H, 0 | H, 0, 0};
    if (bip32_master(n, seed, 64)) return -1;
    return bip32_derive_path(n, path, 5);
}

int wallet_derive(wallet_addrs *out, const uint8_t seed[64], wallet_progress_fn progress, void *user)
{
    bip32_node n;
    uint8_t pub[33];
    int r = 0;

    memset(out, 0, sizeof *out);

    if (progress) progress(0, WALLET_STEPS, user);
    if (derive_leaf(&n, seed, 44, 0) || secp256k1_pubkey_create(pub, n.key)) { r = -1; goto done; }
    if (addr_p2pkh(out->btc_legacy, sizeof out->btc_legacy, 0x00, pub) < 0) { r = -1; goto done; }

    if (progress) progress(1, WALLET_STEPS, user);
    if (derive_leaf(&n, seed, 84, 0) || secp256k1_pubkey_create(pub, n.key)) { r = -1; goto done; }
    if (addr_p2wpkh(out->btc_segwit, sizeof out->btc_segwit, "bc", pub) < 0) { r = -1; goto done; }

    if (progress) progress(2, WALLET_STEPS, user);
    if (derive_leaf(&n, seed, 44, 60) || addr_eth(out->eth, sizeof out->eth, n.key) < 0) { r = -1; goto done; }

    if (progress) progress(3, WALLET_STEPS, user);
    if (derive_leaf(&n, seed, 44, 3) || secp256k1_pubkey_create(pub, n.key)) { r = -1; goto done; }
    if (addr_p2pkh(out->doge, sizeof out->doge, 0x1e, pub) < 0) { r = -1; goto done; }

    if (progress) progress(4, WALLET_STEPS, user);
    if (derive_leaf(&n, seed, 44, 1237) || addr_npub(out->npub, sizeof out->npub, n.key) < 0) { r = -1; goto done; }

done:
    secure_zero(&n, sizeof n);
    return r;
}
