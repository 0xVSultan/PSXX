#pragma once
#include <stddef.h>
#include <stdint.h>

/* Litecoin MimbleWimble (MWEB) stealth addresses, as in Litecoin Core's mw::Keychain (src/libmw) and doc/mweb/stealth-addresses.md.
 * The wallet keeps a scan secret a (BIP32 m/0'/100'/0') and a spend secret b (m/0'/100'/1'); the address of index i is
 *     b_i = b + BLAKE3('A' || i (4 bytes, little endian) || a)      B_i = b_i G
 *     a_i = a * b_i                                                 A_i = a_i G
 * serialised A_i || B_i (66 bytes), regrouped to 5 bits with a leading 0 symbol and written as Bech32 (not Bech32m) with the
 * prefix "ltcmweb". Index 0 is the change key and 1 the peg-in key of the Core wallet, so the first receiving address is
 * index 2 (Core: mw::CHANGE_INDEX 0, PEGIN_INDEX 1). Checked against the test vector of Litecoin Core (src/wallet/test/scriptpubkeyman_tests.cpp). */

#define MWEB_FIRST_INDEX 2
/* Cake Wallet and Electrum-LTC (mwebd) keep the keys under m/1000' (scan m/1000'/0', spend m/1000'/1'), index 0 is the change and the receiving addresses start at 1 */
#define MWEB_CAKE_ROOT 1000u
#define MWEB_CAKE_FIRST_INDEX 1

/* The two public keys of address `index`. Returns 0, or -1 for a secret that is not a valid scalar. */
int mweb_keys(uint8_t A[33], uint8_t B[33], const uint8_t scan[32], const uint8_t spend[32], uint32_t index);
/* The address string (121 characters with the prefix "ltcmweb"). Returns the length, or -1. */
int mweb_address(char *out, size_t cap, const char *hrp, const uint8_t scan[32], const uint8_t spend[32], uint32_t index);
