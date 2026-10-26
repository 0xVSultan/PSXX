#pragma once
#include <stddef.h>
#include <stdint.h>

/* Monero (legacy 25 word seed) key derivation and primary address. */
typedef struct {
    uint8_t spend_sec[32];   /* sc_reduce32(seed) */
    uint8_t view_sec[32];    /* sc_reduce32(keccak256(spend_sec)) */
    uint8_t spend_pub[32];
    uint8_t view_pub[32];
} xmr_keys;

/* spend_seed is the 32 byte value the 25 word mnemonic encodes. */
void xmr_keys_from_seed(xmr_keys *k, const uint8_t spend_seed[32]);

/* Legacy subaddress (major, minor) of the account: m = Hs("SubAddr\0" || view_sec || major || minor),
 * D = spend_pub + m*G, C = view_sec*D, netbyte 0x2a (mainnet). Needs only the view secret and the public spend key, so
 * the spend secret can be wiped. (0, 0) is the main address, use xmr_address for that. Returns the string length or -1. */
int xmr_subaddress(char *out, size_t cap, const uint8_t view_sec[32], const uint8_t spend_pub[32],
                   uint32_t major, uint32_t minor);

/* Standard address: netbyte (0x12 mainnet) || spend_pub || view_pub || 4 byte keccak checksum, Monero Base58 (95 chars).
 * Returns the string length or -1 if `cap` < 96. */
int xmr_address(char *out, size_t cap, uint8_t netbyte, const uint8_t spend_pub[32], const uint8_t view_pub[32]);
/* Integrated address: netbyte 0x13 (mainnet) || spend_pub || view_pub || 8 byte payment ID || 4 byte checksum, Monero Base58 (106 chars). Returns the length or -1 if `cap` < 107. */
int xmr_integrated_address(char *out, size_t cap, const uint8_t spend_pub[32], const uint8_t view_pub[32], const uint8_t pid[8]);
