#include "coin/xmr.h"
#include "coin/base58.h"
#include "ec/ed25519.h"
#include "hash/keccak.h"
#include "util.h"
#include <string.h>

void xmr_keys_from_seed(xmr_keys *k, const uint8_t spend_seed[32])
{
    memcpy(k->spend_sec, spend_seed, 32);
    ed25519_sc_reduce32(k->spend_sec);
    keccak256(k->spend_sec, 32, k->view_sec);
    ed25519_sc_reduce32(k->view_sec);
    ed25519_scalarmult_base(k->spend_pub, k->spend_sec);
    ed25519_scalarmult_base(k->view_pub, k->view_sec);
}

int xmr_subaddress(char *out, size_t cap, const uint8_t view_sec[32], const uint8_t spend_pub[32],
                   uint32_t major, uint32_t minor)
{
    uint8_t buf[48], m[32], D[32], C[32];
    int r;

    memcpy(buf, "SubAddr\0", 8);
    memcpy(buf + 8, view_sec, 32);
    for (int i = 0; i < 4; i++) { buf[40 + i] = (uint8_t)(major >> (8 * i)); buf[44 + i] = (uint8_t)(minor >> (8 * i)); }
    keccak256(buf, sizeof buf, m);
    ed25519_sc_reduce32(m);
    r = ed25519_subaddress_keys(D, C, spend_pub, view_sec, m);
    secure_zero(buf, sizeof buf);
    secure_zero(m, sizeof m);
    if (r) return -1;
    return xmr_address(out, cap, 0x2a, D, C);
}

int xmr_integrated_address(char *out, size_t cap, const uint8_t spend_pub[32], const uint8_t view_pub[32], const uint8_t pid[8])
{
    uint8_t raw[77], h[32];
    raw[0] = 0x13;
    memcpy(raw + 1, spend_pub, 32);
    memcpy(raw + 33, view_pub, 32);
    memcpy(raw + 65, pid, 8);
    keccak256(raw, 73, h);
    memcpy(raw + 73, h, 4);
    return base58_monero_encode(raw, sizeof raw, out, cap);
}

int xmr_address(char *out, size_t cap, uint8_t netbyte, const uint8_t spend_pub[32], const uint8_t view_pub[32])
{
    uint8_t raw[69], h[32];
    raw[0] = netbyte;
    memcpy(raw + 1, spend_pub, 32);
    memcpy(raw + 33, view_pub, 32);
    keccak256(raw, 65, h);
    memcpy(raw + 65, h, 4);
    return base58_monero_encode(raw, sizeof raw, out, cap);
}
