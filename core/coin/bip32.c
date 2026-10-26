#include "coin/bip32.h"
#include "coin/base58.h"
#include "ec/secp256k1.h"
#include "hash/ripemd160.h"
#include "hash/sha512.h"
#include "util.h"
#include <string.h>

int bip32_master(bip32_node *n, const uint8_t *seed, size_t seedlen)
{
    static const uint8_t K[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    uint8_t i[64];
    hmac_sha512(K, sizeof K, seed, seedlen, i);
    memcpy(n->key, i, 32);
    memcpy(n->chain, i + 32, 32);
    secure_zero(i, sizeof i);
    if (!secp256k1_privkey_verify(n->key)) { secure_zero(n, sizeof *n); return -1; }
    return 0;
}

int bip32_derive(bip32_node *n, uint32_t index)
{
    uint8_t data[37], i[64];
    if (index & BIP32_HARDENED) {
        data[0] = 0;
        memcpy(data + 1, n->key, 32);
    } else if (secp256k1_pubkey_create(data, n->key)) {
        return -1;
    }
    data[33] = (uint8_t)(index >> 24); data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >> 8);  data[36] = (uint8_t)index;
    hmac_sha512(n->chain, 32, data, sizeof data, i);
    secure_zero(data, sizeof data);
    int r = secp256k1_privkey_tweak_add(n->key, i);   /* fails if IL >= n or the child key is 0 */
    if (r == 0) memcpy(n->chain, i + 32, 32);
    secure_zero(i, sizeof i);
    return r;
}

int bip32_derive_path(bip32_node *n, const uint32_t *path, size_t len)
{
    for (size_t k = 0; k < len; k++)
        if (bip32_derive(n, path[k])) return -1;
    return 0;
}

int bip32_fingerprint(const bip32_node *n, uint8_t fp[4])
{
    uint8_t pub[33], h[20];
    if (secp256k1_pubkey_create(pub, n->key)) return -1;
    hash160(pub, 33, h);
    memcpy(fp, h, 4);
    return 0;
}

int bip32_serialize(const bip32_node *n, int is_public, uint8_t depth, const uint8_t parent_fp[4], uint32_t child_index,
                    char *out, size_t outcap)
{
    return bip32_serialize_ver(n, is_public ? 0x0488B21Eu : 0x0488ADE4u, depth, parent_fp, child_index, out, outcap);
}

int bip32_serialize_ver(const bip32_node *n, uint32_t ver, uint8_t depth, const uint8_t parent_fp[4], uint32_t child_index, char *out, size_t outcap)
{
    uint8_t raw[78];
    int is_public = ver != 0x0488ADE4u;
    raw[0] = (uint8_t)(ver >> 24); raw[1] = (uint8_t)(ver >> 16); raw[2] = (uint8_t)(ver >> 8); raw[3] = (uint8_t)ver;
    raw[4] = depth;
    memcpy(raw + 5, parent_fp, 4);
    raw[9] = (uint8_t)(child_index >> 24); raw[10] = (uint8_t)(child_index >> 16);
    raw[11] = (uint8_t)(child_index >> 8); raw[12] = (uint8_t)child_index;
    memcpy(raw + 13, n->chain, 32);
    if (is_public) {
        if (secp256k1_pubkey_create(raw + 45, n->key)) return -1;
    } else {
        raw[45] = 0;
        memcpy(raw + 46, n->key, 32);
    }
    int r = base58check_encode(raw, sizeof raw, out, outcap);
    secure_zero(raw, sizeof raw);
    return r;
}
