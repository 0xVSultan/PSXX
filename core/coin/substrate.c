#include "coin/substrate.h"
#include <string.h>
#include "util.h"
#include "ec/ed25519.h"
#include "hash/blake2b.h"
#include "hash/merlin.h"
#include "hash/sha512.h"

void substrate_mini_secret(uint8_t mini[32], const uint8_t *entropy, size_t entlen, const char *password)
{
    uint8_t salt[9 + 128], t[64];
    size_t pl = strlen(password);
    if (pl > 128) pl = 128;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, password, pl);
    pbkdf2_hmac_sha512(entropy, entlen, salt, 8 + pl, 2048, t, 64);
    memcpy(mini, t, 32);
    secure_zero(t, sizeof t);
}

void sr25519_expand(uint8_t scalar[32], const uint8_t mini[32])
{
    uint8_t h[64];
    sha512(mini, 32, h);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    for (int i = 0; i < 31; i++) scalar[i] = (uint8_t) ((h[i] >> 3) | (h[i + 1] << 5));     /* divide by the cofactor 8 */
    scalar[31] = (uint8_t) (h[31] >> 3);
    secure_zero(h, sizeof h);
}

void sr25519_pubkey(uint8_t pub[32], const uint8_t scalar[32]) { ed25519_ristretto_basemul(pub, scalar); }

void sr25519_derive_hard(uint8_t scalar[32], const uint8_t cc[32])
{
    merlin t;
    uint8_t mini[32], chain[32];
    merlin_init(&t, "SchnorrRistrettoHDKD");
    merlin_append(&t, "sign-bytes", NULL, 0);
    merlin_append(&t, "chain-code", cc, 32);
    merlin_append(&t, "secret-key", scalar, 32);
    merlin_challenge(&t, "HDKD-hard", mini, 32);
    merlin_challenge(&t, "HDKD-chaincode", chain, 32);
    sr25519_expand(scalar, mini);
    secure_zero(&t, sizeof t);
    secure_zero(mini, sizeof mini);
}

void sr25519_derive_soft(uint8_t scalar[32], const uint8_t cc[32])
{
    merlin t;
    uint8_t pub[32], wide[64], s[32], chain[32];
    sr25519_pubkey(pub, scalar);
    merlin_init(&t, "SchnorrRistrettoHDKD");
    merlin_append(&t, "sign-bytes", NULL, 0);
    merlin_append(&t, "chain-code", cc, 32);
    merlin_append(&t, "public-key", pub, 32);
    merlin_challenge(&t, "HDKD-scalar", wide, 64);
    merlin_challenge(&t, "HDKD-chaincode", chain, 32);
    ed25519_sc_reduce64(s, wide);
    ed25519_sc_add(scalar, scalar, s);
    secure_zero(&t, sizeof t);
    secure_zero(s, sizeof s);
    secure_zero(wide, sizeof wide);
}

/* The 32 byte chain code of a junction name: a number is a u64 (little-endian), anything else a SCALE string (compact
 * length, bytes); an encoding longer than 32 bytes is hashed with BLAKE2b-256, a shorter one is zero padded. */
static int junction_code(uint8_t cc[32], const char *name, size_t len)
{
    uint8_t enc[80];
    size_t el = 0, i;
    int numeric = len > 0 && len <= 19;
    uint64_t v = 0;

    for (i = 0; i < len; i++) {
        if (name[i] < '0' || name[i] > '9') { numeric = 0; break; }
        v = v * 10 + (uint64_t) (name[i] - '0');
    }
    if (len == 0) return -1;
    memset(cc, 0, 32);
    if (numeric) {
        for (i = 0; i < 8; i++) cc[i] = (uint8_t) (v >> (8 * i));
        return 0;
    }
    if (len > 60) return -1;
    enc[el++] = (uint8_t) (len << 2);                 /* SCALE compact length, one byte form (len < 64) */
    memcpy(enc + el, name, len);
    el += len;
    if (el > 32) blake2b(cc, 32, enc, el);
    else memcpy(cc, enc, el);
    return 0;
}

int substrate_derive_path(uint8_t scalar[32], const char *path)
{
    while (*path) {
        int hard = 0;
        const char *e;
        uint8_t cc[32];
        if (*path != '/') return -1;
        path++;
        if (*path == '/') { hard = 1; path++; }
        for (e = path; *e && *e != '/'; e++) {}
        if (junction_code(cc, path, (size_t) (e - path))) return -1;
        if (hard) sr25519_derive_hard(scalar, cc);
        else sr25519_derive_soft(scalar, cc);
        path = e;
    }
    return 0;
}

void sr25519_sign(uint8_t sig[64], const uint8_t scalar[32], const uint8_t *msg, size_t len)
{
    merlin t, w;
    sha512_ctx c;
    uint8_t pub[32], big[64], r[32], k[32], ks[32], tag[32];

    sr25519_pubkey(pub, scalar);
    merlin_init(&t, "SigningContext");
    merlin_append(&t, "", (const uint8_t *) "substrate", 9);
    merlin_append(&t, "sign-bytes", msg, len);
    merlin_append(&t, "proto-name", (const uint8_t *) "Schnorr-sig", 11);
    merlin_append(&t, "sign:pk", pub, 32);
    w = t;                                             /* the nonce depends on the key and on everything signed so far */
    merlin_challenge(&w, "nonce", tag, 32);
    sha512_init(&c);
    sha512_update(&c, (const uint8_t *) "psxx sr25519 nonce", 18);
    sha512_update(&c, scalar, 32);
    sha512_update(&c, tag, 32);
    sha512_final(&c, big);
    ed25519_sc_reduce64(r, big);
    ed25519_ristretto_basemul(sig, r);                 /* R */
    merlin_append(&t, "sign:R", sig, 32);
    merlin_challenge(&t, "sign:c", big, 64);
    ed25519_sc_reduce64(k, big);
    ed25519_sc_mul(ks, k, scalar);
    ed25519_sc_add(sig + 32, ks, r);
    sig[63] |= 0x80;
    secure_zero(&t, sizeof t); secure_zero(&w, sizeof w); secure_zero(big, sizeof big);
    secure_zero(r, sizeof r); secure_zero(k, sizeof k); secure_zero(ks, sizeof ks);
}
