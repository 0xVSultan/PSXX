#include "sign/orchard_out.h"
#include <string.h>
#include "ec/pallas.h"
#include "hash/blake2b.h"
#include "hash/chacha20poly1305.h"
#include "util.h"
#include "prof.h"

static void b2_256(uint8_t out[32], const char *person, const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                   const uint8_t *c, size_t cl, const uint8_t *d, size_t dl)
{
    blake2b_ctx x;
    blake2b_init(&x, 32, NULL, 0, NULL, (const uint8_t *) person);
    blake2b_update(&x, a, al);
    blake2b_update(&x, b, bl);
    if (c) blake2b_update(&x, c, cl);
    if (d) blake2b_update(&x, d, dl);
    blake2b_final(&x, out);
}

/* psi, rcm and esk of a note from its rseed and rho: ToBase / ToScalar of PRF^expand(rseed, tag || rho) */
static void note_randomness(uint8_t psi[32], uint8_t rcm[32], uint8_t esk[32], const uint8_t rseed[32], const uint8_t rho[32])
{
    uint8_t t[33], e[64];
    memcpy(t + 1, rho, 32);
    if (esk) { t[0] = 0x04; orchard_prf_expand(e, rseed, 32, t, 33); pl_reduce_scalar(esk, e); }
    t[0] = 0x05; orchard_prf_expand(e, rseed, 32, t, 33); pl_reduce_scalar(rcm, e);
    t[0] = 0x09; orchard_prf_expand(e, rseed, 32, t, 33); pl_reduce_base(psi, e);
    secure_zero(e, sizeof e);
}

int orchard_open_output(orch_note *n, const uint8_t *a, const uint8_t ovk[32])
{
    static const uint8_t NONCE[12] = {0};
    const uint8_t *cv = a, *nf = a + 32, *cmx = a + 96, *epk = a + 128, *enc = a + 160, *out = a + 740;
    uint8_t ock[32], op[64], key[32], ka[32], pl[564], psi[32], rcm[32], esk2[32], x[32], gd_enc[32];
    pl_pt pk, e, gd, t, cm;
    int rc = ORCH_BAD;

    PROF("open output: start");
    b2_256(ock, "Zcash_Orchardock", ovk, 32, cv, 32, cmx, 32, epk, 32);
    if (chacha20poly1305_decrypt(op, ock, NONCE, out, 80)) { secure_zero(ock, sizeof ock); return ORCH_NOT_OURS; }
    secure_zero(ock, sizeof ock);
    if (pl_decode(&pk, op) || pl_decode(&e, epk)) goto done;
    PROF("open output: ock opened");
    pl_mul(&t, &pk, op + 32);                                    /* the shared secret [esk] pk_d */
    pl_encode(ka, &t);
    b2_256(key, "Zcash_OrchardKDF", ka, 32, epk, 32, NULL, 0, NULL, 0);
    if (chacha20poly1305_decrypt(pl, key, NONCE, enc, 580) || pl[0] != 2) goto done;
    memcpy(n->d, pl + 1, 11);
    n->v = 0;
    for (int i = 0; i < 8; i++) n->v |= (uint64_t) pl[12 + i] << (8 * i);
    memcpy(n->rseed, pl + 20, 32);
    memcpy(n->pk_d, op, 32);
    PROF("open output: note decrypted");
    orchard_diversify_hash(&gd, n->d);
    pl_mul(&t, &gd, op + 32);                                    /* epk = [esk] g_d */
    pl_encode(x, &t);
    if (memcmp(x, epk, 32)) goto done;
    note_randomness(psi, rcm, esk2, n->rseed, nf);
    if (memcmp(esk2, op + 32, 32)) goto done;                    /* esk is the one the note's rseed gives */
    pl_encode(gd_enc, &gd);
    orchard_note_commit(&cm, rcm, gd_enc, n->pk_d, n->v, nf, psi);
    pl_x_bytes(x, &cm);
    PROF("open output: verified");
    if (memcmp(x, cmx, 32)) goto done;
    rc = ORCH_OK;
done:
    secure_zero(op, sizeof op); secure_zero(key, sizeof key); secure_zero(ka, sizeof ka); secure_zero(pl, sizeof pl);
    return rc;
}

int orchard_is_address_of(const uint8_t d[11], const uint8_t pk_d[32], const uint8_t ivk[32])
{
    pl_pt gd;
    uint8_t enc[32];
    orchard_diversify_hash(&gd, d);
    pl_mul(&gd, &gd, ivk);
    pl_encode(enc, &gd);
    return memcmp(enc, pk_d, 32) == 0;
}

int orchard_check_spend(const uint8_t *a, const uint8_t d[11], uint64_t v, const uint8_t rseed[32], const uint8_t rho[32],
                        const uint8_t ivk[32], const uint8_t nk[32])
{
    uint8_t psi[32], rcm[32], gd_enc[32], pkd[32], nf[32];
    pl_pt gd, t, cm;
    orchard_diversify_hash(&gd, d);
    pl_encode(gd_enc, &gd);
    pl_mul(&t, &gd, ivk);
    pl_encode(pkd, &t);
    note_randomness(psi, rcm, NULL, rseed, rho);
    orchard_note_commit(&cm, rcm, gd_enc, pkd, v, rho, psi);
    orchard_derive_nullifier(nf, nk, rho, psi, &cm);
    return memcmp(nf, a + 32, 32) == 0 ? 0 : -1;
}
