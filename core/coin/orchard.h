#pragma once
#include <stddef.h>
#include <stdint.h>
#include "ec/pallas.h"

/* Zcash Orchard receiving addresses: ZIP-32 keys from the BIP39 seed, the full viewing key, a diversified payment address
 * and its unified address (ZIP-316, Orchard receiver only, "u1..."). Needs Pallas arithmetic, Sinsemilla and BLAKE2b;
 * deriving one address takes about 55 hash-to-curve evaluations. All outputs are public; sk, the chain code and the
 * intermediate keys are secrets that the caller wipes. */

/* ZIP-32 Orchard: master key from the seed (32..252 bytes) and hardened children. */
void orchard_master(uint8_t sk[32], uint8_t chain[32], const uint8_t *seed, size_t seedlen);
void orchard_child(uint8_t sk[32], uint8_t chain[32], uint32_t hardened_index);

/* PRF^expand: BLAKE2b-512("Zcash_ExpandSeed", key || t) */
void orchard_prf_expand(uint8_t out[64], const uint8_t *key, size_t klen, const uint8_t *t, size_t tlen);

typedef struct {
    uint8_t ak[32], nk[32], rivk[32];      /* the full viewing key (little-endian field elements) */
    uint8_t ivk[32];                       /* incoming viewing key (a scalar, 32 bytes little-endian) */
    uint8_t dk[32], ovk[32];
} orchard_fvk;

/* The full viewing key of a spending key. Returns 0. */
int orchard_fvk_from_sk(orchard_fvk *f, const uint8_t sk[32]);
/* Diversifier j (11 bytes): FF1-AES-256 of the index; j = 0 is the default. */
void orchard_diversifier(uint8_t d[11], const uint8_t dk[32], const uint8_t j[11]);
/* The 43 byte raw address d || pk_d of a diversifier. */
int orchard_address(uint8_t addr[43], const orchard_fvk *f, const uint8_t d[11]);
/* Unified address: bech32m "u1..." of the F4Jumbled receiver list. out needs 120 bytes. Returns the length or -1. */
int orchard_unified_address(char *out, size_t cap, const uint8_t addr[43]);

/* Building blocks, public for the tests. */
void orchard_f4jumble(uint8_t *out, const uint8_t *in, size_t len);           /* 48 <= len <= 192 */
void orchard_ff1_diversifier(uint8_t out[11], const uint8_t key[32], const uint8_t in[11]);
/* SinsemillaHash(domain, bits) as the point's x coordinate (32 bytes); `bits` holds one 0 / 1 per entry. */
void orchard_sinsemilla_hash(uint8_t out[32], const uint8_t *domain, size_t dlen, const uint8_t *bits, size_t nbits);

/* The 1024 points S_j = GroupHash("z.cash:SinsemillaS", j) of Sinsemilla can be precomputed (64 KB: 1024 x (x, y), 32 bytes little-endian each).
 * A device that cannot keep them in RAM gives a function that reads entry j (64 bytes) from wherever they are stored (a memory card
 * file); it returns 0 on success. Without it every chunk of a Sinsemilla message costs a hash to curve (about 0.07 s on the PSX). */
typedef int (*orchard_sinsemilla_s_fn)(unsigned j, uint8_t xy[64]);
void orchard_set_sinsemilla_table(orchard_sinsemilla_s_fn fn);
/* Sinsemilla hash-to-point of a message of bits (orchard_sinsemilla_hash gives its x coordinate), for the note commitments of orchard_sign.c. */
void orchard_sinsemilla_point(pl_pt *acc, const uint8_t *domain, size_t dlen, const uint8_t *bits, size_t nbits);

/* The internal full viewing key of an external one (ZIP-32 / ZIP-316): the keys of change addresses. */
int orchard_internal_fvk(orchard_fvk *out, const orchard_fvk *ext);
/* Same, without the incoming viewing key (it costs a Sinsemilla commitment): only dk and ovk (and rivk, ak, nk) are set. */
int orchard_internal_fvk_light(orchard_fvk *out, const orchard_fvk *ext);
/* The incoming viewing key of a light internal key (the missing part of the above). */
void orchard_fvk_complete_ivk(orchard_fvk *f);

/* DiversifyHash(d): the point g_d of a diversifier */
void orchard_diversify_hash(pl_pt *gd, const uint8_t d[11]);
/* NoteCommit^Orchard_rcm(g_d, pk_d, v, rho, psi) as a point (gd_enc and pkd_enc: the 32 byte point encodings; rho and psi: field elements) */
void orchard_note_commit(pl_pt *cm, const uint8_t rcm[32], const uint8_t gd_enc[32], const uint8_t pkd_enc[32], uint64_t v,
                         const uint8_t rho[32], const uint8_t psi[32]);
/* The nullifier of a note: x( [Poseidon(nk, rho) + psi] K + cm ). */
void orchard_derive_nullifier(uint8_t nf[32], const uint8_t nk[32], const uint8_t rho[32], const uint8_t psi[32], const pl_pt *cm);

/* The fixed generators of Orchard (spend authorization base, nullifier base, the Q and R points of NoteCommit and CommitIvk) are hash to
 * curve results (about 100 ms each on the PSX) that are kept after the first use. This makes the next one: call it now and then in idle time
 * (every call does one and returns how many are still to do), so that the first transaction does not pay for them. */
int orchard_warm_constants(void);
