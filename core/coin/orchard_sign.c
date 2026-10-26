/* Orchard, the parts only the signer needs: the note commitment, the nullifier and the warming of the group hash constants (they use Poseidon and the Sinsemilla commitment
 * of orchard.c). A file of its own so that the generator, which only derives addresses, does not carry them. */
#include "coin/orchard.h"
#include <string.h>
#include "util.h"
#include "ec/pallas.h"
#include "ec/poseidon.h"
#include "prof.h"

/* the bits of a byte string, least significant bit of every byte first */
static void put_bits(uint8_t *bits, const uint8_t *bytes, size_t nbits)
{
    for (size_t i = 0; i < nbits; i++) bits[i] = (uint8_t) ((bytes[i >> 3] >> (i & 7)) & 1);
}

void orchard_note_commit(pl_pt *cm, const uint8_t rcm[32], const uint8_t gd_enc[32], const uint8_t pkd_enc[32], uint64_t v,
                         const uint8_t rho[32], const uint8_t psi[32])
{
    static const char M_DOM[] = "z.cash:Orchard-NoteCommit-M", R_DOM[] = "z.cash:Orchard-NoteCommit-r";
    uint8_t bits[256 + 256 + 64 + 255 + 255], vb[8];
    pl_pt h, r;
    for (int i = 0; i < 8; i++) vb[i] = (uint8_t) (v >> (8 * i));
    put_bits(bits, gd_enc, 256);
    put_bits(bits + 256, pkd_enc, 256);
    put_bits(bits + 512, vb, 64);
    put_bits(bits + 576, rho, 255);
    put_bits(bits + 831, psi, 255);
    PROF("note commit: start");
    orchard_sinsemilla_point(&h, (const uint8_t *) M_DOM, sizeof M_DOM - 1, bits, sizeof bits);
    PROF("note commit: sinsemilla");
    pl_group_hash_cached(&r, (const uint8_t *) R_DOM, sizeof R_DOM - 1, NULL, 0);
    pl_mul(&r, &r, rcm);
    pl_add(cm, &h, &r);
    PROF("note commit: randomness point");
}

void orchard_derive_nullifier(uint8_t nf[32], const uint8_t nk[32], const uint8_t rho[32], const uint8_t psi[32], const pl_pt *cm)
{
    static const char K_DOM[] = "z.cash:Orchard";
    uint8_t h[32], sc[32];
    pl_fp a, b;
    pl_pt k, t;
    poseidon_hash2(h, nk, rho);
    pl_fp_from_le(a, h);
    pl_fp_from_le(b, psi);
    pl_fp_add(a, a, b);
    pl_fp_to_le(h, a);
    pl_scalar_from_base(sc, h);
    pl_group_hash_cached(&k, (const uint8_t *) K_DOM, sizeof K_DOM - 1, (const uint8_t *) "K", 1);
    pl_mul(&t, &k, sc);
    pl_add(&t, &t, cm);
    pl_x_bytes(nf, &t);
    PROF("nullifier");
}

int orchard_warm_constants(void)
{
    static int next;
    static const char ORC[] = "z.cash:Orchard", NCM[] = "z.cash:Orchard-NoteCommit-M", NCR[] = "z.cash:Orchard-NoteCommit-r",
                      IVM[] = "z.cash:Orchard-CommitIvk-M", IVR[] = "z.cash:Orchard-CommitIvk-r", QD[] = "z.cash:SinsemillaQ";
    pl_pt p;
    switch (next) {
    case 0: pl_group_hash_cached(&p, (const uint8_t *) ORC, sizeof ORC - 1, (const uint8_t *) "G", 1); break;
    case 1: pl_group_hash_cached(&p, (const uint8_t *) ORC, sizeof ORC - 1, (const uint8_t *) "K", 1); break;
    case 2: pl_group_hash_cached(&p, (const uint8_t *) QD, sizeof QD - 1, (const uint8_t *) NCM, sizeof NCM - 1); break;
    case 3: pl_group_hash_cached(&p, (const uint8_t *) NCR, sizeof NCR - 1, NULL, 0); break;
    case 4: pl_group_hash_cached(&p, (const uint8_t *) QD, sizeof QD - 1, (const uint8_t *) IVM, sizeof IVM - 1); break;
    case 5: pl_group_hash_cached(&p, (const uint8_t *) IVR, sizeof IVR - 1, NULL, 0); break;
    default: return 0;
    }
    next++;
    return 6 - next;
}
