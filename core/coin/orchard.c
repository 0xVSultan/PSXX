#include "coin/orchard.h"
#include <string.h>
#include "util.h"
#include "aes.h"
#include "coin/bech32.h"
#include "ec/pallas.h"
#include "prof.h"
#include "hash/blake2b.h"

static const char DOM_ENC[] = "Zcash_ExpandSeed";

void orchard_prf_expand(uint8_t out[64], const uint8_t *key, size_t klen, const uint8_t *t, size_t tlen)
{
    blake2b_ctx c;
    blake2b_init(&c, 64, NULL, 0, NULL, (const uint8_t *) DOM_ENC);
    blake2b_update(&c, key, klen);
    blake2b_update(&c, t, tlen);
    blake2b_final(&c, out);
}

void orchard_master(uint8_t sk[32], uint8_t chain[32], const uint8_t *seed, size_t seedlen)
{
    uint8_t i64[64];
    blake2b_ctx c;
    blake2b_init(&c, 64, NULL, 0, NULL, (const uint8_t *) "ZcashIP32Orchard");
    blake2b_update(&c, seed, seedlen);
    blake2b_final(&c, i64);
    memcpy(sk, i64, 32);
    memcpy(chain, i64 + 32, 32);
    secure_zero(i64, sizeof i64);
}

void orchard_child(uint8_t sk[32], uint8_t chain[32], uint32_t index)
{
    uint8_t t[1 + 32 + 4], i64[64];
    t[0] = 0x81;
    memcpy(t + 1, sk, 32);
    t[33] = (uint8_t) index;
    t[34] = (uint8_t) (index >> 8);
    t[35] = (uint8_t) (index >> 16);
    t[36] = (uint8_t) (index >> 24);
    orchard_prf_expand(i64, chain, 32, t, sizeof t);
    memcpy(sk, i64, 32);
    memcpy(chain, i64 + 32, 32);
    secure_zero(t, sizeof t);
    secure_zero(i64, sizeof i64);
}

/* ---- Sinsemilla ---- */

static orchard_sinsemilla_s_fn s_get;
void orchard_set_sinsemilla_table(orchard_sinsemilla_s_fn fn) { s_get = fn; }

void orchard_sinsemilla_point(pl_pt *acc, const uint8_t *domain, size_t dlen, const uint8_t *bits, size_t nbits)
{
    static const char Q_DOM[] = "z.cash:SinsemillaQ", S_DOM[] = "z.cash:SinsemillaS";
    size_t n = (nbits + 9) / 10;
    pl_group_hash_cached(acc, (const uint8_t *) Q_DOM, sizeof Q_DOM - 1, domain, dlen);
    for (size_t i0 = 0; i0 < n; i0 += 16) {                       /* the S points of 16 chunks at a time: one shared inversion */
        uint8_t le[16][4];
        pl_pt s[16];
        size_t m = n - i0 < 16 ? n - i0 : 16;
        for (size_t j = 0; j < m; j++) {
            uint32_t v = 0;
            for (int b = 0; b < 10; b++) {
                size_t k = (i0 + j) * 10 + (size_t) b;
                if (k < nbits && bits[k]) v |= 1u << b;
            }
            le[j][0] = (uint8_t) v;
            le[j][1] = (uint8_t) (v >> 8);
            le[j][2] = 0;
            le[j][3] = 0;
        }
        {   /* the points that are in the table come from it, the others are computed (together: one shared inversion) */
            uint8_t miss_le[16][4];
            size_t miss_at[16], nmiss = 0;
            for (size_t j = 0; j < m; j++) {
                uint8_t xy[64];
                if (s_get && !s_get((unsigned) le[j][0] | (unsigned) le[j][1] << 8, xy)) pl_from_affine(&s[j], xy, xy + 32);
                else { memcpy(miss_le[nmiss], le[j], 4); miss_at[nmiss++] = j; }
            }
            if (nmiss) {
                pl_pt c[16];
                pl_group_hash_batch(c, nmiss, (const uint8_t *) S_DOM, sizeof S_DOM - 1, &miss_le[0][0], 4);
                for (size_t q = 0; q < nmiss; q++) s[miss_at[q]] = c[q];
                if (s_get == pl_stable_get) {                  /* the table of the console keeps what had to be computed */
                    unsigned ids[16];
                    for (size_t q = 0; q < nmiss; q++) ids[q] = (unsigned) miss_le[q][0] | (unsigned) miss_le[q][1] << 8;
                    pl_stable_add(ids, c, nmiss);
                }
            }
        }
        for (size_t j = 0; j < m; j++) {
            pl_pt t;
            pl_add(&t, acc, &s[j]);
            pl_add(acc, &t, acc);
        }
    }
}

void orchard_sinsemilla_hash(uint8_t out[32], const uint8_t *domain, size_t dlen, const uint8_t *bits, size_t nbits)
{
    pl_pt p;
    orchard_sinsemilla_point(&p, domain, dlen, bits, nbits);
    pl_x_bytes(out, &p);
}

/* CommitIvk_rivk(ak, nk) = x( SinsemillaHashToPoint("z.cash:Orchard-CommitIvk-M", ak || nk) + [rivk] R ),
 * R = GroupHash("z.cash:Orchard-CommitIvk-r", ""), the field elements as 255 bits each, least significant bit first */
static void commit_ivk(uint8_t out[32], const uint8_t rivk[32], const uint8_t ak[32], const uint8_t nk[32])
{
    static const char M_DOM[] = "z.cash:Orchard-CommitIvk-M", R_DOM[] = "z.cash:Orchard-CommitIvk-r";
    uint8_t bits[510];
    pl_pt h, r, sum;
    for (int i = 0; i < 255; i++) {
        bits[i] = (uint8_t) ((ak[i >> 3] >> (i & 7)) & 1);
        bits[255 + i] = (uint8_t) ((nk[i >> 3] >> (i & 7)) & 1);
    }
    PROF("commit ivk: start");
    orchard_sinsemilla_point(&h, (const uint8_t *) M_DOM, sizeof M_DOM - 1, bits, 510);
    pl_group_hash_cached(&r, (const uint8_t *) R_DOM, sizeof R_DOM - 1, NULL, 0);
    pl_mul(&r, &r, rivk);
    pl_add(&sum, &h, &r);
    pl_x_bytes(out, &sum);
    PROF("commit ivk: done");
}

/* ---- keys ---- */

int orchard_fvk_from_sk(orchard_fvk *f, const uint8_t sk[32])
{
    static const char G_DOM[] = "z.cash:Orchard";
    uint8_t t[1 + 64], e[64], ask[32], k[32], msg[1 + 32 + 32], r[64], xb[32];
    pl_pt g, akp;

    t[0] = 0x06;
    orchard_prf_expand(e, sk, 32, t, 1);
    pl_reduce_scalar(ask, e);
    t[0] = 0x07;
    orchard_prf_expand(e, sk, 32, t, 1);
    pl_reduce_base(f->nk, e);
    t[0] = 0x08;
    orchard_prf_expand(e, sk, 32, t, 1);
    pl_reduce_scalar(f->rivk, e);

    pl_group_hash_cached(&g, (const uint8_t *) G_DOM, sizeof G_DOM - 1, (const uint8_t *) "G", 1);
    pl_mul(&akp, &g, ask);                          /* ak is the x coordinate: the sign of ask does not matter */
    pl_x_bytes(f->ak, &akp);
    secure_zero(ask, sizeof ask);

    commit_ivk(xb, f->rivk, f->ak, f->nk);
    pl_scalar_from_base(f->ivk, xb);               /* the x coordinate used as a scalar */

    memcpy(k, f->rivk, 32);
    msg[0] = 0x82;
    memcpy(msg + 1, f->ak, 32);
    memcpy(msg + 33, f->nk, 32);
    orchard_prf_expand(r, k, 32, msg, sizeof msg);
    memcpy(f->dk, r, 32);
    memcpy(f->ovk, r + 32, 32);
    secure_zero(r, sizeof r);
    secure_zero(k, sizeof k);
    secure_zero(e, sizeof e);
    return 0;
}

/* ---- FF1-AES-256 for the diversifier (radix 2, 88 bits, no tweak) ---- */

void orchard_ff1_diversifier(uint8_t out[11], const uint8_t key[32], const uint8_t in[11])
{
    static const uint8_t P[16] = {1, 2, 1, 0, 0, 2, 10, 44, 0, 0, 0, 88, 0, 0, 0, 0};
    const uint64_t MASK = (1ULL << 44) - 1;
    aes_ctx c;
    uint64_t A = 0, B = 0;
    uint8_t zero_iv[16] = {0}, blk[32], mac[32];

    aes_init(&c, key, 256);
    for (int k = 0; k < 88; k++) {                         /* the 88 bits least significant first; each half is read as a big-endian number */
        uint64_t bit = (uint64_t) ((in[k >> 3] >> (k & 7)) & 1);
        if (k < 44) A = (A << 1) | bit;
        else B = (B << 1) | bit;
    }
    for (int i = 0; i < 10; i++) {
        uint64_t y = 0, nc;
        memcpy(blk, P, 16);
        memset(blk + 16, 0, 16);
        blk[16 + 9] = (uint8_t) i;
        for (int j = 0; j < 6; j++) blk[16 + 10 + j] = (uint8_t) (B >> (8 * (5 - j)));
        aes_cbc_encrypt(&c, zero_iv, blk, mac, 32);
        for (int j = 6; j < 12; j++) y = (y << 8) | mac[16 + j];          /* the low 48 bits of the first 12 bytes of the tag */
        nc = (A + (y & MASK)) & MASK;
        A = B;
        B = nc;
    }
    memset(out, 0, 11);
    for (int k = 0; k < 88; k++) {
        uint64_t bit = k < 44 ? (A >> (43 - k)) & 1 : (B >> (43 - (k - 44))) & 1;
        out[k >> 3] |= (uint8_t) (bit << (k & 7));
    }
    aes_wipe(&c);
    secure_zero(blk, sizeof blk);
    secure_zero(mac, sizeof mac);
}

void orchard_diversifier(uint8_t d[11], const uint8_t dk[32], const uint8_t j[11]) { orchard_ff1_diversifier(d, dk, j); }

int orchard_address(uint8_t addr[43], const orchard_fvk *f, const uint8_t d[11])
{
    static const char D_DOM[] = "z.cash:Orchard-gd";
    pl_pt gd;
    uint8_t enc[32], z = 0;
    pl_group_hash(&gd, (const uint8_t *) D_DOM, sizeof D_DOM - 1, d, 11);
    pl_encode(enc, &gd);
    for (int i = 0; i < 32; i++) z |= enc[i];
    if (!z) pl_group_hash(&gd, (const uint8_t *) D_DOM, sizeof D_DOM - 1, NULL, 0);     /* the identity: use the empty message */
    pl_mul(&gd, &gd, f->ivk);
    memcpy(addr, d, 11);
    pl_encode(addr + 11, &gd);
    return 0;
}

/* ---- ZIP-316 unified address ---- */

static void xor_into(uint8_t *a, const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) a[i] ^= b[i]; }

static void f4_h(uint8_t *out, size_t ll, int i, const uint8_t *u, size_t ul)
{
    uint8_t person[16];
    blake2b_ctx c;
    memset(person, 0, sizeof person);
    memcpy(person, "UA_F4Jumble_H", 13);
    person[13] = (uint8_t) i;
    blake2b_init(&c, ll, NULL, 0, NULL, person);
    blake2b_update(&c, u, ul);
    blake2b_final(&c, out);
}

static void f4_g(uint8_t *out, size_t lr, int i, const uint8_t *u, size_t ul)
{
    for (size_t j = 0; j * 64 < lr; j++) {
        uint8_t person[16], blk[64];
        size_t n = lr - j * 64 < 64 ? lr - j * 64 : 64;
        blake2b_ctx c;
        memset(person, 0, sizeof person);
        memcpy(person, "UA_F4Jumble_G", 13);
        person[13] = (uint8_t) i;
        person[14] = (uint8_t) j;
        person[15] = (uint8_t) (j >> 8);
        blake2b_init(&c, 64, NULL, 0, NULL, person);
        blake2b_update(&c, u, ul);
        blake2b_final(&c, blk);
        memcpy(out + j * 64, blk, n);
    }
}

void orchard_f4jumble(uint8_t *out, const uint8_t *in, size_t len)
{
    size_t ll = len / 2 < 64 ? len / 2 : 64, lr = len - ll;
    uint8_t a[64], b[192], t[192], h[64];
    memcpy(a, in, ll);
    memcpy(b, in + ll, lr);
    f4_g(t, lr, 0, a, ll);  xor_into(b, t, lr);            /* x = b ^ G0(a) */
    f4_h(h, ll, 0, b, lr);  xor_into(a, h, ll);            /* y = a ^ H0(x) */
    f4_g(t, lr, 1, a, ll);  xor_into(b, t, lr);            /* d = x ^ G1(y) */
    f4_h(h, ll, 1, b, lr);  xor_into(a, h, ll);            /* c = y ^ H1(d) */
    memcpy(out, a, ll);
    memcpy(out + ll, b, lr);
}

int orchard_unified_address(char *out, size_t cap, const uint8_t addr[43])
{
    uint8_t raw[1 + 1 + 43 + 16], j[sizeof raw], d5[100];
    int n;
    raw[0] = 0x03;                                           /* the Orchard receiver */
    raw[1] = 43;
    memcpy(raw + 2, addr, 43);
    memset(raw + 45, 0, 16);
    raw[45] = 'u';                                           /* padding: the human readable part, zero filled to 16 bytes */
    orchard_f4jumble(j, raw, sizeof raw);
    n = bech32_convert_bits(d5, sizeof d5, j, sizeof j, 8, 5, 1);
    if (n < 0) return -1;
    return bech32_encode(out, cap, "u", d5, (size_t) n, 1);
}

/* ---- internal keys, note commitments, nullifiers ---- */

int orchard_internal_fvk_light(orchard_fvk *out, const orchard_fvk *ext)
{
    uint8_t msg[1 + 32 + 32], r[64];
    msg[0] = 0x83;
    memcpy(msg + 1, ext->ak, 32);
    memcpy(msg + 33, ext->nk, 32);
    orchard_prf_expand(r, ext->rivk, 32, msg, sizeof msg);
    memcpy(out->ak, ext->ak, 32);
    memcpy(out->nk, ext->nk, 32);
    pl_reduce_scalar(out->rivk, r);
    msg[0] = 0x82;
    orchard_prf_expand(r, out->rivk, 32, msg, sizeof msg);
    memcpy(out->dk, r, 32);
    memcpy(out->ovk, r + 32, 32);
    memset(out->ivk, 0, 32);
    secure_zero(r, sizeof r);
    return 0;
}

void orchard_fvk_complete_ivk(orchard_fvk *f)
{
    uint8_t xb[32];
    commit_ivk(xb, f->rivk, f->ak, f->nk);
    pl_scalar_from_base(f->ivk, xb);
}

int orchard_internal_fvk(orchard_fvk *out, const orchard_fvk *ext)
{
    orchard_internal_fvk_light(out, ext);
    orchard_fvk_complete_ivk(out);
    return 0;
}

void orchard_diversify_hash(pl_pt *gd, const uint8_t d[11])
{
    static const char D_DOM[] = "z.cash:Orchard-gd";
    uint8_t enc[32], z = 0;
    pl_group_hash(gd, (const uint8_t *) D_DOM, sizeof D_DOM - 1, d, 11);
    pl_encode(enc, gd);
    for (int i = 0; i < 32; i++) z |= enc[i];
    if (!z) pl_group_hash(gd, (const uint8_t *) D_DOM, sizeof D_DOM - 1, NULL, 0);
}

