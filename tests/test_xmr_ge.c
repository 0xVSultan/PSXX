/* The Ed25519 group interface the Monero signer uses, against the official Monero test vectors (tests/xmr_monero_vectors.txt, taken
 * from monero/tests/crypto/tests.txt): hash to point and key images, key derivations, derived public and secret keys. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec/ed25519.h"
#include "ec/ed25519_ge.h"
#include "hash/keccak.h"

static int fails, total;

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

static void check(const char *what, int ln, const uint8_t *got, const char *want)
{
    char g[65];
    for (int i = 0; i < 32; i++) sprintf(g + 2 * i, "%02x", got[i]);
    total++;
    if (strcmp(g, want)) { fails++; printf("FAIL %s (line %d)\n  got  %s\n  want %s\n", what, ln, g, want); }
}

/* Hs(derivation || varint(idx)) */
static void deriv_scalar(uint8_t out[32], const uint8_t der[32], unsigned idx)
{
    uint8_t buf[32 + 5], h[32];
    size_t n = 32;
    memcpy(buf, der, 32);
    do { buf[n++] = (uint8_t) ((idx & 0x7f) | (idx > 0x7f ? 0x80 : 0)); idx >>= 7; } while (idx);
    keccak256(buf, n, h);
    ed25519_sc_reduce32(h);
    memcpy(out, h, 32);
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/xmr_monero_vectors.txt", "r");
    char line[1024];
    int ln = 0;

    if (!f) { printf("cannot open the vector file\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *tok[8];
        int nt = 0;
        uint8_t a[32], b[32], c[32], h[32], out[32];
        ed_ge p, q;
        ln++;
        for (char *s = strtok(line, " \r\n"); s && nt < 8; s = strtok(NULL, " \r\n")) tok[nt++] = s;
        if (!nt) continue;
        if (!strcmp(tok[0], "generate_key_image") && nt == 4) {          /* pub sec image: image = sec * Hp(pub) */
            unhex(tok[1], a, 32); unhex(tok[2], b, 32);
            keccak256(a, 32, h);
            ed_hash_to_point(&p, h);
            ed_ge_mul(&q, &p, b);
            ed_ge_encode(out, &q);
            check("key image", ln, out, tok[3]);
        } else if (!strcmp(tok[0], "generate_key_derivation") && nt == 5) {   /* pub sec ok derivation = 8 * sec * pub */
            unhex(tok[1], a, 32); unhex(tok[2], b, 32);
            if (ed_ge_decode(&p, a)) { printf("FAIL decode (line %d)\n", ln); fails++; total++; continue; }
            ed_ge_mul(&q, &p, b);
            ed_ge_mul8(&q, &q);
            ed_ge_encode(out, &q);
            check("derivation", ln, out, tok[4]);
        } else if (!strcmp(tok[0], "derive_public_key") && nt == 6) {          /* der idx base ok result */
            unhex(tok[1], a, 32); unhex(tok[3], b, 32);
            deriv_scalar(c, a, (unsigned) atoi(tok[2]));
            ed_ge_mul_base(&p, c);
            if (ed_ge_decode(&q, b)) { printf("FAIL decode (line %d)\n", ln); fails++; total++; continue; }
            ed_ge_add(&p, &p, &q);
            ed_ge_encode(out, &p);
            check("derive public key", ln, out, tok[5]);
        } else if (!strcmp(tok[0], "derive_secret_key") && nt == 5) {          /* der idx base result */
            unhex(tok[1], a, 32); unhex(tok[3], b, 32);
            deriv_scalar(c, a, (unsigned) atoi(tok[2]));
            ed25519_sc_add(out, b, c);
            check("derive secret key", ln, out, tok[4]);
        }
    }
    fclose(f);
    {   /* group laws on a few points */
        uint8_t k1[32] = {5}, k2[32] = {9}, k3[32] = {14}, e1[32], e2[32];
        ed_ge g, a1, a2, s;
        uint8_t one[32] = {1};
        ed_ge_mul_base(&g, one);
        ed_ge_mul(&a1, &g, k1); ed_ge_mul(&a2, &g, k2);
        ed_ge_mul2_vt(&s, k1, &g, k2, &a1);                     /* 5 G + 9 * 5 G = 50 G */
        ed25519_sc_mul(e1, k1, k1);                            /* 25 */
        ed25519_sc_mul(e1, e1, k3);                            /* 350: not used, check sub instead */
        ed25519_sc_sub(e2, k1, k2);                            /* -4 */
        ed25519_sc_add(e2, e2, k3);                            /* 10 */
        { uint8_t t[32] = {10}; total++; if (memcmp(e2, t, 32)) { fails++; printf("FAIL sc_sub\n"); } }
        { uint8_t t[32] = {50}; ed_ge x; ed_ge_mul_base(&x, t); total++; if (!ed_ge_equal(&s, &x)) { fails++; printf("FAIL mul2\n"); } }
        { ed_ge n, z; ed_ge_neg(&n, &g); ed_ge_add(&z, &n, &g); total++; if (!ed_ge_is_identity(&z)) { fails++; printf("FAIL neg\n"); } }
        { ed_ge d; ed_ge_sub(&d, &a2, &a1); ed_ge x; uint8_t t[32] = {4}; ed_ge_mul_base(&x, t); total++; if (!ed_ge_equal(&d, &x)) { fails++; printf("FAIL sub\n"); } }
    }
    {   /* random and extreme scalars: the window methods against plain sums of single products */
        uint8_t ks[8][32];
        uint32_t seed = 12345;
        ed_ge g, pa, pb, q1, q2, e1, e2, lhs, rhs;
        uint8_t one[32] = {1}, a7[32] = {7};
        ed_ge_mul_base(&g, one);
        ed_ge_mul_base(&pa, a7);
        ed_ge_mul(&pb, &pa, a7);
        memset(ks[0], 0, 32);
        memset(ks[1], 0xff, 32);
        memset(ks[2], 0, 32); ks[2][0] = 1;
        memset(ks[3], 0, 32); ks[3][31] = 0x80;
        for (int i = 4; i < 8; i++) for (int j = 0; j < 32; j++) { seed = seed * 1103515245u + 12345u; ks[i][j] = (uint8_t) (seed >> 16); }
        for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) {
            ed_ge_mul(&q1, &pa, ks[i]); ed_ge_mul(&q2, &pb, ks[j]);
            ed_ge_add(&rhs, &q1, &q2);
            ed_ge_mul2_vt(&lhs, ks[i], &pa, ks[j], &pb);
            total++;
            if (!ed_ge_equal(&lhs, &rhs)) { fails++; printf("FAIL mul2 %d %d\n", i, j); }
        }
        ed_ge_mul(&e1, &g, ks[1]);                              /* the window method against the table of the base point */
        ed_ge_mul_base(&e2, ks[1]);
        total++;
        if (!ed_ge_equal(&e1, &e2)) { fails++; printf("FAIL mul vs mul_base\n"); }
        ed_ge_mul(&e1, &g, ks[6]);
        ed_ge_mul_base(&e2, ks[6]);
        total++;
        if (!ed_ge_equal(&e1, &e2)) { fails++; printf("FAIL mul vs mul_base 2\n"); }
    }
    printf("xmr group: %d checks, %d failed\n", total, fails);
    return fails != 0;
}
