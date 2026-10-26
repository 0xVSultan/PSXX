/* The text forms of a secret key (core/coin/keyparse.c): hex, nsec1, WIF. The vectors are made by tools/nsec_tool.py and a Base58Check encoder (Python). */
#include "coin/keyparse.h"
#include <stdio.h>
#include <string.h>

static int fails;

static void check(int cond, const char *what)
{
    if (!cond) { printf("FAIL %s\n", what); fails++; }
}

static void hex(char *out, const uint8_t *k)
{
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", k[i]);
}

static const struct { const char *hex, *nsec, *wif_c, *wif_u, *wif_t; } V[] = {
    {"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", "nsec1e2tczyk2rw7u47kzxxee5g7ufkncdmlcz37yuu4espmcttlwfzaslzdaqz",
     "L41XHGJA5QX43QRG3FEwPbqD5BYvy6WxUxqAMM9oQdHJ5FcRHcGk", "5KMWWy2d3Mjc8LojNoj8Lcz9B1aWu8bRofUgGwQk959Dw5h2iyw", "cUNWkBJ1WUDKCqtXRf44kvLGhQrLdYceYzydTmcJujwJKzdhR65V"},
    {"42b08dee52c808b18b03986eec72c4e57970f65402c959e9f0a6bb48b814609a", "nsec1g2cgmmjjeqytrzcrnphwcukyu4uhpaj5qty4n60s56a53wq5vzdqpecmhp",
     "KyTM59UWDsPrBPvsfbfJBGXkasnfvvok7wyEpYVatQb8EcCvh4oY", "5JKf5ZjUvDKmg4PB7w59RXhxBr7iu6PpqFGThE2VXE3kL1rWvwW", "cPpLY4UMew67LqQ941URYb2pD765bNuSBz7hvxx6PXF8VMFHKNjF"},
    {"a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89", "nsec14qgq4e42r9qdpdnrhvcu63npgt4mm023suf3hyke8qvfs7pjawysz6pk8l",
     "L2rQK5gRetehiKJCzVkNn2AhkHznigraKCDiwNDGSQyHqhKRnBVL", "5K6JWvd7wobNTabiEUoz3Vp4Ln5wK494UERBQeRyy4AairJCgcW", "cTDPmzgH5xLxskmUNuZW9LfmNXJCP8xGPENC3nfmwXdJ6SRMAuGD"},
};

static const struct { const char *hex, *b58seed, *keypair, *near, *stellar; } E[] = {
    {"6b95ece926b8f14f02adbe686269c44e10082c962e82092e33a9ab87d3986a64", "8EyDfwij9RundKMzWyyWsV1fY1P8177RYSRm1FVoqvM9", "39kuLMWbDvnEmpBEnTDasQUtUuG7dk3jEfGCAwps8qtd5kUQY9vtJAViyFECskxHg6TGqN3wEVLiYWyfVdv8yES4", "ed25519:39kuLMWbDvnEmpBEnTDasQUtUuG7dk3jEfGCAwps8qtd5kUQY9vtJAViyFECskxHg6TGqN3wEVLiYWyfVdv8yES4", "SBVZL3HJE24PCTYCVW7GQYTJYRHBACBMSYXIECJOGOU2XB6TTBVGIL5T"},
    {"68f30b33fb33c1b674f5568703c657b6872af5f3b0118518651d97aa782db14d", "84gMHQ7cRYmpcg9LXJbz5EvKaSaA6efgSw3veybfLXqW", "36hbXQLiG9SRGM7FvSFuAApdPna7oSwjVSK58xpepSErRuUjw2d2HyuR2WBjEXvu9heKnLPwcN3CM7DphgqXXZuH", "ed25519:36hbXQLiG9SRGM7FvSFuAApdPna7oSwjVSK58xpepSErRuUjw2d2HyuR2WBjEXvu9heKnLPwcN3CM7DphgqXXZuH", "SBUPGCZT7MZ4DNTU6VLIOA6GK63IOKXV6OYBDBIYMUOZPKTYFWYU2NB4"},
    {"80473d9c50244391045ab80095dcf17a67ea86740f428b821c8af0e16423f4a3", "9dkC5Fmq5AN7TKSypN3ybdyW1bQERdqzC6L7VxjEf28i", "3ZkdXiudYKLcz8tPbhcWuDgYZaXC4YUrZkNWNQ9MfPkWzGix95gZpygFY4chRNJN1owafhpSXZxvCeZiXE7tG5im", "ed25519:3ZkdXiudYKLcz8tPbhcWuDgYZaXC4YUrZkNWNQ9MfPkWzGix95gZpygFY4chRNJN1owafhpSXZxvCeZiXE7tG5im", "SCAEOPM4KASEHEIELK4ABFO46F5GP2UGOQHUFC4CDSFPBYLEEP2KHZ7H"},
};

int main(void)
{
    uint8_t k[32];
    char h[65];

    for (unsigned i = 0; i < sizeof V / sizeof V[0]; i++) {
        const char *form[5] = {V[i].hex, V[i].nsec, V[i].wif_c, V[i].wif_u, V[i].wif_t};
        char up[100];

        for (int f = 0; f < 5; f++) {
            memset(k, 0, 32);
            check(keyparse_secp256k1(form[f], k) == KP_OK, "a good form is read");
            hex(h, k);
            check(!strcmp(h, V[i].hex), "the key is the one it was made from");
        }
        for (size_t j = 0; j <= strlen(V[i].nsec); j++) up[j] = (char) (V[i].nsec[j] >= 'a' && V[i].nsec[j] <= 'z' ? V[i].nsec[j] - 32 : V[i].nsec[j]);
        check(keyparse_secp256k1(up, k) == KP_OK, "an upper case nsec is read");
        for (size_t j = 0; j <= strlen(V[i].hex); j++) up[j] = (char) (V[i].hex[j] >= 'a' && V[i].hex[j] <= 'f' ? V[i].hex[j] - 32 : V[i].hex[j]);
        check(keyparse_secp256k1(up, k) == KP_OK && keyparse_hex32(up, k) == KP_OK, "upper case hex is read");
        for (int f = 1; f < 5; f++) {                                    /* every character of every form changed: refused (the checksum, or the characters) */
            char bad[100];
            int refused = 1;

            for (size_t j = 0; j < strlen(form[f]); j++) {
                strcpy(bad, form[f]);
                bad[j] = bad[j] == 'q' ? 'p' : 'q';
                if (keyparse_secp256k1(bad, k) == KP_OK) refused = 0;
            }
            check(refused, "a changed character is refused");
        }
    }
    check(keyparse_secp256k1("npub1fksqd72ch6a83mz5gs7lfgl4ygmj20m6ar9ak97ueul74ftlxynq8wkjwr", k) != KP_OK, "an npub is not a key");
    check(keyparse_secp256k1("", k) != KP_OK, "empty");
    check(keyparse_secp256k1("nsec1", k) != KP_OK, "nsec1 alone");
    check(keyparse_secp256k1("0000000000000000000000000000000000000000000000000000000000000000", k) == KP_ERR_RANGE, "zero is not a key");
    check(keyparse_secp256k1("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", k) == KP_ERR_RANGE, "n is not a key");
    check(keyparse_secp256k1("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", k) == KP_OK, "n - 1 is a key");
    check(keyparse_secp256k1("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48b", k) != KP_OK, "63 hex digits");
    check(keyparse_secp256k1("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bg", k) != KP_OK, "a non hex digit");
    check(keyparse_hex32("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", k) == KP_OK, "hex32");
    check(keyparse_hex32("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb00", k) != KP_OK, "hex32: too long");
    check(keyparse_hex32("0000000000000000000000000000000000000000000000000000000000000000", k) == KP_OK, "hex32 takes any 32 bytes (the curve decides)");
    for (unsigned i = 0; i < sizeof E / sizeof E[0]; i++) {
        const char *form[5] = {E[i].hex, E[i].b58seed, E[i].keypair, E[i].near, E[i].stellar};
        char zx[80], lowst[80];

        for (int f = 0; f < 5; f++) {
            memset(k, 0, 32);
            check(keyparse_ed25519(form[f], k) == KP_OK, "an ed25519 form is read");
            hex(h, k);
            check(!strcmp(h, E[i].hex), "the ed25519 seed is the one it was made from");
        }
        snprintf(zx, sizeof zx, "0x%s", E[i].hex);
        check(keyparse_ed25519(zx, k) == KP_OK && keyparse_hex32(zx, k) == KP_OK, "0x hex");
        for (size_t j = 0; j <= strlen(E[i].stellar); j++) lowst[j] = (char) (E[i].stellar[j] >= 'A' && E[i].stellar[j] <= 'Z' ? E[i].stellar[j] + 32 : E[i].stellar[j]);
        check(keyparse_ed25519(lowst, k) == KP_OK, "a lower case Stellar secret");
        for (int f = 2; f < 5; f++) {                                    /* every character of a keypair or a Stellar secret changed: refused */
            char bad[100];
            int refused = 1;

            for (size_t j = 0; j < strlen(form[f]); j++) {
                strcpy(bad, form[f]);
                bad[j] = bad[j] == 'Z' ? 'Y' : 'Z';
                if (keyparse_ed25519(bad, k) == KP_OK) refused = 0;
            }
            check(refused, "a changed character of a keypair or a Stellar secret is refused");
        }
    }
    check(keyparse_ed25519("39kuLMWbDvnEmpBEnTDasQUtUuG7dk3jEfGCAwps8qtd5pNpBeeyBzzSNwMBPGDja2CW6NchwSSd8PHYzqE8h36Q", k) == KP_ERR_CHECKSUM, "a keypair whose public key is not the seed's");
    check(keyparse_ed25519("", k) != KP_OK && keyparse_ed25519("0OIl", k) != KP_OK, "empty and not base58");
    check(keyparse_secp256k1("0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", k) == KP_OK, "a secp256k1 key with 0x");
    printf("%s (%d failed)\n", fails ? "FAILED" : "ok", fails);
    return fails != 0;
}
