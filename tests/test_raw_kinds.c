/* Raw keys of the chains that sign from words in the usual way: a Cardano extended key, an sr25519 mini secret (junctions still apply), an Orchard spending key. Each key is taken from a
 * wallet of words (the secret form the program shows for it), read back with core/coin/keyparse.c and used as a raw key: it has to give the same signing key and the same address as the
 * words do. Usage: test_raw_kinds */
#include <stdio.h>
#include <string.h>
#include "coin/chains.h"
#include "coin/cardano.h"
#include "coin/keyparse.h"
#include "coin/orchard.h"
#include "coin/path.h"

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void)
{
    hd_secret hd, raw;
    hd_path p, none;
    char sec[400], a1[200], a2[200];
    const char *lbl;
    uint8_t k64[64], node[96], node2[96];

    memset(&hd, 0, sizeof hd);
    memset(&none, 0, sizeof none);
    for (int i = 0; i < 64; i++) hd.seed[i] = (uint8_t) (i * 7 + 1);
    for (int i = 0; i < 32; i++) hd.entropy[i] = (uint8_t) (i * 5 + 3);
    hd.entlen = 32;
    hd.passphrase = "";

    {   /* Cardano */
        const chain_def *ada = chain_find("ada");
        char hex[200];
        uint8_t pay[32], b[64];
        int n;

        path_parse(&p, "m/1852'/1815'/0'/0/0");
        n = chain_secret(sec, sizeof sec, &lbl, ada, &hd, &p, NULL);
        CHECK(n > 100 && !strncmp(sec, "addr_xsk1", 9), "addr_xsk: %d", n);
        CHECK(keyparse_cardano(sec, k64) == KP_OK, "the addr_xsk is read");
        CHECK(chain_signing_key(node, ada, &hd, &p, NULL) == 96 && !memcmp(node, k64, 64), "the key of the words is the key of the addr_xsk");
        for (int i = 0; i < 64; i++) sprintf(hex + 2 * i, "%02x", k64[i]);
        CHECK(keyparse_cardano(hex, b) == KP_OK && !memcmp(b, k64, 64), "128 hex digits");
        sec[20] = sec[20] == 'q' ? 'p' : 'q';
        CHECK(keyparse_cardano(sec, b) == KP_ERR_CHECKSUM, "a changed character");
        hex[127] = '\0';
        CHECK(keyparse_cardano(hex, b) == KP_ERR_FORMAT, "127 hex digits");
        memcpy(b, k64, 64);
        sprintf(hex, "%02x", b[0] | 1);                                   /* kL with a low bit set is no BIP32-Ed25519 scalar */
        for (int i = 1; i < 64; i++) sprintf(hex + 2 * i, "%02x", b[i]);
        CHECK(keyparse_cardano(hex, b) == KP_ERR_RANGE, "an unclamped scalar");
        memset(&raw, 0, sizeof raw);
        raw.no_bip = 1;
        raw.raw_curve = 5;
        memcpy(raw.raw, k64, 64);
        CHECK(chain_signing_key(node2, ada, &raw, &none, NULL) == 96 && !memcmp(node, node2, 64), "the raw Cardano key is the signing key");
        CHECK(chain_raw_ok(ada, &raw) && !chain_raw_ok(chain_find("eth"), &raw) && !chain_raw_ok(chain_find("dotsr"), &raw), "a Cardano key signs for Cardano only");
        cardano_pubkey(pay, node);
        cardano_enterprise_address(a1, sizeof a1, pay);
        CHECK(chain_address(a2, sizeof a2, ada, &raw, &none) > 0 && !strcmp(a1, a2) && !strncmp(a2, "addr1v", 6), "the enterprise address: %s", a2);
        CHECK(chain_address(a1, sizeof a1, ada, &hd, &p) > 0 && !strncmp(a1, "addr1q", 6), "the base address of the words differs (it has a staking part)");
        raw.raw_curve = 2;
        CHECK(!chain_raw_ok(ada, &raw), "a secp256k1 key is no Cardano key");
    }
    {   /* sr25519 */
        const chain_def *dot = chain_find("dotsr"), *ksm = chain_find("ksm");
        uint8_t k32[32], s1[96], s2[96];
        char mini[80];
        int n;

        n = chain_secret(sec, sizeof sec, &lbl, dot, &hd, &none, "//polkadot//0");
        CHECK(n == 66 + 13 && sec[0] == '0' && sec[1] == 'x', "secret URI: %d", n);
        memcpy(mini, sec, 66);
        mini[66] = 0;
        CHECK(keyparse_hex32(mini, k32) == KP_OK, "the mini secret is read");
        memset(&raw, 0, sizeof raw);
        raw.no_bip = 1;
        raw.raw_curve = 3;
        memcpy(raw.raw, k32, 32);
        for (int w = 0; w < 2; w++) {
            const char *j = w ? "" : "//polkadot//0";

            CHECK(chain_address_str(a1, sizeof a1, w ? ksm : dot, &hd, j) > 0 && chain_address_str(a2, sizeof a2, w ? ksm : dot, &raw, j) > 0 && !strcmp(a1, a2), "sr25519 address, junctions \"%s\": %s %s", j, a1, a2);
        }
        CHECK(chain_signing_key(s1, dot, &hd, &none, "//polkadot//0") == 32 && chain_signing_key(s2, dot, &raw, &none, "//polkadot//0") == 32 && !memcmp(s1, s2, 32), "the signing key with junctions");
        CHECK(chain_raw_ok(dot, &raw) && chain_raw_ok(ksm, &raw) && !chain_raw_ok(chain_find("dot"), &raw), "an sr25519 key signs for the sr25519 chains only");
        n = chain_secret(sec, sizeof sec, &lbl, dot, &raw, &none, "//x");
        CHECK(n == 66 + 3 && !strncmp(sec, mini, 66), "the secret view of a raw sr25519 key");
    }
    {   /* Orchard */
        const chain_def *zu = chain_find("zecu");
        uint8_t sk[32], chain[32];

        path_parse(&p, "m/32'/133'/0'");
        orchard_master(sk, chain, hd.seed, 64);
        for (int i = 0; i < p.n; i++) orchard_child(sk, chain, p.idx[i]);
        memset(&raw, 0, sizeof raw);
        raw.no_bip = 1;
        raw.raw_curve = 4;
        memcpy(raw.raw, sk, 32);
        CHECK(chain_address(a1, sizeof a1, zu, &hd, &p) > 0 && chain_address(a2, sizeof a2, zu, &raw, &none) > 0 && !strcmp(a1, a2) && !strncmp(a1, "u1", 2) && strlen(a1) <= 144, "the Orchard address of the spending key (%zu characters, 3 lines of 48 on the screen)", strlen(a1));
        CHECK(chain_raw_ok(zu, &raw) && !chain_raw_ok(chain_find("zec"), &raw) && !chain_raw_ok(chain_find("ada"), &raw), "an Orchard key signs for Orchard only");
    }
    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
