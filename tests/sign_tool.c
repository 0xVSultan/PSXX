/* Command line signer for the vector generators (tools/gen_sign_vectors.py), which check the output with reference libraries.
 *   sign_tool sr25519 <mini secret hex> <message hex>     -> signature hex */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/substrate.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t) v;
    }
    return n;
}

int main(int argc, char **argv)
{
    static uint8_t msg[4096];
    uint8_t mini[32], scalar[32], sig[64];
    size_t ml;

    if (argc == 4 && !strcmp(argv[1], "sr25519")) {
        unhex(argv[2], mini, 32);
        ml = unhex(argv[3], msg, sizeof msg);
        sr25519_expand(scalar, mini);
        sr25519_sign(sig, scalar, msg, ml);
        for (int i = 0; i < 64; i++) printf("%02x", sig[i]);
        printf("\n");
        return 0;
    }
    fprintf(stderr, "usage: sign_tool sr25519 <mini hex> <msg hex>\n");
    return 2;
}
