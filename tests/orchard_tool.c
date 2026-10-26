/* Command line Zcash signer for the vector generator (tools/gen_orchard_sign_vectors.py), through the dispatcher:
 *   orchard_tool <chain id> <seed hex (64 bytes)> <path> <payload hex>
 * Prints "summary ..." lines, then "result <hex>" or "error <code>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign/dispatch.h"

static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t) v; }
    return n;
}

int main(int argc, char **argv)
{
    static uint8_t pay[16384], cont[16500], buf[16384], scratch[10240];
    static hd_secret hs;
    sign_req q;
    sign_result r;
    size_t pl, pathl;
    int e;

    if (argc != 5) { fprintf(stderr, "usage: orchard_tool <chain> <seed hex> <path> <payload hex>\n"); return 2; }
    unhex(argv[2], hs.seed, 64);
    hs.passphrase = "";
    pl = unhex(argv[4], pay, sizeof pay);
    pathl = strlen(argv[3]);
    memcpy(cont, "PSXQ\x01", 5);
    cont[5] = 0;
    memset(cont + 6, 0, 8);
    memcpy(cont + 6, argv[1], strlen(argv[1]));
    cont[14] = (uint8_t) pathl;
    memcpy(cont + 15, argv[3], pathl);
    for (int i = 0; i < 4; i++) cont[15 + pathl + i] = (uint8_t) (pl >> (8 * i));
    memcpy(cont + 19 + pathl, pay, pl);
    e = sign_req_parse(&q, cont, 19 + pathl + pl);
    if (!e) e = sign_summary(&q, &hs, &txv_shared);
    if (e) { printf("error %d\n", e); return 0; }
    printf("summary %s | fee %s | sends %s | warn %x\n", txv_shared.title, txv_shared.fee, txv_shared.total, (unsigned) txv_shared.warn);
    for (int i = 0; i < txv_shared.nout; i++) printf("summary out %s %s%s\n", txv_shared.out[i].to, txv_shared.out[i].amount, txv_shared.out[i].mine ? " change" : "");
    for (int i = 0; i < txv_shared.nnote; i++) printf("summary note %s\n", txv_shared.note[i]);
    r.buf = buf; r.cap = sizeof buf; r.scratch = scratch; r.scap = sizeof scratch;
    e = sign_execute(&q, &hs, &r);
    if (e) { printf("error %d\n", e); return 0; }
    printf("result ");
    for (size_t i = 0; i < r.len; i++) printf("%02x", buf[i]);
    printf("\n");
    return 0;
}
