/* Host utility: shows and signs the requests (PSXXRQ files) of a memory card image the way the PSX signer does.
 *   sign_cli <card.mcd> [passphrase] [xmr:<the 25 Monero words>]   uses the BIP39 test mnemonic ("abandon ... about"); the Monero words for requests of the coin xmr
 * Prints the summary of every request and the result. Not a test: a way to see the screens without the console. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coin/bip39.h"
#include "coin/xmr_seed.h"
#include "sign/dispatch.h"

static uint8_t card[131072], res[8192], scratch[10240];
static tx_view v;

int main(int argc, char **argv)
{
    FILE *f;
    hd_secret s;
    const char *words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char *pass = "", *xw = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strncmp(argv[i], "xmr:", 4)) xw = argv[i] + 4;
        else pass = argv[i];
    }

    if (argc < 2 || !(f = fopen(argv[1], "rb"))) { printf("usage: sign_cli <card.mcd> [passphrase]\n"); return 2; }
    if (fread(card, 1, sizeof card, f) != sizeof card) { printf("not a 128 KB image\n"); return 2; }
    fclose(f);
    memset(&s, 0, sizeof s);
    bip39_seed(words, pass, s.seed);
    s.entlen = bip39_mnemonic_to_entropy(words, s.entropy);
    s.passphrase = pass;
    if (xw) {
        if (xmr_seed_decode(xw, s.xmr_seed)) { printf("the Monero words are not valid\n"); return 2; }
        s.xmr_ok = 1;
    }
    for (int b = 1; b <= 15; b++) {
        const uint8_t *e = card + b * 128;
        sign_req q;
        sign_result r;
        uint32_t n;
        int rc;
        if ((e[0] & 0xF0) != 0x50 || memcmp(e + 22, "PSXXRQ", 6)) continue;
        n = (uint32_t) card[64 * b * 128 + 256] | (uint32_t) card[64 * b * 128 + 257] << 8;
        printf("=== block %d  %.20s  (%u bytes)\n", b, (const char *) (e + 10), n);
        rc = sign_req_parse(&q, card + 64 * b * 128 + 256 + 4, n);
        if (!rc) rc = sign_summary(&q, &s, &v);
        if (rc) { printf("  summary: %s\n", sign_error_text(rc)); continue; }
        printf("  %s\n", v.title);
        for (int i = 0; i < v.nout; i++) printf("  -> %s%s\n     %s\n", v.out[i].to, v.out[i].mine ? "  (change)" : "", v.out[i].amount);
        if (v.total[0]) printf("  sends: %s\n", v.total);
        if (v.fee[0]) printf("  fee:   %s\n", v.fee);
        for (int i = 0; i < v.nnote; i++) printf("  note:  %s\n", v.note[i]);
        printf("  warn:  0x%x\n", v.warn);
        r.buf = res; r.cap = sizeof res; r.scratch = scratch; r.scap = sizeof scratch;
        rc = sign_execute(&q, &s, &r);
        if (rc) { printf("  sign:  %s\n", sign_error_text(rc)); continue; }
        printf("  result (%s, %zu bytes): ", r.label, r.len);
        for (size_t i = 0; i < r.len && i < 64; i++) printf("%02x", res[i]);
        printf("%s\n", r.len > 64 ? "..." : "");
    }
    return 0;
}
