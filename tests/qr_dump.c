/* Test helper: reads lines "<ecc 0..3> <hex data>" from stdin, encodes each as a QR code and writes
 *   QR <version> <size> <mask>
 *   <size lines of 0/1>
 * (or "QR -1" if the data does not fit). Used by tests/test_qr.py, which decodes the matrices with OpenCV. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qr.h"

int main(void)
{
    static char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        int ecc;
        char hex[3000];
        uint8_t data[1500];
        size_t n = 0;
        if (sscanf(line, "%d %2999s", &ecc, hex) < 1) continue;
        if (!strcmp(hex, "-")) hex[0] = 0;
        for (const char *p = hex; p[0] && p[1] && n < sizeof data; p += 2) {
            unsigned v;
            sscanf(p, "%2x", &v);
            data[n++] = (uint8_t) v;
        }
        qr_code *q = malloc(sizeof *q);
        int ver = qr_encode(q, data, n, (qr_ecc) ecc);
        if (ver < 0) { puts("QR -1"); free(q); continue; }
        printf("QR %d %d %d\n", ver, q->size, q->mask);
        for (int y = 0; y < q->size; y++) {
            for (int x = 0; x < q->size; x++) putchar(qr_module(q, x, y) ? '1' : '0');
            putchar('\n');
        }
        free(q);
    }
    return 0;
}
