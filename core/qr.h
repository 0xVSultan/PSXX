#pragma once
/* Small static QR code encoder (ISO 18004): byte mode, versions 1..10 (up to 271 bytes at level L), all four
 * error correction levels, automatic mask selection. No heap, about 1 KB of stack. */
#include <stddef.h>
#include <stdint.h>

#define QR_MAX_VERSION 10
#define QR_MAX_SIZE (17 + 4 * QR_MAX_VERSION)         /* 57 modules */

typedef enum { QR_ECC_L = 0, QR_ECC_M = 1, QR_ECC_Q = 2, QR_ECC_H = 3 } qr_ecc;

typedef struct {
    uint8_t version;                                   /* 1..10 */
    uint8_t size;                                      /* modules per side: 17 + 4 * version */
    uint8_t mask;                                      /* chosen mask pattern 0..7 */
    uint8_t m[QR_MAX_SIZE][(QR_MAX_SIZE + 7) / 8];     /* module bitmap, bit x of row y set = dark */
} qr_code;

/* Encode `len` bytes with the smallest version that fits. Returns the version, or -1 if the data is too long. */
int qr_encode(qr_code *qr, const uint8_t *data, size_t len, qr_ecc ecc);
/* Module at (x, y): 1 dark, 0 light (also 0 outside the symbol). */
int qr_module(const qr_code *qr, int x, int y);
