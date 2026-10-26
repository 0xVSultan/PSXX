#pragma once
#include <stdint.h>

/* What the first 16 frames of a memory card (the header frame and the 15 directory entries) say: whether the card is formatted, a fingerprint of them, how many files it has,
 * and whether it is a FreePSXBoot card. The fingerprint is a CRC-32 of the 2048 bytes: it changes when the directory does, which is what a change of
 * the card or of the image of a switchable card does; it is an indication, the hash of the package is what decides. */

#define DIRSCAN_FRAMES 16
#define DIRSCAN_FRAME 128

typedef struct {
    int      formatted;          /* frame 0 is "MC" with the right checksum */
    uint32_t fingerprint;
    int      used;               /* entries that start a file (state 0x51) */
    int      bad_sums;           /* entries 1..15 whose checksum is wrong */
    int      boot;               /* an entry named FreePSXBoot, or one with a size that no card has: the file system of a FreePSXBoot card is damaged on purpose */
} dirscan;

void dirscan_run(dirscan *d, const uint8_t frames[DIRSCAN_FRAMES][DIRSCAN_FRAME]);
