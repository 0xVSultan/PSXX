/* A demonstration overlay: it is linked at a fixed address against a base image (ovl_base_demo.c) and calls its functions (printf, sha256) directly.
 * The loader (M3) copies the image to its address, clears the bss and calls ovl_main(); the return value says that the code ran. */
#include <stdio.h>
#include <stdint.h>
#include "hash/sha256.h"

#define OVL_DEMO_RESULT 0x0DE70001

static uint8_t scratch[64];                       /* bss: the loader has to clear it */
static const char greeting[] = "overlay demo";    /* rodata */
static int calls = 1;                             /* data */

int ovl_main(void)
{
    sha256((const uint8_t *) greeting, sizeof greeting - 1, scratch);
    printf("[ovl] %s ran, sha256 starts %02x%02x%02x%02x\n", greeting, scratch[0], scratch[1], scratch[2], scratch[3]);
    return OVL_DEMO_RESULT + calls - 1;
}
