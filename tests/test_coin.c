/* The coin textures of card A (hal/psx/coin_data.h, tools/gen_coin.py) through the decoder of hal/psx/coin_cm.h: the texels have to be the ones the generator
 * hashed. Usage: test_coin */
#include <stdio.h>
#include <string.h>
#include "hash/sha256.h"
#include "../hal/psx/coin_data.h"
#include "../hal/psx/coin_cm.h"

int main(void)
{
    static const uint8_t WH[6] = {COIN_SIZE, COIN_SIZE, COIN_IN, COIN_IN, COIN_IN, COIN_IN};
    static uint16_t p[COIN_CM_CTX];
    static uint8_t n[COIN_CM_CTX], tx[COIN_SIZE * COIN_SIZE + 2 * COIN_IN * COIN_IN];
    uint8_t h[32];
    char hex[65];

    coin_cm_decode(COIN_CM, WH, 3, tx, p, n);
    sha256(tx, sizeof tx, h);
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
    printf("coin textures: %u bytes of the model -> %u texels, %s\n", (unsigned) sizeof COIN_CM, (unsigned) sizeof tx, strcmp(hex, COIN_TEXELS_SHA256) ? "WRONG" : "ok");
    return strcmp(hex, COIN_TEXELS_SHA256) != 0;
}
