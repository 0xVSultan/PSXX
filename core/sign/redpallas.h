#pragma once
#include <stdint.h>

/* RedPallas (RedDSA over the Pallas curve, Zcash protocol spec 5.4.6) with the spend authorization base point of Orchard, the signature
 * of a spend in an Orchard action. */

/* The spend authorizing key ask of a spending key, negated if needed so that ak = [ask] G has an even y (ZIP-32 / protocol 4.2.3).
 * Returns 0, or -1 for the invalid key ask = 0. */
int orchard_ask(uint8_t ask[32], const uint8_t sk[32]);

/* The randomized key of an action: rsk = ask + alpha (mod q), rk = [rsk] G (32 bytes, the Orchard point encoding). */
void redpallas_randomize(uint8_t rsk[32], uint8_t rk[32], const uint8_t ask[32], const uint8_t alpha[32]);

/* A signature (R || S, 64 bytes) of the 32 byte message with the key rsk. The 80 byte randomness T of the scheme is derived from the key
 * and the message, so no random source is needed. */
void redpallas_sign(uint8_t sig[64], const uint8_t rsk[32], const uint8_t msg[32]);
/* Verification (for the tests): 0 when sig is a valid signature of msg for the key rk. */
int  redpallas_verify(const uint8_t sig[64], const uint8_t rk[32], const uint8_t msg[32]);
