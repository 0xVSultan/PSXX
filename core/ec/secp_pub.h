#pragma once
#include <stdint.h>

/* Public key arithmetic that the signing code does not need but the multisig wallets do (core/sign/mswallet.c): the sum of two compressed points, and the child of an
 * extended public key (BIP32 CKDpub, non-hardened). Built on the field operations of secp256k1.c (secp_fe_*), so it lives in the overlay. */

/* r = a + b (33 byte compressed points). Returns 0, or -1 if a or b is not a point, or a = +-b (the sum would be a doubling or infinity). */
int secp256k1_pubkey_add(uint8_t r[33], const uint8_t a[33], const uint8_t b[33]);
/* CKDpub: the child with index < 2^31 of the public key `pub` with chain code `cc`. Returns 0, or -1 for an index >= 2^31 or the (negligible) invalid child. */
int secp256k1_ckd_pub(uint8_t child_pub[33], uint8_t child_cc[32], const uint8_t pub[33], const uint8_t cc[32], uint32_t index);

/* ECDH of Nostr (NIP-04, NIP-44): the x coordinate of priv * P, P the point of the x only public key pub. Constant time. Returns 0, or -1 for a bad key or an x that is not on the curve. */
int secp256k1_ecdh_x(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);
