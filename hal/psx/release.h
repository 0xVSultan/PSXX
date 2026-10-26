#pragma once
#include <stdint.h>

/* The release record of an image. It sits in its own section (.psxx_release, see exe_hi.ld), 128 bytes, at a fixed place in the
 * loaded image, and tools/release.py fills it in after the build without moving anything:
 *   key      the x only public key (BIP340) that has to have signed the package of the signer and the language module (the loader trusts the package through the signature, core/pkg/pkg.h),
 *   base_id  SHA-256 of the image with key, base_id and data_key set to zero: the identity of this build, written into the overlay package (so it is signed), compared by the loader.
 * data_key the public key that has to have signed the data package (the language card, tools/data_pack.py); the same key as `key` while one project key signs everything. Packages of the
 * data card are signed on their own, so a language can be replaced without a new main card.
 * All three are zero in a build that tools/release.py has not finished (the data key stays zero in a release without a data package); the base id is the hash of the
 * image with all three set to zero. */
typedef struct {
    uint8_t magic[8];        /* "PSXXREL1" */
    uint8_t key[32];
    uint8_t base_id[32];
    uint8_t data_key[32];
    uint8_t reserved[24];
} psxx_release;

extern const psxx_release psxx_release_info;
