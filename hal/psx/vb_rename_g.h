#pragma once
/* Copies of the hashes for the vanity bench, compiled with other options (-O2, unrolled): the same sources under other names, so that the normal ones
 * (-Os, as in the apps) stay in the same program for the comparison. Include before the headers of the hashes. */
#define sha256_init vg_sha256_init
#define sha256_update vg_sha256_update
#define sha256_final vg_sha256_final
#define sha256_tagged_init vg_sha256_tagged_init
#define sha256 vg_sha256
#define hmac_sha256 vg_hmac_sha256
#define ripemd160 vg_ripemd160
#define hash160 vg_hash160
#define keccak256 vg_keccak256
#define keccak_f1600 vg_keccak_f1600
