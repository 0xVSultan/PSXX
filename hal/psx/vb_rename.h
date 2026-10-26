#pragma once
/* Copies of the hashes for the vanity bench, compiled with other options (-O2, unrolled): the same sources under other names, so that the normal ones
 * (-Os, as in the apps) stay in the same program for the comparison. Include before the headers of the hashes. */
#define sha256_init vf_sha256_init
#define sha256_update vf_sha256_update
#define sha256_final vf_sha256_final
#define sha256_tagged_init vf_sha256_tagged_init
#define sha256 vf_sha256
#define hmac_sha256 vf_hmac_sha256
#define ripemd160 vf_ripemd160
#define hash160 vf_hash160
#define keccak256 vf_keccak256
#define keccak_f1600 vf_keccak_f1600
