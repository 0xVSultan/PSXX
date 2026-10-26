#pragma once
#include <stddef.h>
#include <stdint.h>

/* Watch-only export of a Bitcoin account (BlueWallet, Sparrow, Electrum ...): the extended public key of m/purpose'/0'/0' and the output descriptor with its checksum. Everything
 * in it is public. The key is serialised with the version of the kind: zpub (BIP84), ypub (BIP49), xpub (BIP44 and BIP86). */
enum { XPUB_BIP84 = 0, XPUB_BIP49 = 1, XPUB_BIP44 = 2, XPUB_BIP86 = 3, XPUB_BIP47 = 4, XPUB_KINDS = 5 };
/* XPUB_BIP47: the BIP47 reusable payment code (version 1) of m/47'/0'/0': `key` is the "PM8T..." text (Base58Check of 0x47 and 80 bytes: 0x01, features 0x00, the compressed public key,
 * the chain code, 13 zero bytes) and `desc` is empty (no descriptor). */

#define XPUB_KEY_MAX 120
#define XPUB_DESC_MAX 220

/* The BIP32 account key from the BIP39 seed (64 bytes) as zpub / ypub / xpub text in `key`, and the descriptor
 * wpkh([fp/84h/0h/0h]xpub.../<0;1>/ *)#checksum  (sh(wpkh()), pkh(), tr() for the other kinds; the descriptor always carries the xpub form). Returns 0, or -1. */
int xpub_export(char key[XPUB_KEY_MAX], char desc[XPUB_DESC_MAX], const uint8_t seed[64], int kind);
/* What the kind is called, and its path. */
const char *xpub_name(int kind);
const char *xpub_path(int kind);
/* The checksum (8 characters and the NUL) of the descriptor text (Bitcoin Core's descriptor checksum); returns 0, or -1 for a character that is not allowed. */
int descriptor_checksum(const char *desc, char out[9]);
