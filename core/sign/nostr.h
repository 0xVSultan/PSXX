#pragma once
#include <stddef.h>
#include <stdint.h>
#include "sign/txview.h"

/* Nostr events (NIP-01). The request is the event as JSON with at least "kind", "created_at", "tags" and "content" (a "pubkey",
 * "id" or "sig" in it is ignored: the id is computed here and the pubkey is ours). The id is the SHA-256 of the canonical
 * serialisation [0, pubkey, created_at, kind, tags, content]; the signature is BIP340 Schnorr over the id. */
enum { NOSTR_OK = 0, NOSTR_ERR_PARSE = -1, NOSTR_ERR_SPACE = -2, NOSTR_ERR_KEY = -3, NOSTR_ERR_SIZE = -4 /* a message over 4096 bytes: neither encrypted nor decrypted here */ };

int nostr_summary(const char *json, size_t len, tx_view *v);
/* scratch holds the canonical tags and content (about the size of the event); out gets the complete event JSON. */
int nostr_sign(const char *json, size_t len, const uint8_t priv[32], char *scratch, size_t scap, char *out, size_t cap, size_t *outlen);

/* Encrypted direct messages (NIP-04, NIP-44; core/sign/nip44.h) and the NIP-19 forms (core/sign/nip19.h).
 *  Signing an event with "encrypt":"nip44" or "nip04" in the request: the "content" is the plain text, the signer replaces it by the encrypted message to the "recipient" (npub,
 *  nprofile or hex; without it the first "p" tag) and signs that. The nonce (IV) comes from an HMAC of the text, not from a random source. Notes of the summary show the recipient
 *  as npub, the first "e" tag as note1..., and how many "nostr:" references of the content are not valid NIP-19 strings.
 *  A decrypt request ({"content":"<message>","pubkey":"<the other side>"}, optionally "with", "decrypt":"nip44"|"nip04"; a whole event can be given) is a message request for the
 *  chain nostr: the summary shows the plain text; nostr_decrypt writes it as the result. A wrong key or a changed NIP-44 message gives NOSTR_ERR_KEY. */
int nostr_decrypt_summary(const char *json, size_t len, const uint8_t priv[32], tx_view *v);
int nostr_decrypt(const char *json, size_t len, const uint8_t priv[32], char *scratch, size_t scap, char *out, size_t cap, size_t *outlen);
