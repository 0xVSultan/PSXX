#pragma once
#include <stddef.h>
#include <stdint.h>

/* NIP-19: the Bech32 forms of Nostr identifiers (npub, nsec, note: 32 bytes; nprofile, nevent, naddr: type-length-value lists). The text is Bech32 (not Bech32m) with the checksum of
 * BIP173, without its 90 character limit. These forms are for people: events and tags always carry the hex. */
enum { N19_NPUB = 1, N19_NSEC, N19_NOTE, N19_NPROFILE, N19_NEVENT, N19_NADDR, N19_NRELAY };

typedef struct {
    int      type;                  /* N19_ */
    uint8_t  id[32];                /* npub / nsec / note / nprofile: the key or id; nevent: the event id */
    uint8_t  author[32];            /* nevent, naddr: the author's key (have_author) */
    uint32_t kind;                  /* nevent, naddr: the kind (have_kind) */
    int      have_author, have_kind;
    char     relay[96];             /* the first relay of the list, "" when there is none */
    char     d[64];                 /* naddr: the identifier (the "d" tag) */
    int      nrelays;
} nip19;

/* Decode a NIP-19 string (all lower case or all upper case). Returns the type (N19_), or -1 for a bad checksum, an unknown prefix or a malformed list. */
int nip19_decode(nip19 *r, const char *s);
/* The npub / nsec / note form of 32 bytes (hrp "npub", "nsec" or "note"). Returns the length, or -1. */
int nip19_encode32(char *out, size_t cap, const char *hrp, const uint8_t v[32]);
