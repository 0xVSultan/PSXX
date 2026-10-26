#pragma once
#include <stddef.h>
#include <stdint.h>

/* Card packages: a 48 byte header, a table of 48 byte group entries, a 64 byte BIP340 signature, the groups.
 * The loader trusts a package only through the signature (of the Nostr event that carries the SHA-256 of the header and the table, see PKG_EVENT_TIME) that is valid for the public key in the
 * release record of the main card: the table lists the SHA-256 of every group, so a group is used only if its hash is the one in the signed table. A package can be replaced
 * by another one that the same key signed (a language of the data card) without a new main card. Nothing is read twice from the card: the table is checked once
 * and kept in RAM, a card that is changed afterwards can only make a read fail, never give other data.
 * The reader is a callback (offset in the package file, length), so the same code works on a memory buffer in the tests and on the frames of a card in the app. */

#define PKG_HEADER_SIZE 48
#define PKG_ENTRY_SIZE 48
#define PKG_SIG_SIZE 64                  /* the BIP340 signature after the table (format version 3) */
/* What is signed is a Nostr event (NIP-01), so that a Nostr signer can make the signature: [0,"<key hex>",TIME,KIND,[["d","<digest hex>"]],"<digest hex>"], where the digest is the SHA-256
 * of the header and the table under the tag "PSXX/package"; the signature is BIP340 over the SHA-256 of that text (the id of the event). TIME is fixed, so that the same inputs always
 * give the same package (a repeatable build); the event proves the content, not a moment. The "d" tag is the digest too, so every package is an event of its own on a relay (kind 30078
 * is replaceable by key, kind and "d": a common tag would let one package replace another). tools/nostr_publish.py makes the whole event of a package and can send it to a relay. */
#define PKG_EVENT_TIME "1792774136"
#define PKG_EVENT_KIND "30078"           /* NIP-78: application specific data */
#define PKG_ALIGN 16                     /* the groups start at multiples of it (the card is read at any byte offset, cardfile.h) */
#define PKG_MAX_GROUPS 48
#define PKG_MAX_SIZE 122624u             /* 15 blocks of 8192 bytes less the two frames (header, icon) of the first block: the biggest file a card holds */
#define PKG_MAX_RAW (4u << 20)

enum { PKG_KIND_OVERLAY = 1, PKG_KIND_DATA = 2 };
enum { PKG_CODEC_STORED = 0, PKG_CODEC_LZMA = 1, PKG_CODEC_LZMA_BASE = 2 };     /* LZMA_BASE: LZMA with the image of the base as the preset dictionary (an overlay, ovl.h) */

enum {
    PKG_OK = 0,
    PKG_ERR_READ = -1,                   /* the reader failed (card removed, bad frame) */
    PKG_ERR_MAGIC = -2,
    PKG_ERR_VERSION = -3,
    PKG_ERR_KIND = -4,
    PKG_ERR_HEADER = -5,                 /* a field of the header is out of range */
    PKG_ERR_PIN = -6,                    /* the signature of header and table is not valid for the key of the main card */
    PKG_ERR_TABLE = -7,                  /* an entry is out of range, unaligned, overlapping, not ascending */
    PKG_ERR_NOGROUP = -8,
    PKG_ERR_HASH = -9,                   /* the content of a group is not what the table says */
    PKG_ERR_SIZE = -10,                  /* the file is too short, or the buffer is too small */
    PKG_ERR_BASE = -11                   /* the overlay belongs to another base image */
};

/* read len bytes at offset off of the package file into buf; 0 on success */
typedef int (*pkg_read_fn)(void *ctx, uint32_t off, uint8_t *buf, uint32_t len);

typedef struct {
    uint16_t id;
    uint16_t flags;                      /* bits 0..3 codec, bits 4..11 the LZMA properties byte */
    uint32_t offset, len, rawlen;        /* position and size of the stored bytes in the file, size after unpacking */
    uint8_t  sha256[32];                 /* of the stored bytes */
} pkg_group;

typedef struct {
    pkg_read_fn read;
    void       *ctx;
    uint32_t    size, total;             /* bytes available, bytes the package says it has */
    uint8_t     kind;
    uint16_t    ngroups;
    uint8_t     base_id[32];
    uint8_t     digest[32];              /* SHA-256 of the header and the table */
    pkg_group   g[PKG_MAX_GROUPS];
} pkg;

#define PKG_CODEC(f) ((f) & 15)
#define PKG_PROPS(f) (((f) >> 4) & 255)

/* Reads and checks the header and the table. kind: PKG_KIND_* the caller wants, 0 for any. key: the x only public key (32 bytes) the signature has to be valid for; NULL only in tools
 * and tests (the loader always passes it). On an error p has no groups. */
int pkg_open(pkg *p, pkg_read_fn read, void *ctx, uint32_t size, int kind, const uint8_t *key);
/* the group with this id, or NULL */
const pkg_group *pkg_find(const pkg *p, uint16_t id);
/* Reads the stored bytes of a group into dst (cap >= g->len) and checks their hash; on a mismatch dst is zeroed and PKG_ERR_HASH returned. */
int pkg_read_group(const pkg *p, const pkg_group *g, uint8_t *dst, uint32_t cap);
/* An overlay: PKG_OK if it was made for the base image with this id, else PKG_ERR_BASE */
int pkg_check_base(const pkg *p, const uint8_t id[32]);
/* short text for the user interface */
const char *pkg_strerror(int rc);
