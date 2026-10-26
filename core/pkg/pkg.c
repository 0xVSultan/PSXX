#include "pkg.h"
#include <string.h>
#include "hash/sha256.h"
#include "ec/secp256k1.h"
#include "tr.h"

static uint32_t rd16(const uint8_t *p) { return p[0] | ((uint32_t) p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | (rd16(p + 2) << 16); }
static uint32_t up(uint32_t n) { return (n + PKG_ALIGN - 1) / PKG_ALIGN * PKG_ALIGN; }

/* the id of the Nostr event the signature is of (pkg.h): SHA-256 of the text of NIP-01, made here from the key and the digest */
static void event_id(uint8_t id[32], const uint8_t key[32], const uint8_t digest[32])
{
    static const char HEX[] = "0123456789abcdef", A[] = "[0," "\"", B[] = "\"," PKG_EVENT_TIME "," PKG_EVENT_KIND ",[[\"d\",\"", D[] = "\"]],\"", C[] = "\"]";
    char ev[sizeof A + sizeof B + sizeof D + sizeof C + 192];
    size_t o = 0;

    memcpy(ev, A, sizeof A - 1); o += sizeof A - 1;
    for (int i = 0; i < 32; i++) { ev[o++] = HEX[key[i] >> 4]; ev[o++] = HEX[key[i] & 15]; }
    memcpy(ev + o, B, sizeof B - 1); o += sizeof B - 1;
    for (int i = 0; i < 32; i++) { ev[o++] = HEX[digest[i] >> 4]; ev[o++] = HEX[digest[i] & 15]; }              /* the "d" tag */
    memcpy(ev + o, D, sizeof D - 1); o += sizeof D - 1;
    for (int i = 0; i < 32; i++) { ev[o++] = HEX[digest[i] >> 4]; ev[o++] = HEX[digest[i] & 15]; }              /* the content */
    memcpy(ev + o, C, sizeof C - 1); o += sizeof C - 1;
    sha256((const uint8_t *) ev, o, id);
}

int pkg_open(pkg *p, pkg_read_fn read, void *ctx, uint32_t size, int kind, const uint8_t *key)
{
    uint8_t h[PKG_HEADER_SIZE], chunk[8 * PKG_ENTRY_SIZE];
    uint32_t n, total, tbl_end, k, prev_end;
    int prev_id = -1;
    sha256_ctx sc;

    memset(p, 0, sizeof *p);
    if (!read || size < PKG_HEADER_SIZE + PKG_ENTRY_SIZE) return PKG_ERR_SIZE;
    if (read(ctx, 0, h, PKG_HEADER_SIZE)) return PKG_ERR_READ;
    if (memcmp(h, "PSXP", 4)) return PKG_ERR_MAGIC;
    if (h[4] != 3) return PKG_ERR_VERSION;
    if ((h[5] != PKG_KIND_OVERLAY && h[5] != PKG_KIND_DATA) || (kind && h[5] != kind)) return PKG_ERR_KIND;
    n = rd16(h + 6);
    total = rd32(h + 8);
    if (n == 0 || n > PKG_MAX_GROUPS || rd32(h + 12) != 0) return PKG_ERR_HEADER;
    if (h[5] == PKG_KIND_DATA) for (k = 16; k < 48; k++) if (h[k]) return PKG_ERR_HEADER;
    tbl_end = PKG_HEADER_SIZE + n * PKG_ENTRY_SIZE;
    if (total < tbl_end + PKG_SIG_SIZE || total > size || total > PKG_MAX_SIZE) return PKG_ERR_HEADER;

    sha256_tagged_init(&sc, "PSXX/package");                       /* the signed message: header and table, under a tag of its own (the key may sign other things) */
    sha256_update(&sc, h, PKG_HEADER_SIZE);
    for (k = 0; k < n; ) {                                         /* the table, a few entries per read */
        uint32_t c = n - k < 8 ? n - k : 8;
        if (read(ctx, PKG_HEADER_SIZE + k * PKG_ENTRY_SIZE, chunk, c * PKG_ENTRY_SIZE)) return PKG_ERR_READ;
        sha256_update(&sc, chunk, c * PKG_ENTRY_SIZE);
        for (uint32_t i = 0; i < c; i++) {
            const uint8_t *e = chunk + i * PKG_ENTRY_SIZE;
            pkg_group *g = &p->g[k + i];
            g->id = (uint16_t) rd16(e);
            g->flags = (uint16_t) rd16(e + 2);
            g->offset = rd32(e + 4);
            g->len = rd32(e + 8);
            g->rawlen = rd32(e + 12);
            memcpy(g->sha256, e + 16, 32);
        }
        k += c;
    }
    sha256_final(&sc, p->digest);
    if (key) {                                                     /* the 64 bytes after the table: the BIP340 signature of the event id; the key is the one in the release record of the main card */
        uint8_t sig[PKG_SIG_SIZE], id[32];
        if (read(ctx, tbl_end, sig, PKG_SIG_SIZE)) { memset(p, 0, sizeof *p); return PKG_ERR_READ; }
        event_id(id, key, p->digest);
        if (secp256k1_schnorr_verify(sig, id, key)) { memset(p, 0, sizeof *p); return PKG_ERR_PIN; }
    }

    prev_end = up(tbl_end + PKG_SIG_SIZE);
    for (k = 0; k < n; k++) {
        const pkg_group *g = &p->g[k];
        uint32_t codec = PKG_CODEC(g->flags), props = PKG_PROPS(g->flags);
        int bad = (int) g->id <= prev_id || g->offset % PKG_ALIGN || g->offset < prev_end || g->len == 0 || (uint64_t) g->offset + g->len > total || (g->flags >> 12);

        if (codec == PKG_CODEC_STORED) bad |= g->rawlen != g->len;
        else if (codec == PKG_CODEC_LZMA || codec == PKG_CODEC_LZMA_BASE) bad |= props > 224 || g->rawlen == 0 || g->rawlen > PKG_MAX_RAW;
        else bad = 1;
        if (bad) { memset(p, 0, sizeof *p); return PKG_ERR_TABLE; }
        prev_id = g->id;
        prev_end = g->offset + up(g->len);
    }
    p->read = read;
    p->ctx = ctx;
    p->size = size;
    p->total = total;
    p->kind = h[5];
    p->ngroups = (uint16_t) n;
    memcpy(p->base_id, h + 16, 32);
    return PKG_OK;
}

const pkg_group *pkg_find(const pkg *p, uint16_t id)
{
    for (unsigned k = 0; k < p->ngroups; k++) if (p->g[k].id == id) return &p->g[k];
    return 0;
}

int pkg_read_group(const pkg *p, const pkg_group *g, uint8_t *dst, uint32_t cap)
{
    uint8_t h[32];

    if (!p->ngroups || g < p->g || g >= p->g + p->ngroups) return PKG_ERR_NOGROUP;
    if (cap < g->len) return PKG_ERR_SIZE;
    if (p->read(p->ctx, g->offset, dst, g->len)) { memset(dst, 0, g->len); return PKG_ERR_READ; }
    sha256(dst, g->len, h);
    if (memcmp(h, g->sha256, 32)) { memset(dst, 0, g->len); return PKG_ERR_HASH; }
    return PKG_OK;
}

int pkg_check_base(const pkg *p, const uint8_t id[32])
{
    return p->kind == PKG_KIND_OVERLAY && !memcmp(p->base_id, id, 32) ? PKG_OK : PKG_ERR_BASE;
}

const char *pkg_strerror(int rc)
{
    switch (rc) {
    case PKG_OK: return "ok";
    case PKG_ERR_READ: return T(TXT_READ_ERROR);
    case PKG_ERR_MAGIC: return T(TXT_NOT_A_PACKAGE);
    case PKG_ERR_VERSION: return T(TXT_UNKNOWN_PACKAGE_VERSION);
    case PKG_ERR_KIND: return T(TXT_WRONG_KIND_OF_PACKAGE);
    case PKG_ERR_HEADER: return T(TXT_BAD_PACKAGE_HEADER);
    case PKG_ERR_PIN: return T(TXT_THE_SIGNATURE_OF_THE_PACKAGE_IS_NOT_VALID);
    case PKG_ERR_TABLE: return T(TXT_BAD_PACKAGE_TABLE);
    case PKG_ERR_NOGROUP: return T(TXT_NO_SUCH_GROUP);
    case PKG_ERR_HASH: return T(TXT_A_GROUP_HAS_A_WRONG_HASH);
    case PKG_ERR_SIZE: return T(TXT_PACKAGE_TOO_SHORT_OR_BUFFER);
    case PKG_ERR_BASE: return T(TXT_THE_PACKAGE_BELONGS_TO_ANOTHER);
    default: return "error";
    }
}
