#include "blob.h"
#include <string.h>
#include "aes.h"
#include "util.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

void hkdf_sha256(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen, const uint8_t *info, size_t infolen,
                 uint8_t *out, size_t olen)
{
    static const uint8_t zeros[32];
    uint8_t prk[32], t[32] = {0}, buf[32 + 64 + 1];
    size_t tl = 0;

    if (infolen > 64) infolen = 64;
    if (slen == 0) { salt = zeros; slen = 32; }
    hmac_sha256(salt, slen, ikm, ilen, prk);
    for (uint8_t i = 1; olen; i++) {
        size_t n = olen < 32 ? olen : 32;
        memcpy(buf, t, tl);
        memcpy(buf + tl, info, infolen);
        buf[tl + infolen] = i;
        hmac_sha256(prk, 32, buf, tl + infolen + 1, t);
        tl = 32;
        memcpy(out, t, n);
        out += n;
        olen -= n;
    }
    secure_zero(prk, sizeof prk);
    secure_zero(t, sizeof t);
    secure_zero(buf, sizeof buf);
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) (v >> 24); p[1] = (uint8_t) (v >> 16); p[2] = (uint8_t) (v >> 8); p[3] = (uint8_t) v; }

static int derive(const uint8_t *pw, size_t pwlen, const uint8_t *extra, size_t extralen, uint32_t iter, const uint8_t salt[16],
                  uint8_t key[32])
{
    static const char INFO[] = "psx-blob-v1";
    uint8_t ikm[32 + 64];
    size_t n = 0;

    if (extralen != 0 && extralen != 32) return -1;
    if (iter == 0) return -1;
    if (extralen) { memcpy(ikm, extra, 32); n = 32; }
    pbkdf2_hmac_sha512(pw, pwlen, salt, 16, iter, ikm + n, 64);
    hkdf_sha256(salt, 16, ikm, n + 64, (const uint8_t *) INFO, sizeof INFO - 1, key, 32);
    secure_zero(ikm, sizeof ikm);
    return 0;
}

int blob_seal(const uint8_t *pw, size_t pwlen, const uint8_t *extra, size_t extralen, uint32_t iter, const uint8_t rnd[28],
              const uint8_t *pt, size_t ptlen, uint8_t *out, size_t outcap)
{
    uint8_t key[32];
    aes_ctx c;

    if (ptlen > 0xFFFF || outcap < ptlen + BLOB_OVERHEAD || derive(pw, pwlen, extra, extralen, iter, rnd, key)) return -1;
    memcpy(out, "PSXT", 4);
    out[4] = 1; out[5] = 1; out[6] = extralen ? BLOB_FLAG_EXTRA : 0; out[7] = 0;
    put32(out + 8, iter);
    memcpy(out + 12, rnd, 28);                          /* salt, nonce */
    out[40] = (uint8_t) (ptlen >> 8); out[41] = (uint8_t) ptlen;
    aes_init(&c, key, 256);
    aes_gcm_encrypt(&c, out + 28, out, BLOB_HDR, pt, ptlen, out + BLOB_HDR, out + BLOB_HDR + ptlen);
    aes_wipe(&c);
    secure_zero(key, sizeof key);
    return (int) (ptlen + BLOB_OVERHEAD);
}

uint32_t blob_iterations(const uint8_t *blob, size_t len)
{
    if (len < BLOB_OVERHEAD || memcmp(blob, "PSXT", 4)) return 0;
    return ((uint32_t) blob[8] << 24) | ((uint32_t) blob[9] << 16) | ((uint32_t) blob[10] << 8) | blob[11];
}

int blob_open(const uint8_t *pw, size_t pwlen, const uint8_t *extra, size_t extralen, const uint8_t *blob, size_t len,
              uint8_t *pt, size_t ptcap)
{
    uint8_t key[32];
    aes_ctx c;
    uint32_t iter;
    size_t clen;
    int r;

    if (len < BLOB_OVERHEAD || memcmp(blob, "PSXT", 4) || blob[4] != 1 || blob[5] != 1 || blob[7] != 0) return -1;
    if ((blob[6] & ~BLOB_FLAG_EXTRA) || ((blob[6] & BLOB_FLAG_EXTRA) != 0) != (extralen != 0)) return -1;
    clen = ((size_t) blob[40] << 8) | blob[41];
    if (len != clen + BLOB_OVERHEAD || ptcap < clen) return -1;
    iter = ((uint32_t) blob[8] << 24) | ((uint32_t) blob[9] << 16) | ((uint32_t) blob[10] << 8) | blob[11];
    if (iter > BLOB_ITER_MAX) return -1;
    if (derive(pw, pwlen, extra, extralen, iter, blob + 12, key)) return -1;
    aes_init(&c, key, 256);
    r = aes_gcm_decrypt(&c, blob + 28, blob, BLOB_HDR, blob + BLOB_HDR, clen, blob + BLOB_HDR + clen, pt);
    aes_wipe(&c);
    secure_zero(key, sizeof key);
    return r ? -2 : (int) clen;
}
