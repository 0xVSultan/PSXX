#include "sign/nip44.h"
#include <string.h>
#include "aes.h"
#include "b64.h"
#include "ec/secp_pub.h"
#include "hash/chacha20poly1305.h"
#include "hash/sha256.h"
#include "util.h"

int nip04_key(uint8_t key[32], const uint8_t priv[32], const uint8_t pub[32]) { return secp256k1_ecdh_x(key, priv, pub) ? NIP_ERR_KEY : NIP_OK; }

int nip44_conv_key(uint8_t ck[32], const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t x[32];
    if (secp256k1_ecdh_x(x, priv, pub)) return NIP_ERR_KEY;
    hmac_sha256((const uint8_t *) "nip44-v2", 8, x, 32, ck);                 /* HKDF-extract with the salt as the HMAC key */
    secure_zero(x, sizeof x);
    return NIP_OK;
}

/* the padded length of NIP-44 (a text of 1 .. 65535 bytes) */
static size_t padded_len(size_t n)
{
    size_t next = 32, chunk;
    if (n <= 32) return 32;
    while (next < n) next <<= 1;                                              /* the next power of two >= n (n - 1 and the power of the spec are the same for n > 32) */
    chunk = next <= 256 ? 32 : next / 8;
    return chunk * ((n - 1) / chunk + 1);
}

/* HKDF-expand of 76 bytes: T(i) = HMAC(prk, T(i-1) || info || i) */
static void msg_keys(uint8_t okm[96], const uint8_t ck[32], const uint8_t nonce[32])
{
    uint8_t buf[32 + 32 + 1];
    for (int i = 0; i < 3; i++) {
        size_t n = 0;
        if (i) { memcpy(buf, okm + 32 * (i - 1), 32); n = 32; }
        memcpy(buf + n, nonce, 32); n += 32;
        buf[n++] = (uint8_t) (i + 1);
        hmac_sha256(ck, 32, buf, n, okm + 32 * i);
    }
}

int nip44_encrypt(char *out, size_t cap, uint8_t *work, const uint8_t ck[32], const uint8_t nonce[32], const uint8_t *pt, size_t len)
{
    uint8_t okm[96], mac[32];
    size_t pl, ctlen, total;
    int r;

    if (!len || len > NIP_PT_MAX) return NIP_ERR_SIZE;
    pl = padded_len(len);
    ctlen = 2 + pl;
    total = 1 + 32 + ctlen + 32;
    work[0] = 2;
    memcpy(work + 1, nonce, 32);
    work[33] = (uint8_t) (len >> 8);
    work[34] = (uint8_t) len;
    if (pt != work + 35) memmove(work + 35, pt, len);
    memset(work + 35 + len, 0, pl - len);
    msg_keys(okm, ck, nonce);
    chacha20_xor(work + 33, work + 33, ctlen, okm, 0, okm + 32);
    hmac_sha256(okm + 44, 32, work + 1, 32 + ctlen, mac);                    /* the nonce is the associated data: nonce || ciphertext */
    memcpy(work + 33 + ctlen, mac, 32);
    secure_zero(okm, sizeof okm);
    r = b64_encode(work, total, out, cap);
    return r < 0 ? NIP_ERR_SIZE : r;
}

int nip44_decrypt(const uint8_t **pt, uint8_t *work, const uint8_t ck[32], const char *payload)
{
    uint8_t okm[96], mac[32];
    size_t slen = strlen(payload), ctlen, ulen, d = 0;
    int n;

    if (slen > NIP_B64_MAX) return NIP_ERR_SIZE;
    if (slen < 132 || payload[0] == '#') return NIP_ERR_FORMAT;
    n = b64_decode(payload, work, NIP44_WORK);
    if (n < 99 || work[0] != 2) return NIP_ERR_FORMAT;
    ctlen = (size_t) n - 1 - 32 - 32;
    msg_keys(okm, ck, work + 1);
    hmac_sha256(okm + 44, 32, work + 1, 32 + ctlen, mac);
    for (int i = 0; i < 32; i++) d |= (size_t) (mac[i] ^ work[33 + ctlen + (size_t) i]);
    if (d) { secure_zero(okm, sizeof okm); return NIP_ERR_MAC; }
    chacha20_xor(work + 33, work + 33, ctlen, okm, 0, okm + 32);
    secure_zero(okm, sizeof okm);
    ulen = (size_t) work[33] << 8 | work[34];
    if (!ulen || ulen > ctlen - 2 || ctlen != 2 + padded_len(ulen)) return NIP_ERR_FORMAT;
    *pt = work + 35;
    return (int) ulen;
}

int nip04_encrypt(char *out, size_t cap, uint8_t *work, const uint8_t key[32], const uint8_t iv[16], const uint8_t *pt, size_t len)
{
    aes_ctx c;
    size_t pl = (len / 16 + 1) * 16;
    int a, b;

    if (!len || len > NIP_PT_MAX) return NIP_ERR_SIZE;
    if (pt != work) memmove(work, pt, len);
    memset(work + len, (int) (pl - len), pl - len);                           /* PKCS#7 */
    aes_init(&c, key, 256);
    aes_cbc_encrypt(&c, iv, work, work, pl);
    aes_wipe(&c);
    a = b64_encode(work, pl, out, cap);
    if (a < 0 || (size_t) a + 4 + 24 + 1 > cap) return NIP_ERR_SIZE;
    memcpy(out + a, "?iv=", 4);
    b = b64_encode(iv, 16, out + a + 4, cap - (size_t) a - 4);
    return b < 0 ? NIP_ERR_SIZE : a + 4 + b;
}

int nip04_decrypt(const uint8_t **pt, uint8_t *work, const uint8_t key[32], char *payload)
{
    aes_ctx c;
    uint8_t iv[16];
    char *q = strstr(payload, "?iv=");
    int n, pad;

    if (!q) return NIP_ERR_FORMAT;
    if ((size_t) (q - payload) > NIP_B64_MAX) return NIP_ERR_SIZE;
    if (b64_decode(q + 4, iv, sizeof iv) != 16) return NIP_ERR_FORMAT;
    *q = 0;                                                                   /* the ciphertext ends at the "?iv="; decoded in place when work is the payload */
    n = b64_decode(payload, work, NIP04_WORK);
    *q = '?';
    if (n < 16 || n % 16) return NIP_ERR_FORMAT;
    aes_init(&c, key, 256);
    aes_cbc_decrypt(&c, iv, work, work, (size_t) n);
    aes_wipe(&c);
    pad = work[n - 1];
    if (pad < 1 || pad > 16 || pad > n) return NIP_ERR_FORMAT;
    for (int i = 0; i < pad; i++) if (work[n - 1 - i] != pad) return NIP_ERR_FORMAT;
    *pt = work;
    return n - pad;
}
