#include "sign/nostr.h"
#include <stdio.h>
#include <string.h>
#include "ec/secp256k1.h"
#include "hash/sha256.h"
#include "sign/nip19.h"
#include "sign/nip44.h"
#include "util.h"
#include "tr.h"

typedef struct { const char *p, *end; } jr;

typedef struct {
    char *buf; size_t cap, n; int err;
} sb;

static void sb_put(sb *s, const char *d, size_t n)
{
    if (s->n + n >= s->cap) { s->err = 1; return; }
    memmove(s->buf + s->n, d, n);
    s->n += n;
    s->buf[s->n] = 0;
}

static void sb_ch(sb *s, char c) { sb_put(s, &c, 1); }

/* the 35 bytes of NIP-44 in front of the text (version, nonce, length): the message is built in place over the content */
static const char GAP[35];

static void ws(jr *j) { while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++; }

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static void put_utf8(sb *s, uint32_t cp)
{
    char b[4];
    int n;
    if (cp < 0x80) { sb_ch(s, (char) cp); return; }
    if (cp < 0x800) { b[0] = (char) (0xC0 | (cp >> 6)); b[1] = (char) (0x80 | (cp & 63)); n = 2; }
    else if (cp < 0x10000) { b[0] = (char) (0xE0 | (cp >> 12)); b[1] = (char) (0x80 | ((cp >> 6) & 63)); b[2] = (char) (0x80 | (cp & 63)); n = 3; }
    else { b[0] = (char) (0xF0 | (cp >> 18)); b[1] = (char) (0x80 | ((cp >> 12) & 63)); b[2] = (char) (0x80 | ((cp >> 6) & 63)); b[3] = (char) (0x80 | (cp & 63)); n = 4; }
    sb_put(s, b, (size_t) n);
}

/* one decoded character in the canonical NIP-01 form: only quote, backslash, \n \r \t \b \f are escaped */
static void put_canon(sb *s, uint32_t cp)
{
    switch (cp) {
    case '"': sb_put(s, "\\\"", 2); break;
    case '\\': sb_put(s, "\\\\", 2); break;
    case '\n': sb_put(s, "\\n", 2); break;
    case '\r': sb_put(s, "\\r", 2); break;
    case '\t': sb_put(s, "\\t", 2); break;
    case '\b': sb_put(s, "\\b", 2); break;
    case '\f': sb_put(s, "\\f", 2); break;
    default: put_utf8(s, cp);
    }
}

static int hex4(jr *j, uint32_t *v)
{
    uint32_t x = 0;
    if (j->end - j->p < 4) return -1;
    for (int i = 0; i < 4; i++) { int h = hexv(j->p[i]); if (h < 0) return -1; x = x * 16 + (uint32_t) h; }
    j->p += 4;
    *v = x;
    return 0;
}

/* a quoted string with its escapes decoded, then written canonically */
static int string_decode(jr *j, sb *s)
{
    while (j->p < j->end) {
        unsigned char c = (unsigned char) *j->p++;
        if (c == '"') return 0;
        if (c == '\\') {
            uint32_t cp;
            if (j->p >= j->end) return -1;
            c = (unsigned char) *j->p++;
            switch (c) {
            case 'n': put_canon(s, '\n'); break;
            case 'r': put_canon(s, '\r'); break;
            case 't': put_canon(s, '\t'); break;
            case 'b': put_canon(s, '\b'); break;
            case 'f': put_canon(s, '\f'); break;
            case '"': put_canon(s, '"'); break;
            case '\\': put_canon(s, '\\'); break;
            case '/': put_canon(s, '/'); break;
            case 'u':
                if (hex4(j, &cp)) return -1;
                if (cp >= 0xD800 && cp < 0xDC00) {                      /* a surrogate pair */
                    uint32_t lo;
                    if (j->end - j->p < 2 || j->p[0] != '\\' || j->p[1] != 'u') return -1;
                    j->p += 2;
                    if (hex4(j, &lo) || lo < 0xDC00 || lo > 0xDFFF) return -1;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp < 0xE000) return -1;
                put_canon(s, cp);
                break;
            default: return -1;
            }
        } else if (c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\b' && c != '\f') {
            sb_ch(s, (char) c);                                           /* other control characters stay raw */
        } else if (c >= 0x80) {
            sb_ch(s, (char) c);                                           /* the bytes of a UTF-8 character stay as they are */
        } else {
            put_canon(s, c);
        }
    }
    return -1;
}

static int skip_value(jr *j)
{
    int depth = 0;
    ws(j);
    if (j->p >= j->end) return -1;
    if (*j->p == '"') {
        j->p++;
        while (j->p < j->end) { char c = *j->p++; if (c == '\\') j->p++; else if (c == '"') return 0; }
        return -1;
    }
    if (*j->p != '[' && *j->p != '{') {
        while (j->p < j->end && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
        return 0;
    }
    while (j->p < j->end) {
        char c = *j->p++;
        if (c == '"') { j->p--; if (skip_value(j)) return -1; }
        else if (c == '[' || c == '{') depth++;
        else if (c == ']' || c == '}') { if (--depth == 0) return 0; }
    }
    return -1;
}

/* a JSON value made of arrays, strings, numbers and literals, copied in the canonical form */
static int copy_value(jr *j, sb *s, int depth)
{
    ws(j);
    if (j->p >= j->end || depth > 4) return -1;
    if (*j->p == '[') {
        j->p++;
        sb_ch(s, '[');
        ws(j);
        if (j->p < j->end && *j->p == ']') { j->p++; sb_ch(s, ']'); return 0; }
        for (;;) {
            if (copy_value(j, s, depth + 1)) return -1;
            ws(j);
            if (j->p >= j->end) return -1;
            if (*j->p == ',') { j->p++; sb_ch(s, ','); continue; }
            if (*j->p == ']') { j->p++; sb_ch(s, ']'); return 0; }
            return -1;
        }
    }
    if (*j->p == '"') {
        j->p++;
        sb_ch(s, '"');
        if (string_decode(j, s)) return -1;
        sb_ch(s, '"');
        return 0;
    }
    if ((*j->p >= '0' && *j->p <= '9') || *j->p == '-') {
        while (j->p < j->end && ((*j->p >= '0' && *j->p <= '9') || *j->p == '-' || *j->p == '.' || *j->p == 'e' || *j->p == 'E' || *j->p == '+')) sb_ch(s, *j->p++);
        return 0;
    }
    if (j->end - j->p >= 4 && !memcmp(j->p, "true", 4)) { sb_put(s, "true", 4); j->p += 4; return 0; }
    if (j->end - j->p >= 5 && !memcmp(j->p, "false", 5)) { sb_put(s, "false", 5); j->p += 5; return 0; }
    if (j->end - j->p >= 4 && !memcmp(j->p, "null", 4)) { sb_put(s, "null", 4); j->p += 4; return 0; }
    return -1;
}

typedef struct {
    uint64_t kind, created;
    int      have_kind, have_created;
    size_t   tags_off, tags_len, content_off, content_len;     /* inside the scratch buffer */
    int      enc;                                              /* "encrypt": 0 no, 4 NIP-04, 44 NIP-44 (the content is the plain text, the signer encrypts it) */
    uint8_t  recip[32];                                        /* "recipient": npub, nprofile or hex; without it the first "p" tag */
    int      have_recip;
} nostr_ev;

static int hex_n(uint8_t *out, const char *s, size_t n)         /* n hex digits to n / 2 bytes */
{
    for (size_t i = 0; i < n; i += 2) {
        int a = hexv(s[i]), b = hexv(s[i + 1]);
        if (a < 0 || b < 0) return -1;
        out[i / 2] = (uint8_t) (a << 4 | b);
    }
    return 0;
}

/* a public key as people write it: 64 hex digits, an npub or an nprofile */
static int pubkey_of(uint8_t out[32], const char *s)
{
    nip19 n;
    int t;
    if (strlen(s) == 64) return hex_n(out, s, 64);
    t = nip19_decode(&n, s);
    if (t != N19_NPUB && t != N19_NPROFILE) return -1;
    memcpy(out, n.id, 32);
    return 0;
}

/* the value (64 hex digits) of the first tag named `name` (a letter) in the canonical tags: ["p","<hex>" ... ; inside a string a quote is always escaped, so this cannot match text */
static int tag_hex(uint8_t out[32], const char *tags, size_t len, char name)
{
    for (size_t i = 0; i + 6 + 64 + 1 <= len; i++)
        if (tags[i] == '[' && tags[i + 1] == '"' && tags[i + 2] == name && tags[i + 3] == '"' && tags[i + 4] == ',' && tags[i + 5] == '"' && tags[i + 6 + 64] == '"' && !hex_n(out, tags + i + 6, 64)) return 0;
    return -1;
}

/* the canonical text of a content back to bytes (\" \\ \n \r \t \b \f) */
static size_t unesc(uint8_t *o, const char *in, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c == '\\' && i + 1 < n) {
            c = in[++i];
            c = c == 'n' ? '\n' : c == 'r' ? '\r' : c == 't' ? '\t' : c == 'b' ? '\b' : c == 'f' ? '\f' : c;
        }
        o[k++] = (uint8_t) c;
    }
    return k;
}

static size_t unesc_len(const char *in, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++, k++) if (in[i] == '\\' && i + 1 < n) i++;
    return k;
}

static int ev_parse(nostr_ev *e, const char *json, size_t len, sb *s)
{
    jr j = {json, json + len};
    char key[24];

    memset(e, 0, sizeof *e);
    ws(&j);
    if (j.p >= j.end || *j.p++ != '{') return NOSTR_ERR_PARSE;
    ws(&j);
    if (j.p < j.end && *j.p == '}') return NOSTR_ERR_PARSE;
    for (;;) {
        sb k = {key, sizeof key, 0, 0};
        ws(&j);
        if (j.p >= j.end || *j.p++ != '"' || string_decode(&j, &k) || k.err) return NOSTR_ERR_PARSE;
        ws(&j);
        if (j.p >= j.end || *j.p++ != ':') return NOSTR_ERR_PARSE;
        ws(&j);
        if (!strcmp(key, "kind") || !strcmp(key, "created_at")) {
            uint64_t v = 0;
            int nd = 0;
            while (j.p < j.end && *j.p >= '0' && *j.p <= '9' && nd < 19) { v = v * 10 + (uint64_t) (*j.p++ - '0'); nd++; }
            if (!nd) return NOSTR_ERR_PARSE;
            if (!strcmp(key, "kind")) { e->kind = v; e->have_kind = 1; } else { e->created = v; e->have_created = 1; }
        } else if (!strcmp(key, "tags")) {
            e->tags_off = s->n;
            if (copy_value(&j, s, 0) || s->err) return s->err ? NOSTR_ERR_SPACE : NOSTR_ERR_PARSE;
            e->tags_len = s->n - e->tags_off;
        } else if (!strcmp(key, "content")) {
            if (j.p >= j.end || *j.p++ != '"') return NOSTR_ERR_PARSE;
            sb_put(s, GAP, sizeof GAP);
            e->content_off = s->n;
            if (string_decode(&j, s) || s->err) return s->err ? NOSTR_ERR_SPACE : NOSTR_ERR_PARSE;
            e->content_len = s->n - e->content_off;
        } else if (!strcmp(key, "encrypt") || !strcmp(key, "recipient")) {
            char val[320];
            sb vs = {val, sizeof val, 0, 0};
            if (j.p >= j.end || *j.p++ != '"' || string_decode(&j, &vs) || vs.err) return NOSTR_ERR_PARSE;
            if (key[0] == 'e') {
                if (!strcmp(val, "nip44")) e->enc = 44;
                else if (!strcmp(val, "nip04")) e->enc = 4;
                else return NOSTR_ERR_PARSE;
            } else {
                if (pubkey_of(e->recip, val)) return NOSTR_ERR_PARSE;
                e->have_recip = 1;
            }
        } else if (skip_value(&j)) return NOSTR_ERR_PARSE;
        ws(&j);
        if (j.p >= j.end) return NOSTR_ERR_PARSE;
        if (*j.p == ',') { j.p++; continue; }
        if (*j.p == '}') break;
        return NOSTR_ERR_PARSE;
    }
    if (!e->have_kind || !e->have_created) return NOSTR_ERR_PARSE;
    if (!e->tags_len) {                                                     /* no tags: an empty list */
        e->tags_off = s->n;
        sb_put(s, "[]", 2);
        e->tags_len = 2;
    }
    if (e->enc && !e->have_recip) {                                         /* encrypted to the first "p" tag unless a recipient is named */
        if (tag_hex(e->recip, s->buf + e->tags_off, e->tags_len, 'p')) return NOSTR_ERR_PARSE;
        e->have_recip = 1;
    }
    return s->err ? NOSTR_ERR_SPACE : NOSTR_OK;
}

static const char HX[] = "0123456789abcdef";
static void hexs(char *out, const uint8_t *d, size_t n) { for (size_t i = 0; i < n; i++) { out[2 * i] = HX[d[i] >> 4]; out[2 * i + 1] = HX[d[i] & 15]; } out[2 * n] = 0; }

/* a note with the NIP-19 form (npub, note) of the first tag of that name */
static void note_key(tx_view *v, uint16_t text, const char *hrp, const char *tags, size_t tlen, char name)
{
    uint8_t k[32];
    char b[80], line[96];
    if (tag_hex(k, tags, tlen, name) || nip19_encode32(b, sizeof b, hrp, k) < 0) return;
    snprintf(line, sizeof line, T(text), b);
    txv_note(v, line);
}

/* the "nostr:" references of a text (NIP-21) that are not valid NIP-19 strings: a bad checksum means the reference is not what it looks like */
static void note_refs(tx_view *v, const char *c, size_t n)
{
    char tok[404], line[96];
    nip19 tmp;
    int total = 0, bad = 0;

    for (size_t i = 0; i + 6 <= n; i++) {
        size_t a, b;
        if (memcmp(c + i, "nostr:", 6)) continue;
        a = b = i + 6;
        while (b < n && ((c[b] >= '0' && c[b] <= '9') || (c[b] >= 'a' && c[b] <= 'z') || (c[b] >= 'A' && c[b] <= 'Z'))) b++;
        if (b == a) continue;                                              /* "nostr:" and nothing after it: no reference */
        total++;
        if (b - a >= sizeof tok) bad++;
        else { memcpy(tok, c + a, b - a); tok[b - a] = 0; if (nip19_decode(&tmp, tok) < 0) bad++; }
        i = b - 1;
    }
    if (!total) return;
    snprintf(line, sizeof line, T(TXT_NOSTR_REFERENCES_N_N_NOT_VALID), total, bad);
    txv_note(v, line);
}

int nostr_summary(const char *json, size_t len, tx_view *v)
{
    char local[3072], *scratch = local;
    size_t scap = sizeof local;
    sb s;
    nostr_ev e;
    int r;
    char line[96];
    int ntags = 0, depth = 0;

    if (txv_work && txv_work_cap > scap) { scratch = (char *) txv_work; scap = txv_work_cap; }          /* the signer's work area: a request is up to one card block */
    s = (sb) {scratch, scap, 0, 0};
    r = ev_parse(&e, json, len, &s);
    txv_clear(v);
    if (r) return r;
    if (e.enc && unesc_len(scratch + e.content_off, e.content_len) > NIP_PT_MAX) return NOSTR_ERR_SIZE;      /* too long to encrypt here: say so before anything is signed */
    switch (e.kind) {
    case 0: strcpy(v->title, T(TXT_NOSTR_PROFILE_KIND_0)); break;
    case 1: strcpy(v->title, T(TXT_NOSTR_NOTE_KIND_1)); break;
    case 3: strcpy(v->title, T(TXT_NOSTR_CONTACT_LIST_KIND_3)); break;
    case 4: strcpy(v->title, T(TXT_NOSTR_DIRECT_MESSAGE_KIND_4)); break;
    case 5: strcpy(v->title, T(TXT_NOSTR_DELETION_KIND_5)); break;
    case 6: strcpy(v->title, T(TXT_NOSTR_REPOST_KIND_6)); break;
    case 7: strcpy(v->title, T(TXT_NOSTR_REACTION_KIND_7)); break;
    case 22242: strcpy(v->title, T(TXT_NOSTR_RELAY_LOGIN_KIND_22242)); break;
    default: snprintf(v->title, sizeof v->title, T(TXT_NOSTR_EVENT_KIND_N), (unsigned long long) e.kind);
    }
    for (size_t i = 0; i < e.tags_len; i++) {                          /* the tags: how many lists on the first level */
        char c = scratch[e.tags_off + i];
        if (c == '"') { i++; while (i < e.tags_len && scratch[e.tags_off + i] != '"') { if (scratch[e.tags_off + i] == '\\') i++; i++; } }
        else if (c == '[') { depth++; if (depth == 2) ntags++; }
        else if (c == ']') depth--;
    }
    v->nout = 1;
    {
        size_t n = e.content_len < sizeof v->out[0].to - 1 ? e.content_len : sizeof v->out[0].to - 1;
        memcpy(v->out[0].to, scratch + e.content_off, n);
        v->out[0].to[n] = 0;
    }
    {
        char a[24], b[64];
        snprintf(a, sizeof a, TN(ntags, TXT_COUNT_TAG_ONE, TXT_COUNT_TAG_MANY), ntags);
        snprintf(b, sizeof b, T(TXT_CREATED_AT_CONTENT_BYTES), (unsigned long long) e.created, (unsigned) e.content_len);
        snprintf(line, sizeof line, "%s, %s", a, b);
    }
    txv_note(v, line);
    if (e.enc) {                                                           /* the content is plain text that the signer encrypts: say to whom */
        char b[80];
        if (nip19_encode32(b, sizeof b, "npub", e.recip) < 0) return NOSTR_ERR_PARSE;
        snprintf(line, sizeof line, T(TXT_NOSTR_ENCRYPTED_WITH_NIP_N_FOR_S), e.enc, b);
        txv_note(v, line);
    } else {
        if (e.kind == 4) txv_note(v, T(TXT_THE_CONTENT_IS_ENCRYPTED_ONLY));
        note_key(v, TXT_NOSTR_TO_S, "npub", scratch + e.tags_off, e.tags_len, 'p');
    }
    note_key(v, TXT_NOSTR_EVENT_S, "note", scratch + e.tags_off, e.tags_len, 'e');
    note_refs(v, scratch + e.content_off, e.content_len);
    if (unesc_len(scratch + e.content_off, e.content_len) > sizeof v->out[0].to - 1) {          /* a long text gets pages of its own: all of it can be read before it is signed */
        size_t tl = unesc((uint8_t *) scratch + e.content_off, scratch + e.content_off, e.content_len);
        if (!txv_set_text(v, (const uint8_t *) scratch + e.content_off, tl)) txv_note(v, T(TXT_NOSTR_LONG_TEXT_READ_EVERY_PAGE));
    }
    return NOSTR_OK;
}

/* "encrypt": the content (plain text) is replaced by its NIP-44 or NIP-04 message to the recipient. There is no random source in a request, so the nonce (IV) is an HMAC of the
 * conversation key over the time and the text: a different message never repeats a nonce, the same one gives the same message.
 * The text is decoded in place, the NIP-44 message is built over it (the 35 bytes before the content are free for its header); the base64 message goes to the END of the output buffer,
 * where the event is assembled in front of it, so no second buffer is needed. */
static int encrypt_content(nostr_ev *e, sb *s, const uint8_t priv[32], char *out, size_t cap, const char **cp, size_t *cl)
{
    uint8_t key[32], nonce[32], *pt, *work;
    char *msg;
    size_t ptlen, need = NIP_PT_MAX + 64;
    int n;

    if (cap < NIP_B64_MAX + 1 + 600) return NOSTR_ERR_SPACE;
    msg = out + cap - (NIP_B64_MAX + 1);
    if (e->tags_off > e->content_off) {                                      /* tags after the content in the request: out of the way of the message that grows over it */
        if (e->content_off + need + e->tags_len + 1 > s->cap) return NOSTR_ERR_SPACE;
        memmove(s->buf + e->content_off + need, s->buf + e->tags_off, e->tags_len + 1);
        e->tags_off = e->content_off + need;
    } else if (e->content_off + need > s->cap) return NOSTR_ERR_SPACE;
    pt = (uint8_t *) s->buf + e->content_off;
    ptlen = unesc(pt, s->buf + e->content_off, e->content_len);
    if (!ptlen) return NOSTR_ERR_PARSE;
    if (ptlen > NIP_PT_MAX) return NOSTR_ERR_SIZE;
    if (e->enc == 44 ? nip44_conv_key(key, priv, e->recip) : nip04_key(key, priv, e->recip)) return NOSTR_ERR_KEY;
    for (int i = 0; i < 8; i++) msg[i] = (char) (e->created >> (56 - 8 * i));         /* the time, then the text: the input of the nonce */
    memcpy(msg + 8, pt, ptlen);
    hmac_sha256(key, 32, (const uint8_t *) msg, 8 + ptlen, nonce);
    work = e->enc == 44 ? pt - sizeof GAP : pt;
    if (e->enc == 44) n = nip44_encrypt(msg, NIP_B64_MAX + 1, work, key, nonce, pt, ptlen);
    else n = nip04_encrypt(msg, NIP_B64_MAX + 1, work, key, nonce, pt, ptlen);
    secure_zero(key, sizeof key);
    secure_zero(work, need + (e->enc == 44 ? sizeof GAP : 0));
    if (n >= 0 && (size_t) n + 1 < 8 + ptlen) secure_zero(msg + n + 1, 8 + ptlen - (size_t) n - 1);     /* what is left of the plain text copy */
    if (n < 0) return n == NIP_ERR_SIZE ? NOSTR_ERR_SIZE : NOSTR_ERR_SPACE;
    if (400 + e->tags_len > (size_t) (msg - out)) return NOSTR_ERR_SPACE;           /* the start of the event must not reach the message */
    *cp = msg;
    *cl = (size_t) n;
    return NOSTR_OK;
}

int nostr_sign(const char *json, size_t len, const uint8_t priv[32], char *scratch, size_t scap, char *out, size_t cap, size_t *outlen)
{
    sb s = {scratch, scap, 0, 0};
    nostr_ev e;
    int r = ev_parse(&e, json, len, &s);
    uint8_t xo[32], id[32], sig[64];
    char pk[65], idh[65], sgh[129], num[48];
    sha256_ctx c;
    sb o = {out, cap, 0, 0};
    const char *cp;
    size_t cl;

    if (r) return r;
    cp = scratch + e.content_off;
    cl = e.content_len;
    if (e.enc && (r = encrypt_content(&e, &s, priv, out, cap, &cp, &cl))) return r;
    if (secp256k1_xonly_pubkey(xo, NULL, priv)) return NOSTR_ERR_KEY;
    hexs(pk, xo, 32);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *) "[0,\"", 4);
    sha256_update(&c, (const uint8_t *) pk, 64);
    snprintf(num, sizeof num, "\",%llu,%llu,", (unsigned long long) e.created, (unsigned long long) e.kind);
    sha256_update(&c, (const uint8_t *) num, strlen(num));
    sha256_update(&c, (const uint8_t *) scratch + e.tags_off, e.tags_len);
    sha256_update(&c, (const uint8_t *) ",\"", 2);
    sha256_update(&c, (const uint8_t *) cp, cl);
    sha256_update(&c, (const uint8_t *) "\"]", 2);
    sha256_final(&c, id);
    if (secp256k1_schnorr_sign(sig, priv, id, NULL)) return NOSTR_ERR_KEY;
    hexs(idh, id, 32);
    hexs(sgh, sig, 64);
    sb_put(&o, "{\"id\":\"", 7); sb_put(&o, idh, 64);
    sb_put(&o, "\",\"pubkey\":\"", 12); sb_put(&o, pk, 64);
    snprintf(num, sizeof num, "\",\"created_at\":%llu,\"kind\":%llu,\"tags\":", (unsigned long long) e.created, (unsigned long long) e.kind);
    sb_put(&o, num, strlen(num));
    sb_put(&o, scratch + e.tags_off, e.tags_len);
    sb_put(&o, ",\"content\":\"", 12);
    sb_put(&o, cp, cl);
    sb_put(&o, "\",\"sig\":\"", 9); sb_put(&o, sgh, 128);
    sb_put(&o, "\"}", 2);
    if (o.err) return NOSTR_ERR_SPACE;
    *outlen = o.n;
    return NOSTR_OK;
}

/* ---- decrypting a message (a request of kind "message" for the chain nostr): {"content":"<NIP-44 or NIP-04 text>","pubkey":"<the other side>"}, optionally "with" (the other side when the
 * event is our own: the recipient) and "decrypt":"nip44" | "nip04" (otherwise the "?iv=" of NIP-04 tells). A whole event can be pasted: its other fields are ignored. ---- */

typedef struct {
    int     mode;                                              /* 4 or 44 */
    uint8_t peer[32];
    size_t  coff, clen;
} dec_req;

static int dec_parse(dec_req *d, const char *json, size_t len, sb *s)
{
    jr j = {json, json + len};
    char key[24];
    int have_pk = 0, have_with = 0, mode = 0;
    uint8_t pk[32], with[32];

    memset(d, 0, sizeof *d);
    ws(&j);
    if (j.p >= j.end || *j.p++ != '{') return NOSTR_ERR_PARSE;
    for (;;) {
        sb k = {key, sizeof key, 0, 0};
        ws(&j);
        if (j.p >= j.end || *j.p++ != '"' || string_decode(&j, &k) || k.err) return NOSTR_ERR_PARSE;
        ws(&j);
        if (j.p >= j.end || *j.p++ != ':') return NOSTR_ERR_PARSE;
        ws(&j);
        if (!strcmp(key, "content") || !strcmp(key, "pubkey") || !strcmp(key, "with") || !strcmp(key, "decrypt")) {
            char val[320];
            sb vs = {val, sizeof val, 0, 0};
            if (j.p >= j.end || *j.p++ != '"') return NOSTR_ERR_PARSE;
            if (key[0] == 'c') {
                d->coff = s->n;
                if (string_decode(&j, s) || s->err) return s->err ? NOSTR_ERR_SPACE : NOSTR_ERR_PARSE;
                d->clen = s->n - d->coff;
                sb_ch(s, 0);
                if (s->err) return NOSTR_ERR_SPACE;
            } else {
                if (string_decode(&j, &vs) || vs.err) return NOSTR_ERR_PARSE;
                if (key[0] == 'p') { if (pubkey_of(pk, val)) return NOSTR_ERR_PARSE; have_pk = 1; }
                else if (key[0] == 'w') { if (pubkey_of(with, val)) return NOSTR_ERR_PARSE; have_with = 1; }
                else mode = !strcmp(val, "nip44") ? 44 : !strcmp(val, "nip04") ? 4 : -1;
            }
        } else if (skip_value(&j)) return NOSTR_ERR_PARSE;
        ws(&j);
        if (j.p >= j.end) return NOSTR_ERR_PARSE;
        if (*j.p == ',') { j.p++; continue; }
        if (*j.p == '}') break;
        return NOSTR_ERR_PARSE;
    }
    if (!d->clen || mode < 0 || (!have_pk && !have_with)) return NOSTR_ERR_PARSE;
    memcpy(d->peer, have_with ? with : pk, 32);
    d->mode = mode ? mode : strstr(s->buf + d->coff, "?iv=") ? 4 : 44;
    return NOSTR_OK;
}

/* the message is decoded and decrypted in place over its own text in the scratch; the plain text stays there. Returns its length or a NOSTR_ERR_ code. */
static int do_decrypt(dec_req *d, const char *json, size_t len, const uint8_t priv[32], char *scratch, size_t scap, const uint8_t **pt)
{
    sb s = {scratch, scap, 0, 0};
    uint8_t key[32];
    int r = dec_parse(d, json, len, &s);

    if (r) return r;
    if (d->mode == 44) {
        if (nip44_conv_key(key, priv, d->peer)) return NOSTR_ERR_KEY;
        r = nip44_decrypt(pt, (uint8_t *) scratch + d->coff, key, scratch + d->coff);
    } else {
        if (nip04_key(key, priv, d->peer)) return NOSTR_ERR_KEY;
        r = nip04_decrypt(pt, (uint8_t *) scratch + d->coff, key, scratch + d->coff);
    }
    secure_zero(key, sizeof key);
    return r >= 0 ? r : r == NIP_ERR_MAC ? NOSTR_ERR_KEY : r == NIP_ERR_SIZE ? NOSTR_ERR_SIZE : NOSTR_ERR_PARSE;
}

int nostr_decrypt_summary(const char *json, size_t len, const uint8_t priv[32], tx_view *v)
{
    char local[3072], *scratch = local, line[96], b[80];
    size_t scap = sizeof local;
    const uint8_t *pt;
    dec_req d;
    int n;

    if (txv_work && txv_work_cap > scap) { scratch = (char *) txv_work; scap = txv_work_cap; }
    n = do_decrypt(&d, json, len, priv, scratch, scap, &pt);
    txv_clear(v);
    if (n < 0) return n;
    snprintf(v->title, sizeof v->title, T(TXT_NOSTR_DECRYPTED_MESSAGE_NIP_N), d.mode);
    if (nip19_encode32(b, sizeof b, "npub", d.peer) > 0) { snprintf(line, sizeof line, T(TXT_NOSTR_WITH_S), b); txv_note(v, line); }
    snprintf(line, sizeof line, T(TXT_NOSTR_MESSAGE_BYTES_N), n);
    txv_note(v, line);
    n = txv_set_text(v, pt, (size_t) n) ? NOSTR_ERR_SPACE : NOSTR_OK;          /* the whole text, on pages of its own */
    secure_zero(scratch, scap);
    return n;
}

int nostr_decrypt(const char *json, size_t len, const uint8_t priv[32], char *scratch, size_t scap, char *out, size_t cap, size_t *outlen)
{
    const uint8_t *pt;
    dec_req d;
    int n = do_decrypt(&d, json, len, priv, scratch, scap, &pt);

    if (n < 0) return n;
    if ((size_t) n + 1 > cap) return NOSTR_ERR_SPACE;
    memcpy(out, pt, (size_t) n);
    out[n] = 0;
    *outlen = (size_t) n;
    secure_zero(scratch, scap);
    return NOSTR_OK;
}
