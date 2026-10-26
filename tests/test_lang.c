/* The language card: the package that tools/data_pack.py builds, read with the code of the console (core/pkg, core/lang, core/wordlist) and compared with what the tool
 * wrote from the sources (data_ref.txt): every word list decoded and hashed, the Chinese lists rebuilt from the mappings, the glyph sets in their canonical form, the index,
 * and the refusals (a wrong pin, a damaged group, buffers that are too small).
 * Usage: test_lang <data.pkg> <data_ref.txt> <data.json>   (the pin is in the json; without a package the test says so and passes: the package is made from the downloaded sources) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkg/pkg.h"
#include "pkg/ovl.h"
#include "lang/lang.h"
#include "lang/nfkd.h"
#include "lang/langin.h"
#include "coin/bip39.h"
#include "wordlist/wl.h"
#include "hash/sha256.h"

static uint8_t file_buf[1 << 18];
static size_t file_size;
static int flip_at = -1;                                 /* a damaged read: this offset of the file is inverted */

static int mem_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t len)
{
    (void) ctx;
    if ((size_t) off + len > file_size) return -1;
    memcpy(buf, file_buf + off, len);
    if (flip_at >= 0 && (uint32_t) flip_at >= off && (uint32_t) flip_at < off + len) buf[flip_at - (int) off] ^= 0x40;
    return 0;
}

static void hex_of(char *o, const uint8_t *d, int n) { for (int i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", d[i]); }

static int unhex(const char *s, uint8_t *o, int n)
{
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; o[i] = (uint8_t) v; }
    return 0;
}

static uint8_t stage[64 * 1024], rawbuf[200000], zbuf[16000], work[200000];
static uint16_t probs[OVL_PROBS];
static char wtext[40000], stext[8200], ttext[8200], mtext[8200], xtext[40000], mtext2[40000];
static uint16_t woff[2100], soff[2100], toff[2100], moff[2100], sel[2048], zwork[4096], hcps[4096], gcps[4096], xoff[2100], moff2[2100];

static void sha_text(const char *t, size_t n, char out[65])
{
    uint8_t h[32];
    sha256((const uint8_t *) t, n, h);
    hex_of(out, h, 32);
}

/* the list of a group id as the words of core/coin/words.h: a blob is decoded, the Chinese ones are the lists made above */
static const lang_info *find_lang(const lang_info *l, int n, unsigned id)
{
    for (int i = 0; i < n; i++) if (l[i].id == id) return &l[i];
    return NULL;
}

static int list_of(const pkg *pk, unsigned gid, int nmon_, words_list *wl)
{
    uint32_t br;
    int detail_, nw;

    if (gid == LANG_ID_ZH_SIMPLIFIED) { wl->text = stext; wl->off = soff; wl->n = 2048; return 0; }
    if (gid == LANG_ID_ZH_TRADITIONAL) { wl->text = ttext; wl->off = toff; wl->n = 2048; return 0; }
    if (gid == LANG_ID_ZH_XMR) { wl->text = mtext; wl->off = moff; wl->n = nmon_; return 0; }
    if ((gid >> 8) == 5) {                                                          /* the Monero list as a mask over the BIP39 list of the same language */
        uint32_t mr;
        int n;
        if (ovl_unpack_group(pk, (uint16_t) (LANG_ID_BIP39 + (gid & 255)), rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &br, &detail_)) return -1;
        nw = wl_decode(rawbuf, br, work, sizeof work, wtext, sizeof wtext, woff, 2100);
        if (nw <= 0) return -1;
        uint32_t ml = ((uint32_t) nw + 7) / 8, cl;
        static uint8_t mask[256];
        if (ovl_unpack_group(pk, (uint16_t) gid, zbuf, sizeof zbuf, stage, sizeof stage, probs, &mr, &detail_)) return -1;
        cl = mr >= 2 ? (uint32_t) (zbuf[0] | zbuf[1] << 8) : 0;                  /* u16 length, the coded mask */
        if (mr < 2 + cl || ml > sizeof mask) return -1;
        wl_mask_decode(zbuf + 2, cl, (unsigned) nw, mask);
        if (mr > 2 + cl) {                                                      /* then the words of its own: the two merged */
            int on = wl_decode(zbuf + 2 + cl, mr - 2 - cl, work, sizeof work, mtext2, sizeof mtext2, moff2, 2100);
            if (on <= 0) return -1;
            n = wl_merge(wtext, woff, nw, mask, ml, mtext2, moff2, on, xtext, sizeof xtext, xoff, 2100);
            if (n <= 0) return -1;
            wl->text = xtext; wl->off = xoff; wl->n = n;
            return 0;
        }
        if (lang_xmr_subset_size(woff, nw, mask, ml) == 0) return -1;
        n = lang_xmr_subset(wtext, woff, nw, mask, ml, xtext, sizeof xtext, xoff, 2100);
        if (n <= 0) return -1;
        wl->text = xtext; wl->off = xoff; wl->n = n;
        return 0;
    }
    if (ovl_unpack_group(pk, (uint16_t) gid, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &br, &detail_)) return -1;
    nw = wl_decode(rawbuf, br, work, sizeof work, wtext, sizeof wtext, woff, 2100);
    if (nw <= 0) return -1;
    wl->text = wtext; wl->off = woff; wl->n = nw;
    return 0;
}

int main(int argc, char **argv)
{
    FILE *f, *rf;
    static pkg p;
    uint8_t pin[32];
    char line[400];
    int bad = 0, total = 0, rc, detail, nmon, nlang;
    uint32_t raw;
    glyphset hanzi;
    lang_info langs[LANG_MAX];

#define CHECK(c, ...) do { total++; if (!(c)) { bad++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

    if (argc < 4 || !(f = fopen(argv[1], "rb"))) { printf("language card test: no package (tools/data_pack.py build), skipped\n"); return 0; }
    file_size = fread(file_buf, 1, sizeof file_buf, f);
    fclose(f);
    {
        char js[4000], *q;
        FILE *jf = fopen(argv[3], "r");
        size_t jn = jf ? fread(js, 1, sizeof js - 1, jf) : 0;
        if (jf) fclose(jf);
        js[jn] = 0;
        q = strstr(js, "\"key\": \"");
        if (!q || unhex(q + 8, pin, 32)) { printf("no key in %s\n", argv[3]); return 1; }
    }
    rc = pkg_open(&p, mem_read, NULL, (uint32_t) file_size, PKG_KIND_DATA, pin);
    CHECK(rc == 0, "pkg_open %d", rc);
    if (rc) return 1;
    {
        uint8_t wrong[32];
        static pkg q;
        memcpy(wrong, pin, 32); wrong[5] ^= 1;
        CHECK(pkg_open(&q, mem_read, NULL, (uint32_t) file_size, PKG_KIND_DATA, wrong) == PKG_ERR_PIN, "a wrong pin must be refused");
        CHECK(pkg_open(&q, mem_read, NULL, (uint32_t) file_size, PKG_KIND_OVERLAY, pin) == PKG_ERR_KIND, "a data package is not an overlay");
    }

    /* the hanzi set and the three Chinese lists */
    rc = ovl_unpack_group(&p, LANG_ID_HANZI, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &raw, &detail);
    CHECK(rc == 0, "hanzi group %d", rc);
    CHECK(glyphset_open(&hanzi, rawbuf, raw, hcps) == 0 && hanzi.n == 2821, "hanzi set (%u glyphs)", hanzi.n);
    {
        uint32_t zr;
        int n;
        rc = ovl_unpack_group(&p, LANG_ID_ZH_SIMPLIFIED, zbuf, sizeof zbuf, stage, sizeof stage, probs, &zr, &detail);
        n = rc ? -1 : lang_zh_simplified(&hanzi, zbuf, zr, stext, sizeof stext, soff, 2100, sel);
        CHECK(n == 2048, "simplified Chinese list (%d / %d)", rc, n);
        rc = ovl_unpack_group(&p, LANG_ID_ZH_TRADITIONAL, zbuf, sizeof zbuf, stage, sizeof stage, probs, &zr, &detail);
        n = rc ? -1 : lang_zh_traditional(&hanzi, stext, soff, zbuf, zr, ttext, sizeof ttext, toff, 2100, zwork);
        CHECK(n == 2048, "traditional Chinese list (%d / %d)", rc, n);
        rc = ovl_unpack_group(&p, LANG_ID_ZH_XMR, zbuf, sizeof zbuf, stage, sizeof stage, probs, &zr, &detail);
        nmon = rc ? -1 : lang_zh_monero(stext, soff, zbuf, zr, mtext, sizeof mtext, moff, 2100);
        CHECK(nmon > 0, "Monero Chinese list (%d)", nmon);
    }
    /* the index */
    {
        uint32_t ir;
        rc = ovl_unpack_group(&p, LANG_ID_INDEX, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &ir, &detail);
        nlang = rc ? -1 : lang_index(rawbuf, ir, langs, LANG_MAX);
        CHECK(nlang == 14, "language index (%d)", nlang);
    }

    rf = fopen(argv[2], "r");
    if (!rf) { printf("FAIL no reference\n"); return 1; }
    while (fgets(line, sizeof line, rf)) {
        unsigned a, b, c, d, e, g, h;
        char name[40], want[70], got[65];
        int n;

        if (sscanf(line, "lang %u %u %u %u %u %u %u %39s", &a, &b, &c, &d, &e, &g, &h, name) == 8) {
            int i;
            for (i = 0; i < nlang && langs[i].id != a; i++) {}
            CHECK(i < nlang && langs[i].flags == b && langs[i].glyphs == c && langs[i].xmr_prefix == d && langs[i].bip_group == e && langs[i].xmr_group == g && langs[i].separator == h,
                  "language %u", a);
            if (i < nlang) { for (char *s = name; *s; s++) if (*s == '~') *s = ' '; CHECK(!strcmp(langs[i].name, name), "name of language %u: %s / %s", a, langs[i].name, name); }
        } else if (sscanf(line, "list %x %d %64s", &a, &n, want) == 3 && (a >> 8) == 5) {      /* a mask over the BIP39 list: the words it makes */
            words_list wl;
            int ok = list_of(&p, a, nmon, &wl) == 0;
            if (ok) sha_text(wl.text, wl.off[wl.n], got); else strcpy(got, "-");
            CHECK(ok && wl.n == n && !strcmp(got, want), "Monero list %04x from a mask: %d words / %d, hash %.8s / %.8s", a, ok ? wl.n : -1, n, got, want);
            if (ok) {
                static uint8_t ones[256];
                static uint16_t so[2100];
                char tiny[8];
                memset(ones, 0xFF, sizeof ones);
                CHECK(lang_xmr_subset(wl.text, wl.off, wl.n, ones, 2, tiny, sizeof tiny, so, 2100) < 0, "a mask that is too short is refused");
                CHECK(lang_xmr_subset(wl.text, wl.off, wl.n, ones, sizeof ones, tiny, sizeof tiny, so, 2100) < 0, "a subset into a text buffer that is too small is refused");
                CHECK(lang_xmr_subset_size(wl.off, wl.n, ones, 2) == 0 && lang_xmr_subset_size(wl.off, wl.n, ones, sizeof ones) == wl.off[wl.n], "the size of a subset");
            }
        } else if (sscanf(line, "list %x %d %64s", &a, &n, want) == 3) {
            uint32_t br;
            size_t ws;
            int nw;
            rc = ovl_unpack_group(&p, (uint16_t) a, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &br, &detail);
            ws = rc ? 0 : wl_work_size(rawbuf, br);
            nw = !rc && ws && ws <= sizeof work ? wl_decode(rawbuf, br, work, sizeof work, wtext, sizeof wtext, woff, 2100) : -1;
            if (nw > 0) sha_text(wtext, woff[nw], got); else strcpy(got, "-");
            CHECK(nw == n && !strcmp(got, want), "word list %04x: %d words / %d, hash %.8s / %.8s", a, nw, n, got, want);
        } else if (sscanf(line, "zh %x %d %64s", &a, &n, want) == 3) {
            const char *t = a == 0x0400 ? stext : a == 0x0401 ? ttext : mtext;
            const uint16_t *o = a == 0x0400 ? soff : a == 0x0401 ? toff : moff;
            int nw = a == 0x0402 ? nmon : 2048;
            sha_text(t, o[nw], got);
            CHECK(nw == n && !strcmp(got, want), "Chinese list %04x: %d words / %d, hash %.8s / %.8s", a, nw, n, got, want);
        } else if (!strncmp(line, "mn39 ", 5) || !strncmp(line, "mnxmr ", 6)) {
            int xmr = line[2] == 'x';
            char hexs[80], joined[1200], *rest;
            uint8_t key[32];
            uint16_t idx[25];
            words_list wl;
            const lang_info *li;
            int nw, klen, o = 0;
            if (sscanf(line + (xmr ? 6 : 5), "%u %79s", &a, hexs) != 2) continue;
            rest = strstr(line + (xmr ? 6 : 5), hexs) + strlen(hexs) + 1;
            for (char *q = rest; *q; q++) if (*q == '\n' || *q == '\r') *q = 0;
            klen = (int) strlen(hexs) / 2;
            li = find_lang(langs, nlang, a);
            if (!li || unhex(hexs, key, klen)) { CHECK(0, "mnemonic line for language %u", a); continue; }
            if (list_of(&p, xmr ? li->xmr_group : li->bip_group, nmon, &wl)) { CHECK(0, "list of language %u", a); continue; }
            nw = xmr ? lang_xmr_indexes(&wl, li->xmr_prefix, key, idx) : lang_bip39_indexes(key, (size_t) klen, idx);
            for (int i = 0; i < nw; i++) {
                size_t l = (size_t) (wl.off[idx[i] + 1] - wl.off[idx[i]]) - 1;
                if (o + l + 2 >= sizeof joined) break;
                if (i) joined[o++] = '|';
                memcpy(joined + o, wl.text + wl.off[idx[i]], l);
                o += (int) l;
            }
            joined[o] = 0;
            CHECK(nw > 0 && !strcmp(joined, rest), "%s mnemonic of language %u: %s", xmr ? "Monero" : "BIP39", a, joined);
            if (xmr && nw == 25) {                                           /* and back: the key from the indexes, and a wrong checksum word is refused */
                uint8_t key2[32];
                CHECK(lang_xmr_decode(&wl, li->xmr_prefix, idx, key2) == 0 && !memcmp(key, key2, 32), "Monero key of language %u from its words", a);
                idx[24] = (uint16_t) ((idx[24] + 1) % wl.n);
                CHECK(lang_xmr_decode(&wl, li->xmr_prefix, idx, key2) < 0, "a wrong checksum word of language %u is refused", a);
            }
        } else if (sscanf(line, "hangul %64s", want) == 1) {         /* every syllable: NFKD by formula */
            static char hb[11172 * 10];
            size_t o = 0;
            for (unsigned c = 0xAC00; c <= 0xD7A3; c++) {
                char u[4] = {(char) (0xE0 | c >> 12), (char) (0x80 | ((c >> 6) & 63)), (char) (0x80 | (c & 63)), 0};
                o += lang_nfkd(u, hb + o, sizeof hb - o) + 1;
            }
            sha_text(hb, o, got);
            CHECK(!strcmp(got, want), "NFKD of all Hangul syllables: %.8s / %.8s", got, want);
        } else if (sscanf(line, "nfkd %u %64s", &a, want) == 2) {
            words_list wl;
            const lang_info *li = find_lang(langs, nlang, a);
            static char nb[40000];
            size_t o = 0;
            if (!li || list_of(&p, li->bip_group, nmon, &wl)) { CHECK(0, "list of language %u", a); continue; }
            for (int i = 0; i < wl.n; i++) {
                size_t l = lang_nfkd(wl.text + wl.off[i], nb + o, sizeof nb - o);
                if (l == (size_t) -1) { o = 0; break; }
                o += l + 1;
            }
            sha_text(nb, o, got);
            CHECK(o && !strcmp(got, want), "NFKD of the words of language %u: %.8s / %.8s", a, got, want);
        } else if (sscanf(line, "keys %u %u %64s", &a, &b, want) == 3) {
            words_list wl;
            const lang_info *li = find_lang(langs, nlang, a);
            static uint8_t kb_[2100 * 19];
            static uint16_t found[8];
            int ok = 1, bad_find = 0;
            if (!li || list_of(&p, li->bip_group, nmon, &wl)) { CHECK(0, "list of language %u", a); continue; }
            for (int i = 0; i < wl.n; i++) if (langin_key((int) b, wl.text + wl.off[i], kb_ + i * 19, 19) < 0) ok = 0;
            sha_text((const char *) kb_, (size_t) wl.n * 19, got);
            CHECK(ok && !strcmp(got, want), "keys of the words of language %u: %.8s / %.8s", a, got, want);
            for (int i = 0; i < wl.n; i += 7) {                    /* every word is found by its whole key, and by the first letters of it */
                int kl = (int) strlen((const char *) kb_ + i * 19), tl = kl < 3 ? kl : 3, total, hit = 0;
                total = langin_find(kb_, 19, wl.n, kb_ + i * 19, kl, 0, 8, found);
                for (int j = 0; j < total && j < 8; j++) if (found[j] == i) hit = 1;
                if (!hit) bad_find++;
                if (tl > 0 && langin_find(kb_, 19, wl.n, kb_ + i * 19, tl, 0, 8, found) < 1) bad_find++;
            }
            CHECK(!bad_find, "words are found by their keys in language %u (%d misses)", a, bad_find);
        } else if (!strncmp(line, "seed ", 5)) {
            char hexs[80], pw[40], want_seed[140], sent[600], got_seed[140];
            uint8_t ent[32], ent2[32], seed[64];
            uint16_t idx[24];
            words_list wl;
            const lang_info *li;
            int nw, klen, el;
            if (sscanf(line + 5, "%u %79s %39s %139s", &a, hexs, pw, want_seed) != 4) continue;
            klen = (int) strlen(hexs) / 2;
            li = find_lang(langs, nlang, a);
            if (!li || unhex(hexs, ent, klen) || list_of(&p, li->bip_group, nmon, &wl)) { CHECK(0, "seed line for language %u", a); continue; }
            nw = lang_bip39_indexes(ent, (size_t) klen, idx);
            CHECK(nw > 0 && langin_sentence(&wl, idx, nw, sent, sizeof sent) > 0, "sentence of language %u", a);
            bip39_seed(sent, strcmp(pw, "-") ? pw : "", seed);
            hex_of(got_seed, seed, 64);
            CHECK(!strcmp(got_seed, want_seed), "seed of a sentence of language %u (%.8s / %.8s)", a, got_seed, want_seed);
            el = langin_bip39_entropy(idx, nw, ent2);
            CHECK(el == klen && !memcmp(ent, ent2, (size_t) klen), "entropy from the indexes of language %u", a);
            idx[0] ^= 1;
            el = langin_bip39_entropy(idx, nw, ent2);
            CHECK(el < 0 || memcmp(ent, ent2, (size_t) klen), "a changed index does not give the same entropy (language %u)", a);
        } else if (sscanf(line, "glyphs %x %d %d %64s", &a, &n, &b, want) == 4) {
            glyphset gs;
            uint32_t gr;
            sha256_ctx cx;
            uint8_t h32[32];
            rc = ovl_unpack_group(&p, (uint16_t) a, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &gr, &detail);
            if (rc || glyphset_open(&gs, rawbuf, gr, gcps)) { CHECK(0, "glyph group %04x (%d)", a, rc); continue; }
            sha256_init(&cx);
            for (int i = 0; i < gs.n; i++) {
                uint16_t rows[18];
                uint8_t cb[2];
                glyphset_rows(&gs, i, rows);
                cb[0] = (uint8_t) gs.cps[i]; cb[1] = (uint8_t) (gs.cps[i] >> 8);
                sha256_update(&cx, cb, 2);
                for (int y = 0; y < gs.h; y++) { cb[0] = (uint8_t) rows[y]; cb[1] = (uint8_t) (rows[y] >> 8); sha256_update(&cx, cb, 2); }
                CHECK(glyphset_find(&gs, gs.cps[i]) == i, "glyphset_find %04x", gs.cps[i]);
            }
            sha256_final(&cx, h32);
            hex_of(got, h32, 32);
            CHECK(gs.n == n && gs.h == b && !strcmp(got, want), "glyph group %04x: %u glyphs / %d, hash %.8s / %.8s", a, gs.n, n, got, want);
            CHECK(glyphset_find(&gs, 0x41) == -1, "a letter is not in %04x", a);
        }
    }
    fclose(rf);

    /* refusals */
    {
        uint32_t r2;
        CHECK(ovl_unpack_group(&p, 0x0999, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &r2, &detail) == OVL_ERR_GROUP, "a missing group");
        CHECK(ovl_unpack_group(&p, LANG_ID_HANZI, rawbuf, 1000, stage, sizeof stage, probs, &r2, &detail) == OVL_ERR_SPACE, "a destination that is too small");
        CHECK(ovl_unpack_group(&p, LANG_ID_HANZI, rawbuf, sizeof rawbuf, stage, 100, probs, &r2, &detail) == OVL_ERR_SPACE, "a stage that is too small");
        for (int i = 0; i < p.ngroups; i++) {
            if (p.g[i].id != LANG_ID_HANZI && p.g[i].id != 0x0204) continue;
            flip_at = (int) (p.g[i].offset + p.g[i].len / 2);
            rc = ovl_unpack_group(&p, p.g[i].id, rawbuf, sizeof rawbuf, stage, sizeof stage, probs, &r2, &detail);
            CHECK(rc == OVL_ERR_PKG && detail == PKG_ERR_HASH, "a damaged group %04x must fail its hash (%d, %d)", p.g[i].id, rc, detail);
            flip_at = -1;
        }
    }
    printf("language card: %d checks, %d bad\n", total, bad);
    return bad != 0;
}
