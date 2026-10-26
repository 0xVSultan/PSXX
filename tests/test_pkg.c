/* The card package parser (core/pkg/pkg.c) against tests/pkg_vectors.txt (made by tools/gen_pkg_vectors.py with its own checker), then a reader that fails,
 * then random damage: a package that is accepted with the right pin must give exactly the bytes that were packed, whatever was changed, and nothing may crash.
 * Usage: test_pkg <pkg_vectors.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash/sha256.h"
#include "pkg/pkg.h"

typedef struct { const uint8_t *d; uint32_t n; int calls, fail_at; } mem;

static int mem_read(void *ctx, uint32_t off, uint8_t *buf, uint32_t len)
{
    mem *m = ctx;
    if (m->fail_at >= 0 && m->calls++ == m->fail_at) return -1;
    if ((uint64_t) off + len > m->n) return -1;
    memcpy(buf, m->d + off, len);
    return 0;
}

static int code_of(const char *s)
{
    static const struct { const char *n; int c; } T[] = {{"OK", PKG_OK}, {"READ", PKG_ERR_READ}, {"MAGIC", PKG_ERR_MAGIC}, {"VERSION", PKG_ERR_VERSION}, {"KIND", PKG_ERR_KIND},
        {"HEADER", PKG_ERR_HEADER}, {"PIN", PKG_ERR_PIN}, {"TABLE", PKG_ERR_TABLE}, {"SIZE", PKG_ERR_SIZE}};
    for (unsigned i = 0; i < sizeof T / sizeof T[0]; i++) if (!strcmp(T[i].n, s)) return T[i].c;
    return 99;
}

static int unhex(const char *s, uint8_t *out, size_t max)
{
    size_t n = 0;
    while (s[0] && s[1] && s[0] != '\n' && s[0] != '\r') {
        unsigned v;
        if (n >= max || sscanf((char[3]) {s[0], s[1], 0}, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t) v;
        s += 2;
    }
    return (int) n;
}

typedef struct { char name[64]; uint8_t *d; uint32_t n; uint8_t pin[32]; int has_pin, kind; } vec;

static uint32_t rnd_state = 0x2545F491u;
static uint32_t rnd(void) { rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5; return rnd_state; }

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/pkg_vectors.txt", "r");
    static char line[1 << 17];
    static vec valid[8];
    static uint8_t buf[PKG_MAX_SIZE + 1024];
    int total = 0, fails = 0, nvalid = 0;

    if (!f) { printf("cannot read the vectors\n"); return 2; }
    while (fgets(line, sizeof line, f)) {
        char *fld[6], *s = line;
        vec v;
        pkg p;
        mem m;
        int rc, want, n;

        if (line[0] == '#' || line[0] == '\n') continue;
        for (int i = 0; i < 6; i++) { fld[i] = s; s = strchr(s, '|'); if (s) *s++ = 0; else if (i < 5) { printf("bad line\n"); return 2; } }
        snprintf(v.name, sizeof v.name, "%s", fld[0]);
        v.kind = atoi(fld[1]);
        v.has_pin = strcmp(fld[2], "-") != 0;
        if (v.has_pin && unhex(fld[2], v.pin, 32) != 32) { printf("bad pin\n"); return 2; }
        n = unhex(fld[5], buf, sizeof buf);
        if (n < 0) { printf("bad hex in %s\n", v.name); return 2; }
        v.n = (uint32_t) n;
        v.d = malloc(v.n);
        memcpy(v.d, buf, v.n);
        m = (mem) {v.d, v.n, 0, -1};
        rc = pkg_open(&p, mem_read, &m, v.n, v.kind, v.has_pin ? v.pin : NULL);
        want = code_of(fld[3]);
        total++;
        if (rc != want) { printf("FAIL %s: open gave %d (%s), wanted %s\n", v.name, rc, pkg_strerror(rc), fld[3]); fails++; }
        else if (rc == PKG_OK) {
            char *g = fld[4];
            for (unsigned k = 0; k < p.ngroups; k++) {
                static uint8_t gb[PKG_MAX_SIZE];
                int r = pkg_read_group(&p, &p.g[k], gb, sizeof gb), w = !strncmp(g, "OK", 2) ? PKG_OK : PKG_ERR_HASH;
                if (r != w) { printf("FAIL %s: group %u gave %d, wanted %s\n", v.name, k, r, g); fails++; }
                if (r == PKG_ERR_HASH && memcmp(gb, (uint8_t[16]) {0}, p.g[k].len < 16 ? p.g[k].len : 16)) { printf("FAIL %s: a refused group was not wiped\n", v.name); fails++; }
                g = strchr(g, ',');
                if (!g) break;
                g++;
            }
        }
        if (!strncmp(v.name, "valid_", 6) && v.has_pin && nvalid < 8) valid[nvalid++] = v;
        else free(v.d);
    }
    fclose(f);

    /* other calls: unknown group, a group pointer that is not in the table, a buffer that is too small, the base image id */
    for (int i = 0; i < nvalid; i++) {
        vec *v = &valid[i];
        pkg p;
        mem m = {v->d, v->n, 0, -1};
        pkg_group alien = {0};
        uint8_t tiny[1], base[32];

        if (pkg_open(&p, mem_read, &m, v->n, 0, v->pin) != PKG_OK) { printf("FAIL %s: reopen\n", v->name); fails++; continue; }
        total++;
        if (pkg_find(&p, 65535) || !pkg_find(&p, p.g[0].id)) { printf("FAIL %s: pkg_find\n", v->name); fails++; }
        if (pkg_read_group(&p, &alien, buf, sizeof buf) != PKG_ERR_NOGROUP) { printf("FAIL %s: foreign group accepted\n", v->name); fails++; }
        if (p.g[0].len > 1 && pkg_read_group(&p, &p.g[0], tiny, sizeof tiny) != PKG_ERR_SIZE) { printf("FAIL %s: small buffer\n", v->name); fails++; }
        sha256((const uint8_t *) "base image", 10, base);
        if (!strcmp(v->name, "valid_overlay")) {
            if (pkg_check_base(&p, base) != PKG_OK) { printf("FAIL valid_overlay: base id\n"); fails++; }
            base[0] ^= 1;
            if (pkg_check_base(&p, base) != PKG_ERR_BASE) { printf("FAIL valid_overlay: another base id accepted\n"); fails++; }
        } else if (p.kind == PKG_KIND_DATA && pkg_check_base(&p, base) != PKG_ERR_BASE) { printf("FAIL %s: base id of a data package\n", v->name); fails++; }

        /* the reader fails at the n-th call: no crash, a read error, and nothing is left in p */
        for (int at = 0; at < 8; at++) {
            mem fm = {v->d, v->n, 0, at};
            int rc = pkg_open(&p, mem_read, &fm, v->n, 0, v->pin);
            if (rc != PKG_OK && (rc != PKG_ERR_READ || p.ngroups)) { printf("FAIL %s: failing reader (call %d): %d\n", v->name, at, rc); fails++; }
        }
    }

    /* random damage */
    {
        long accepted = 0, refused = 0, wrong = 0;
        for (int i = 0; i < nvalid; i++) {
            vec *v = &valid[i];
            static uint8_t orig[PKG_MAX_GROUPS][4096], got[4096], *bad;
            pkg p0, p;
            mem m0 = {v->d, v->n, 0, -1};

            pkg_open(&p0, mem_read, &m0, v->n, 0, v->pin);
            for (unsigned k = 0; k < p0.ngroups; k++) pkg_read_group(&p0, &p0.g[k], orig[k], 4096);
            bad = malloc(v->n);
            for (int it = 0; it < 4000; it++) {
                uint32_t len = v->n;
                mem m;
                int rc;
                memcpy(bad, v->d, v->n);
                if (it % 5 == 0) len = rnd() % v->n;                                   /* cut short */
                else for (int k = 0, c = 1 + (int) (rnd() % 3); k < c; k++) {
                    if (rnd() % 2) bad[rnd() % v->n] ^= (uint8_t) (1u << (rnd() % 8));
                    else bad[rnd() % v->n] = (uint8_t) rnd();
                }
                m = (mem) {bad, len, 0, -1};
                rc = pkg_open(&p, mem_read, &m, len, 0, v->pin);
                if (rc != PKG_OK) { refused++; continue; }
                accepted++;
                for (unsigned k = 0; k < p.ngroups; k++) {
                    if (pkg_read_group(&p, &p.g[k], got, sizeof got) != PKG_OK) continue;
                    {
                        unsigned j;
                        for (j = 0; j < p0.ngroups && p0.g[j].id != p.g[k].id; j++) {}
                        if (j == p0.ngroups || p.g[k].len != p0.g[j].len || memcmp(got, orig[j], p.g[k].len)) wrong++;
                    }
                }
            }
            free(bad);
        }
        total++;
        printf("damage: %ld refused, %ld accepted (only damage the pin does not cover: the padding, the content of a group that then fails its hash), %ld wrong data accepted\n", refused, accepted, wrong);
        if (wrong) fails++;
    }
    printf("card packages: %d checks, %d wrong\n", total, fails);
    return fails != 0;
}
