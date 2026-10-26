/* Files of several blocks on a memory card (core/pkg/cardfile.c) against tests/cardfile_card.txt (written by tools/mkcard.py): the files are found and read at every
 * offset and length, then the card is damaged in many ways (frames changed, a reader that fails) and nothing may be read from it wrongly or crash.
 * Usage: test_cardfile <cardfile_card.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkg/cardfile.h"

static uint8_t card[1024][CF_FRAME];

typedef struct { int fail_at, calls; const uint8_t (*c)[CF_FRAME]; } rdctx;

static int rd(void *ctx, int frame, uint8_t out[CF_FRAME])
{
    rdctx *r = ctx;
    if (frame < 0 || frame > 1023) return -1;
    if (r->fail_at >= 0 && r->calls++ == r->fail_at) return -1;
    memcpy(out, r->c[frame], CF_FRAME);
    return 0;
}

static uint8_t pat(uint32_t i, int salt) { return (uint8_t) (i * 37 + (i >> 7) * 11 + salt); }

static uint32_t rnd_state = 0x1234567u;
static uint32_t rnd(void) { rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5; return rnd_state; }

static void fix_xor(uint8_t *e) { uint8_t x = 0; for (int i = 0; i < 127; i++) x ^= e[i]; e[127] = x; }

int main(int argc, char **argv)
{
    FILE *fp = fopen(argc > 1 ? argv[1] : "tests/cardfile_card.txt", "r");
    char line[512];
    struct { char name[24]; int len, salt, nblocks, blocks[15]; } F[4];
    int nf = 0, fails = 0, checks = 0;
    static uint8_t buf[40000];

    if (!fp) { printf("cannot read the card\n"); return 2; }
    memset(card, 0, sizeof card);
    while (fgets(line, sizeof line, fp)) {
        if (line[0] == 'f' && line[1] == ' ') {
            int fr;
            char *h = strchr(line + 2, ' ');
            sscanf(line + 2, "%d", &fr);
            for (int i = 0; i < CF_FRAME; i++) { unsigned v; sscanf(h + 1 + 2 * i, "%2x", &v); card[fr][i] = (uint8_t) v; }
        } else if (!strncmp(line, "file ", 5)) {
            char blocks[64];
            sscanf(line + 5, "%23s %63s %d %d", F[nf].name, blocks, &F[nf].len, &F[nf].salt);
            F[nf].nblocks = 0;
            for (char *t = strtok(blocks, ","); t; t = strtok(NULL, ",")) F[nf].blocks[F[nf].nblocks++] = atoi(t);
            nf++;
        }
    }
    fclose(fp);

#define CHECK(cond, ...) do { checks++; if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

    for (int k = 0; k < nf; k++) {
        rdctx c = {-1, 0, (const uint8_t (*)[CF_FRAME]) card};
        cf_file f;
        int rc = cf_open(&f, rd, &c, F[k].name);
        CHECK(rc == CF_OK, "open %s: %d (%s)", F[k].name, rc, cf_strerror(rc));
        if (rc) continue;
        CHECK(f.nblocks == F[k].nblocks, "%s: %d blocks, wanted %d", F[k].name, f.nblocks, F[k].nblocks);
        for (int i = 0; i < f.nblocks && i < F[k].nblocks; i++) CHECK(f.blocks[i] == F[k].blocks[i], "%s: block %d is %d, wanted %d", F[k].name, i, f.blocks[i], F[k].blocks[i]);
        CHECK(f.size == 8192u * F[k].nblocks - 256, "%s: size %u", F[k].name, (unsigned) f.size);
        for (int it = 0; it < 3000; it++) {                                   /* reads of any offset and length, also across the blocks */
            uint32_t off = rnd() % f.size, len = rnd() % 700;
            if (off + len > f.size) len = f.size - off;
            rc = cf_read(&f, off, buf, len);
            CHECK(rc == CF_OK, "%s: read %u+%u: %d", F[k].name, (unsigned) off, (unsigned) len, rc);
            if (rc) break;
            for (uint32_t i = 0; i < len; i++)
                if (buf[i] != (off + i < (uint32_t) F[k].len ? pat(off + i, F[k].salt) : 0)) { CHECK(0, "%s: wrong byte at %u", F[k].name, (unsigned) (off + i)); break; }
        }
        CHECK(cf_read(&f, 0, buf, f.size) == CF_OK, "%s: the whole file", F[k].name);
        CHECK(cf_read(&f, f.size - 5, buf, 6) == CF_ERR_RANGE, "%s: a read past the end", F[k].name);
        CHECK(cf_read(&f, f.size, buf, 0) == CF_OK, "%s: an empty read at the end", F[k].name);
    }
    {   /* names that are not there, or are not the whole name */
        rdctx c = {-1, 0, (const uint8_t (*)[CF_FRAME]) card};
        cf_file f;
        CHECK(cf_open(&f, rd, &c, "BESCES-00000PSXXPK03") == CF_ERR_NOTFOUND, "an unknown name");
        CHECK(cf_open(&f, rd, &c, "BESCES-00000PSXXPK0") == CF_ERR_NOTFOUND, "a prefix of a name");
        CHECK(cf_open(&f, rd, &c, "") == CF_ERR_NOTFOUND, "an empty name");
        CHECK(cf_open(&f, rd, &c, "BESCES-00000PSXXPK01X") == CF_ERR_NOTFOUND, "a name that is too long");
    }

    /* damage: a copy of the card is changed in one place, then the first file is opened and read (the answer has to be an error, or the right data) */
    {
        static uint8_t bad[1024][CF_FRAME];
        const char *name = F[0].name;
        int first = F[0].blocks[0], second = F[0].blocks[1], third = F[0].blocks[2];
        struct { const char *what; int expect; } T[] = {
            {"the header frame is not MC", CF_ERR_FORMAT}, {"the checksum of the header frame", CF_ERR_FORMAT}, {"the checksum of the first entry", CF_ERR_CHAIN},
            {"the checksum of the second entry", CF_ERR_CHAIN}, {"the chain loops back to the first block", CF_ERR_CHAIN}, {"the chain loops on the second block", CF_ERR_CHAIN},
            {"a link to a free block", CF_ERR_CHAIN}, {"a link beyond block 15", CF_ERR_CHAIN}, {"the last block does not end the chain", CF_ERR_CHAIN},
            {"a middle block that ends the chain", CF_ERR_CHAIN}, {"a middle block marked as first", CF_ERR_CHAIN}, {"the size of the first entry is wrong", CF_ERR_CHAIN},
            {"the file header is not SC", CF_ERR_HEADER}, {"the icon flag is wrong", CF_ERR_HEADER}, {"the unformatted card (all zero)", CF_ERR_FORMAT}};
        for (unsigned t = 0; t < sizeof T / sizeof T[0]; t++) {
            rdctx c = {-1, 0, (const uint8_t (*)[CF_FRAME]) bad};
            cf_file f;
            int rc;
            memcpy(bad, card, sizeof card);
            switch (t) {
            case 0: bad[0][0] = 'X'; break;
            case 1: bad[0][127] ^= 1; break;
            case 2: bad[first][127] ^= 1; break;
            case 3: bad[second][127] ^= 1; break;
            case 4: bad[third][8] = (uint8_t) (first - 1); bad[third][9] = 0; bad[third][0] = 0x52; fix_xor(bad[third]); break;
            case 5: bad[third][8] = (uint8_t) (second - 1); bad[third][9] = 0; bad[third][0] = 0x52; fix_xor(bad[third]); break;
            case 6: bad[first][8] = 1; bad[first][9] = 0; fix_xor(bad[first]); break;            /* block 2 is free */
            case 7: bad[first][8] = 0xF0; bad[first][9] = 0x00; fix_xor(bad[first]); break;
            case 8: bad[third][8] = 0; bad[third][9] = 0; fix_xor(bad[third]); break;
            case 9: bad[second][8] = 0xFF; bad[second][9] = 0xFF; fix_xor(bad[second]); break;
            case 10: bad[second][0] = 0x51; fix_xor(bad[second]); break;
            case 11: bad[first][4] = 0; bad[first][5] = 0x40; fix_xor(bad[first]); break;
            case 12: bad[64 * first][0] = 'X'; break;
            case 13: bad[64 * first][2] = 0x20; break;
            case 14: memset(bad, 0, sizeof bad); break;
            }
            rc = cf_open(&f, rd, &c, name);
            CHECK(rc == T[t].expect, "damage \"%s\": open gave %d (%s), wanted %d", T[t].what, rc, cf_strerror(rc), T[t].expect);
        }
        for (int at = 0; at < 24; at++) {                                      /* a reader that fails at the n-th frame, while opening and while reading */
            rdctx c = {at, 0, (const uint8_t (*)[CF_FRAME]) card};
            cf_file f;
            int rc = cf_open(&f, rd, &c, name);
            if (rc == CF_OK) rc = cf_read(&f, 0, buf, f.size > sizeof buf ? sizeof buf : f.size);
            CHECK(rc == CF_ERR_READ, "a failing reader at %d: %d (wanted a read error)", at, rc);
        }
        {                                                                      /* random damage in the directory and in the data: no crash, whatever the answer is */
            int opened = 0;
            for (int it = 0; it < 6000; it++) {
                rdctx c = {-1, 0, (const uint8_t (*)[CF_FRAME]) bad};
                cf_file f;
                memcpy(bad, card, sizeof card);
                for (int k = 0, n = 1 + (int) (rnd() % 3); k < n; k++) {
                    int fr = (rnd() % 3 == 0) ? (int) (rnd() % 16) : (int) (rnd() % 1024);
                    bad[fr][rnd() % CF_FRAME] ^= (uint8_t) (1u << (rnd() % 8));
                }
                if (cf_open(&f, rd, &c, name) == CF_OK) {
                    uint32_t n = f.size > sizeof buf ? sizeof buf : f.size;
                    opened++;
                    (void) cf_read(&f, 0, buf, n);
                    (void) cf_read(&f, f.size / 2, buf, 77);
                }
            }
            printf("random damage: 6000 cards, the file could still be opened on %d\n", opened);
            checks++;
        }
    }
    printf("card files: %d checks, %d wrong\n", checks, fails);
    return fails != 0;
}
