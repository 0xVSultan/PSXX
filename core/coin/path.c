#include "coin/path.h"
#include <stdio.h>
#include <string.h>

int path_parse(hd_path *p, const char *s)
{
    memset(p, 0, sizeof *p);
    if (*s == 'm' || *s == 'M') {
        s++;
        if (*s == 0) return PATH_OK;
        if (*s != '/') return PATH_ERR_SYNTAX;
        s++;
    }
    for (;;) {
        uint64_t v = 0;
        int digits = 0, hard = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (uint64_t)(*s - '0');
            if (v > 0xFFFFFFFFu) return PATH_ERR_RANGE;      /* keep it from overflowing; too large either way */
            digits++;
            s++;
        }
        if (!digits) return PATH_ERR_SYNTAX;
        if (*s == '\'' || *s == 'h' || *s == 'H') { hard = 1; s++; }
        if (v >= PATH_HARD) return PATH_ERR_RANGE;
        if (p->n >= PATH_MAX_DEPTH) return PATH_ERR_DEPTH;
        p->idx[p->n++] = (uint32_t)v | (hard ? PATH_HARD : 0);
        if (*s == 0) return PATH_OK;
        if (*s != '/') return PATH_ERR_SYNTAX;
        s++;
    }
}

int path_format(const hd_path *p, char *out, size_t cap)
{
    size_t o = 0;
    if (cap < 2) return -1;
    out[o++] = 'm';
    for (int i = 0; i < p->n; i++) {
        char t[14];
        int l = sprintf(t, "/%lu%s", (unsigned long) (p->idx[i] & ~PATH_HARD), (p->idx[i] & PATH_HARD) ? "'" : "");
        if (o + (size_t) l + 1 > cap) { out[o] = 0; return -1; }      /* the text that fits, ended (the screens print it as it is) */
        memcpy(out + o, t, (size_t) l);
        o += (size_t) l;
    }
    out[o] = 0;
    return (int) o;
}

int path_all_hardened(const hd_path *p)
{
    for (int i = 0; i < p->n; i++) if (!(p->idx[i] & PATH_HARD)) return 0;
    return 1;
}
