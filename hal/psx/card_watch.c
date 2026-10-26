#include "card_watch.h"
#include "log.h"
#include <stdio.h>
#include "ui.h"
#include <string.h>
#include "mcard.h"

#define CHECK_SECONDS 5                                   /* a fingerprint check of a steady card every this many seconds */

void cw_init(cw *c, int hz, const char *package_name, int kind, const uint8_t pin[32])
{
    memset(c, 0, sizeof *c);
    c->hz = hz;
    c->interval = hz / 4;
    c->name = package_name;
    c->kind = kind;
    c->pin = pin;
    for (int p = 0; p < 2; p++) watch_init(&c->s[p].w);
}

void cw_begin(cw *c, int frame, int interval_ms)
{
    c->interval = interval_ms * c->hz / 1000;
    if (c->interval < 1) c->interval = 1;
    c->next_poll = frame;
    for (int p = 0; p < 2; p++) {
        c->s[p].have = 0;                                 /* a screen that opens looks again, whatever it knew */
        c->s[p].state = CW_CHECKING;
        watch_init(&c->s[p].w);
    }
}

static int pin_empty(const uint8_t *pin)
{
    for (int i = 0; i < 32; i++) if (pin[i]) return 0;
    return 1;
}

/* the full look at a card that has been steady */
static void look(cw *c, int p, int frame)
{
    static ldr_pkg tmp;
    cw_slot *s = &c->s[p];
    dirscan d;
    int detail, rc = ldr_scan(p, &d, &detail);

    s->have = 1;
    s->next_check = frame + CHECK_SECONDS * c->hz;
    s->code = s->detail = 0;
    if (rc) { s->state = CW_READ_ERROR; s->fp = 0; return; }
    s->fp = d.fingerprint;
    if (!d.formatted) { s->state = CW_UNFORMATTED; return; }
    if (d.boot) { s->state = CW_BOOT; return; }
    if (pin_empty(c->pin)) { s->state = CW_PKG_BAD; s->code = LDR_ERR_NOPIN; return; }
    rc = ldr_open(&tmp, p, c->name, c->kind, c->pin, &detail);
    if (rc == LDR_OK) {
        snprintf(s->digest, sizeof s->digest, "%02x%02x%02x%02x", tmp.pk.digest[0], tmp.pk.digest[1], tmp.pk.digest[2], tmp.pk.digest[3]);
        s->state = CW_PKG_OK;
    } else if (rc == LDR_ERR_CARD && detail == CF_ERR_NOTFOUND) s->state = CW_NO_PACKAGE;
    else if (rc == LDR_ERR_CARD && detail == CF_ERR_READ) s->state = CW_READ_ERROR;
    else { s->state = CW_PKG_BAD; s->code = rc; s->detail = detail; }
}

static void log_state(const cw *c, int p, const char *why)
{
    char t[40];

    cw_text(c, p, t, sizeof t);
    LOG("[cw] slot %d %s: %s\n", p + 1, why, t);
}

static void poll(cw *c, int p)
{
    cw_slot *s = &c->s[p];
    unsigned ev = watch_feed(&s->w, mc_present(p));

    if (ev & WATCH_EVENT_RAW_FLIP) { s->have = 0; if (s->state != CW_UNKNOWN) s->state = CW_CHECKING; LOG("[cw] slot %d raw %s\n", p + 1, s->w.raw ? "present" : "absent"); }   /* whatever was known is void */
    if (s->w.shown == 0 && s->state != CW_NO_CARD) { s->state = CW_NO_CARD; s->have = 0; }
}

void cw_tick(cw *c, int frame)
{
    if (frame >= c->next_poll) {
        c->next_poll = frame + c->interval;
        poll(c, 0);
        poll(c, 1);
    }
    for (int p = 0; p < 2; p++) {                         /* one look per frame at most, so a screen does not stall for two cards at once */
        cw_slot *s = &c->s[p];

        if (s->w.shown == 1 && s->w.raw == 1 && !s->have) { look(c, p, frame); log_state(c, p, T(TXT_LOOKED_AT)); return; }
        if (s->have && s->w.shown == 1 && frame >= s->next_check) {            /* the content of a card that stays: a changed image shows here */
            dirscan d;
            int detail;
            if (ldr_scan(p, &d, &detail) || d.fingerprint != s->fp) { s->have = 0; s->w.gen++; s->state = CW_CHECKING; LOG("[cw] slot %d: the content changed\n", p + 1); }
            else s->next_check = frame + CHECK_SECONDS * c->hz;
            return;
        }
    }
}

void cw_refresh(cw *c, int frame)
{
    for (int p = 0; p < 2; p++) {
        cw_slot *s = &c->s[p];
        watch_init(&s->w);
        watch_feed(&s->w, mc_present(p));
        watch_feed(&s->w, mc_present(p));
        s->have = 0;
        if (s->w.shown == 1) look(c, p, frame);
        else { s->state = CW_NO_CARD; }
    }
}

int cw_ok(const cw *c, int port) { return c->s[port].state == CW_PKG_OK && c->s[port].have; }

void cw_text(const cw *c, int port, char *buf, size_t n)
{
    const cw_slot *s = &c->s[port];

    switch (s->state) {
    case CW_UNKNOWN: snprintf(buf, n, "..."); break;
    case CW_CHECKING: snprintf(buf, n, "checking..."); break;
    case CW_NO_CARD: snprintf(buf, n, T(TXT_NO_CARD)); break;
    case CW_UNFORMATTED: snprintf(buf, n, T(TXT_CARD_NOT_FORMATTED)); break;
    case CW_BOOT: snprintf(buf, n, T(TXT_FREEPSXBOOT_CARD_NOT_A_PACKAGE)); break;
    case CW_NO_PACKAGE: snprintf(buf, n, T(TXT_CARD_NO_PACKAGE)); break;
    case CW_PKG_OK: snprintf(buf, n, T(TXT_PACKAGE_N_THIS_RELEASE), s->digest); break;
    case CW_PKG_BAD:
        if (s->code == LDR_ERR_BASE || (s->code == LDR_ERR_PKG && s->detail == PKG_ERR_PIN)) snprintf(buf, n, T(TXT_ANOTHER_RELEASE_VERSION));
        else snprintf(buf, n, "%s", ldr_describe(s->code, s->detail));
        break;
    default: snprintf(buf, n, T(TXT_CARD_NOT_READABLE)); break;
    }
}
