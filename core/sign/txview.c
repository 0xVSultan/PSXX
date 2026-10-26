#include "sign/txview.h"
#include <stdio.h>
#include <string.h>

tx_view txv_shared;
char *txv_text;
size_t txv_text_cap;
uint8_t *txv_work;
size_t txv_work_cap;

int txv_set_text(tx_view *v, const uint8_t *s, size_t n)
{
    if (!txv_text || n + 1 > txv_text_cap) { v->text_len = 0; return -1; }
    for (size_t i = 0; i < n; i++) txv_text[i] = (char) (s[i] < 0x20 ? ' ' : s[i]);
    txv_text[n] = 0;
    v->text_len = (int) n;
    return 0;
}

int txv_amount_be(char *out, size_t cap, const uint8_t *value, size_t n, int decimals, const char *sym)
{
    uint8_t x[32];
    char dig[80];
    int nd = 0, len = 0;
    size_t i;

    if (n > 32) n = 32;
    memcpy(x, value, n);
    for (;;) {                                         /* repeated division by 10: the digits come least significant first */
        unsigned rem = 0;
        int nz = 0;
        for (i = 0; i < n; i++) {
            unsigned cur = rem * 256u + x[i];
            x[i] = (uint8_t) (cur / 10);
            rem = cur % 10;
            nz |= x[i];
        }
        dig[nd++] = (char) ('0' + rem);
        if (!nz || nd >= 78) break;
    }
    while (nd <= decimals) dig[nd++] = '0';            /* at least one digit before the point */
    {
        int int_digits = nd - decimals, frac = decimals;
        char tmp[100];
        int t = 0;
        while (frac > 0 && dig[decimals - frac] == '0') frac--;     /* trailing zeros of the fraction */
        for (i = 0; i < (size_t) int_digits; i++) tmp[t++] = dig[nd - 1 - (int) i];
        if (frac > 0) {
            tmp[t++] = '.';
            for (int k = 0; k < frac; k++) tmp[t++] = dig[decimals - 1 - k];
        }
        tmp[t] = 0;
        len = (int) strlen(tmp);
        if (sym) len += 1 + (int) strlen(sym);
        if ((size_t) len + 1 > cap) { if (cap) out[0] = 0; return -1; }
        strcpy(out, tmp);
        if (sym) { strcat(out, " "); strcat(out, sym); }
    }
    return len;
}

int txv_amount_u64(char *out, size_t cap, uint64_t value, int decimals, const char *sym)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t) (value >> (56 - 8 * i));
    return txv_amount_be(out, cap, b, 8, decimals, sym);
}

void txv_note(tx_view *v, const char *s)
{
    if (v->nnote >= TXV_NOTES) return;
    strncpy(v->note[v->nnote], s, sizeof v->note[0] - 1);
    v->note[v->nnote][sizeof v->note[0] - 1] = 0;
    v->nnote++;
}

void txv_clear(tx_view *v) { memset(v, 0, sizeof *v); }

void txv_add_out(tx_view *v, const char *to, const char *amount)
{
    if (v->nout >= TXV_OUTS) { v->nmore++; v->warn |= TXW_TRUNCATED; return; }
    snprintf(v->out[v->nout].to, sizeof v->out[0].to, "%s", to);
    snprintf(v->out[v->nout].amount, sizeof v->out[0].amount, "%s", amount);
    v->nout++;
}

uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

int rd_cs(const uint8_t **pp, const uint8_t *end, uint64_t *v)
{
    const uint8_t *p = *pp;
    int n;
    uint64_t x = 0;
    if (p >= end) return -1;
    if (*p < 0xFD) { *v = *p; *pp = p + 1; return 0; }
    n = *p == 0xFD ? 2 : *p == 0xFE ? 4 : 8;
    if (end - p - 1 < n) return -1;
    for (int i = 0; i < n; i++) x |= (uint64_t) p[1 + i] << (8 * i);
    *v = x;
    *pp = p + 1 + n;
    return 0;
}
