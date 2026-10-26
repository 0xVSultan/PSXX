/* The formatting of card A and its overlays instead of the SDK's (4.5 KB): only what the program uses. Conversions d i u x X c s and %%,
 * the flags - and 0, a width (a number or *), a precision for s (.N or .*), the lengths l and ll (long is 32 bits). Anything else is written as it stands. The return value
 * is the length of the whole result, also when it is cut to `size` (C99). tests/test_vsnprintf.c compares it with the C library of the host. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

int vsnprintf(char *out, size_t size, const char *f, va_list ap);
int vsprintf(char *out, const char *f, va_list ap);
int sprintf(char *out, const char *f, ...);
int snprintf(char *out, size_t size, const char *f, ...);

int vsnprintf(char *out, size_t size, const char *f, va_list ap)
{
    size_t n = 0;

#define PUT(c) do { if (n + 1 < size) out[n] = (char) (c); n++; } while (0)
    for (; *f; f++) {
        int left = 0, zero = 0, w = 0, prec = -1, lng = 0, len, neg = 0;
        char buf[24], *s, c;

        if (*f != '%') { PUT(*f); continue; }
        for (; f[1] == '-' || f[1] == '0'; f++) { if (f[1] == '-') left = 1; else zero = 1; }
        f++;
        if (*f == '*') { w = va_arg(ap, int); f++; if (w < 0) { left = 1; w = -w; } }
        else while (*f >= '0' && *f <= '9') w = w * 10 + *f++ - '0';
        if (*f == '.') {
            f++;
            prec = 0;
            if (*f == '*') { prec = va_arg(ap, int); f++; }
            else while (*f >= '0' && *f <= '9') prec = prec * 10 + *f++ - '0';
        }
        while (*f == 'l') { lng++; f++; }
        c = *f;
        if (c == 's') {
            s = va_arg(ap, char *);
            if (!s) s = "(null)";
            for (len = 0; s[len] && (prec < 0 || len < prec); len++) ;
            zero = 0;
        } else if (c == 'c') {
            buf[0] = (char) va_arg(ap, int);
            s = buf;
            len = 1;
            zero = 0;
        } else if (c == 'd' || c == 'i' || c == 'u' || c == 'x' || c == 'X') {
            unsigned base = c == 'x' || c == 'X' ? 16 : 10;
            const char *dig = c == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
            unsigned long long v = lng > 1 ? va_arg(ap, unsigned long long) : (unsigned long long) va_arg(ap, unsigned);

            if (c == 'd' || c == 'i') {
                long long sv = lng > 1 ? (long long) v : (long long) (int) v;
                if (sv < 0) { neg = 1; v = (unsigned long long) -sv; }
            }
            s = buf + sizeof buf;
            do { *--s = dig[v % base]; v /= base; } while (v);
            len = (int) (buf + sizeof buf - s);
            if (neg) {
                if (zero) { PUT('-'); w--; }
                else { *--s = '-'; len++; }
            }
        } else {                                                 /* %% and what is not known: the character itself */
            if (c != '%') PUT('%');
            if (!c) break;
            PUT(c);
            continue;
        }
        if (!left) for (; w > len; w--) PUT(zero ? '0' : ' ');
        for (int i = 0; i < len; i++) PUT(s[i]);
        for (; w > len; w--) PUT(' ');
    }
    if (size) out[n < size ? n : size - 1] = 0;
#undef PUT
    return (int) n;
}

int vsprintf(char *out, const char *f, va_list ap) { return vsnprintf(out, (size_t) -1 >> 1, f, ap); }

int sprintf(char *out, const char *f, ...)
{
    va_list ap;
    int r;

    va_start(ap, f);
    r = vsnprintf(out, (size_t) -1 >> 1, f, ap);
    va_end(ap);
    return r;
}

int snprintf(char *out, size_t size, const char *f, ...)
{
    va_list ap;
    int r;

    va_start(ap, f);
    r = vsnprintf(out, size, f, ap);
    va_end(ap);
    return r;
}
