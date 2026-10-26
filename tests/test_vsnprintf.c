/* The formatting of card A (hal/psx/vsnprintf.c) against the C library of the host: every kind of conversion the program uses, with random and edge values, and the
 * cutting to a small buffer (the text and the return value). Usage: test_vsnprintf */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int host_snprintf(char *out, size_t size, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = vsnprintf(out, size, f, ap);
    va_end(ap);
    return r;
}

#define vsnprintf psx_vsnprintf
#define vsprintf psx_vsprintf
#define sprintf psx_sprintf
#define snprintf psx_snprintf
#include "../hal/psx/vsnprintf.c"
#undef vsnprintf
#undef vsprintf
#undef sprintf
#undef snprintf

static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

static long cases, bad;

static void same(const char *what, int r1, const char *a, int r2, const char *b)
{
    cases++;
    if (r1 != r2 || strcmp(a, b)) {
        if (bad++ < 10) printf("FAIL %s: [%s] %d, the host [%s] %d\n", what, a, r1, b, r2);
    }
}

#define BOTH(size, ...) do { \
        char a[300], b[300]; \
        memset(a, 'Z', sizeof a); memset(b, 'Z', sizeof b); \
        int r1 = psx_snprintf(a, size, __VA_ARGS__), r2 = host_snprintf(b, size, __VA_ARGS__); \
        if (!(size)) { a[0] = b[0] = 0; } \
        same(#__VA_ARGS__, r1, a, r2, b); \
    } while (0)

int main(void)
{
    static const char *const INTF[] = {"%d", "%u", "%x", "%X", "%02x", "%08x", "%02u", "%2d", "%4d", "%02d", "%3d", "%6d", "%7d", "%8u", "%7u", "%6u", "%04x", "%04u",
                                       "%-6d", "%-8x", "%i", "<%5d>", "%02X", "%0d", "%1u"};
    static const char *const LF[] = {"%lu", "%6lu", "%ld", "%lx"};
    static const char *const LLF[] = {"%llu", "%lld", "%llx", "%20llu", "%-22lld", "%016llx"};
    static const char *const STR[] = {"", "a", "hello", "a longer string with spaces", "árvíztűrő tükörfúrógép"};
    static const char *const SF[] = {"%s", "%10s", "%11s", "%-12s", "%-36s", "%.9s", "%.30s", "%.56s", "%.80s", "[%s|%s]", "%5.2s"};
    static const unsigned EDGE[] = {0, 1, 9, 10, 99, 100, 255, 256, 65535, 65536, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu, 1234567890u};

    for (unsigned i = 0; i < sizeof INTF / sizeof INTF[0]; i++) {
        for (unsigned j = 0; j < sizeof EDGE / sizeof EDGE[0]; j++) { BOTH(300, INTF[i], EDGE[j]); BOTH(300, INTF[i], -(int) EDGE[j]); }
        for (int k = 0; k < 2000; k++) { unsigned v = (unsigned) rnd() >> (rnd() % 32); BOTH(300, INTF[i], v); }
    }
    for (unsigned i = 0; i < sizeof LF / sizeof LF[0]; i++)
        for (int k = 0; k < 2000; k++) { unsigned long v = (unsigned long) (uint32_t) rnd() >> (rnd() % 32); BOTH(300, LF[i], v); }
    for (unsigned i = 0; i < sizeof LLF / sizeof LLF[0]; i++) {
        static const unsigned long long E[] = {0, 1, 10, 0xFFFFFFFFull, 0x100000000ull, 99999999999ull, 0x7FFFFFFFFFFFFFFFull, 0x8000000000000000ull, 0xFFFFFFFFFFFFFFFFull};
        for (unsigned j = 0; j < sizeof E / sizeof E[0]; j++) BOTH(300, LLF[i], E[j]);
        for (int k = 0; k < 5000; k++) { unsigned long long v = rnd() >> (rnd() % 64); BOTH(300, LLF[i], v); }
    }
    for (unsigned i = 0; i < sizeof SF / sizeof SF[0]; i++)
        for (unsigned j = 0; j < sizeof STR / sizeof STR[0]; j++) BOTH(300, SF[i], STR[j], STR[(j + 1) % 5]);
    for (unsigned w = 0; w < 40; w++) { BOTH(300, "%*s|", (int) w, "abc"); BOTH(300, "%.*s|", (int) w, "abcdefghijklmnopqrstuvwxyz"); BOTH(300, "%-*d|", (int) w, -42); }
    BOTH(300, "%c%c%c %5c|%-3c|", 'a', 'b', 'c', 'd', 'e');
    BOTH(300, "%lu %%  -  hold SELECT to cancel", 42ul);
    BOTH(300, "%c Wallet %02x%02x%02x%02x  %d of %d  %s", '>', 0xde, 0xad, 0xbe, 0xef, 2, 3, "Bitcoin");
    BOTH(300, "command %02X, status %02X, error %02X", 0x1b, 0x02, 0x80);
    BOTH(300, "100%% done, %s", "ok");
    for (size_t size = 0; size < 30; size++) { BOTH(size, "%s %d %08x %llu|", "truncated", -123456, 0xCAFEu, 18446744073709551615ull); BOTH(size, "%-20s|", "x"); }
    printf("formatting: %ld cases, %ld wrong\n", cases, bad);
    return bad != 0;
}
