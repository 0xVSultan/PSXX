/* The 64 bit division of card A (hal/psx/divdi3.c) against the division of the host: random numbers of every size, the 32 bit fast path, the divisors of the callers
 * (10, 58, 1626, 10^8, 10^9), quotients of 0 and 1, the largest numbers. Usage: test_divdi3 */
#include <stdint.h>
#include <stdio.h>
#define __udivdi3 psx_udivdi3
#define __umoddi3 psx_umoddi3
#include "../hal/psx/divdi3.c"

static uint64_t s = 88172645463325252ull;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }

static long n, bad;

static void one(uint64_t a, uint64_t b)
{
    if (!b) return;
    n++;
    if (psx_udivdi3(a, b) != a / b || psx_umoddi3(a, b) != a % b) {
        if (bad++ < 5) printf("FAIL %llu / %llu\n", (unsigned long long) a, (unsigned long long) b);
    }
}

int main(void)
{
    static const uint64_t D[] = {1, 2, 3, 10, 58, 1626, 100000000ull, 1000000000ull, 0xFFFFFFFFull, 0x100000000ull, 0xFFFFFFFFFFFFFFFFull, 0x8000000000000000ull};

    for (unsigned i = 0; i < sizeof D / sizeof D[0]; i++)
        for (unsigned j = 0; j < sizeof D / sizeof D[0]; j++) { one(D[i], D[j]); one(D[i] - 1, D[j]); one(D[i] + 1, D[j]); }
    for (int i = 0; i < 3000000; i++) {
        uint64_t a = rnd(), b = rnd();
        switch (rnd() % 8) {
        case 1: b >>= rnd() % 64; break;
        case 2: a >>= rnd() % 64; break;
        case 3: a >>= 32; b >>= 32 + rnd() % 32; break;
        case 4: b = rnd() % 100 + 1; break;
        case 5: b = D[rnd() % (sizeof D / sizeof D[0])]; break;
        case 6: b = 1626; a >>= rnd() % 40; break;
        case 7: b = a - rnd() % 3; break;
        }
        one(a, b);
    }
    printf("64 bit division: %ld cases, %ld wrong\n", n, bad);
    return bad != 0;
}
