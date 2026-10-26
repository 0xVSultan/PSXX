/* The unsigned 64 bit division of the compiler (libgcc's __udivdi3 and __umoddi3), one bit per step: 288 bytes instead of the 3 KB of libgcc with its table
 *. The callers are the formatting of amounts and times, base58 and the Monero words, none of them in a hot loop; a division of two
 * 32 bit numbers goes to the divider of the CPU. Linked into card A only, the overlays call these (gen_exports.cmake); tests/test_divdi3.c checks them on the host. */
#include <stdint.h>

static uint64_t udivmod(uint64_t n, uint64_t d, int want_rem)
{
    uint32_t nh = (uint32_t) (n >> 32), nl = (uint32_t) n, dh = (uint32_t) (d >> 32), dl = (uint32_t) d, rh = 0, rl = 0, qh = 0, ql = 0;

    if (!nh && !dh) return want_rem ? nl % dl : nl / dl;
    for (int i = 0; i < 64; i++) {
        rh = (rh << 1) | (rl >> 31); rl = (rl << 1) | (nh >> 31);         /* r = r << 1 | the top bit of n */
        nh = (nh << 1) | (nl >> 31); nl <<= 1;
        qh = (qh << 1) | (ql >> 31); ql <<= 1;
        if (rh > dh || (rh == dh && rl >= dl)) {                           /* r >= d: subtract, the bit of q is 1 */
            rh -= dh + (rl < dl); rl -= dl; ql |= 1;
        }
    }
    return want_rem ? ((uint64_t) rh << 32 | rl) : ((uint64_t) qh << 32 | ql);
}

uint64_t __udivdi3(uint64_t n, uint64_t d);
uint64_t __umoddi3(uint64_t n, uint64_t d);
uint64_t __udivdi3(uint64_t n, uint64_t d) { return udivmod(n, d, 0); }
uint64_t __umoddi3(uint64_t n, uint64_t d) { return udivmod(n, d, 1); }
