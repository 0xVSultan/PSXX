/* The same permutation with the state in main RAM, for the benchmark (the PSX build keeps it in the scratchpad). */
#undef KECCAK_SCRATCH
#define keccak_f1600 keccak_f1600_ram
#include "../../core/hash/keccak_fast.c"
