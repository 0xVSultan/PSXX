/* keccak.c and the permutation under other names and other compiler options (see vb_rename_g.h); the state in the scratchpad on the PSX */
#include "vb_rename_g.h"
#ifdef __mips__
#define KECCAK_SCRATCH 1
#endif
#include "../../core/hash/keccak_fast.c"
#include "../../core/hash/keccak.c"
