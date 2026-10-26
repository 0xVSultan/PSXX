#pragma once
#include <stdint.h>
#include "hash/argon2.h"

/* The memory behind an Argon2id run: 1 KiB blocks in the main RAM, in the VRAM (a strip beside the picture) and in the SPU RAM.
 * Everything is polled (no interrupts: from a FreePSXBoot card the kernel swallows the DMA IRQs), the GPU and the SPU are driven through their registers. */

enum { VRAM_PIO = 0, VRAM_DMA = 1 };

#define VRAM_POOL_X 640                  /* the strip x 640..895, y 0..511: four blocks (64 x 8 pixels of 16 bit) per row of blocks, 64 rows */
#define VRAM_POOL_BLOCKS 256
#define SPU_POOL_BASE 0x1000             /* the first 4 KB of the SPU RAM are the capture buffers */
#define SPU_POOL_BLOCKS 508

/* The SPU: voices keyed off, enabled and unmuted, no reverb, no CD audio, no IRQ. */
void spu_pool_init(void);
/* bytes: a multiple of 64; spu_addr a multiple of 8; the main RAM buffer word aligned. Both return 0, or -1 when the SPU did not answer in time. */
int spu_pool_write(uint32_t spu_addr, const void *src, uint32_t bytes);
int spu_pool_read(uint32_t spu_addr, void *dst, uint32_t bytes);

void vram_pool_write(int block, const void *src, int mode);       /* 1024 bytes, word aligned */
void vram_pool_read(int block, void *dst, int mode);

typedef struct {
    uint64_t *ram;                       /* ram_blocks blocks */
    uint32_t  ram_blocks, vram_blocks, spu_blocks;
    int       vram_mode;
    uint32_t  n_ram, n_vram, n_spu;      /* accesses per tier */
    void    (*poke)(void);               /* optional, called at every access (the stopwatch of a probe) */
} mempool;

/* argon2_mem whose blocks 0 .. ram_blocks - 1 are in the RAM, the next vram_blocks in the VRAM, the next spu_blocks in the SPU RAM */
void mempool_mem(mempool *mp, argon2_mem *out);
