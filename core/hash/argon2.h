#pragma once
/* Argon2id (RFC 9106, version 0x13) with the memory behind callbacks, so that the blocks can live in the main RAM, the VRAM and the SPU RAM of the console
 *. One block is 1024 bytes = 128 little endian 64 bit words. The work buffers are static: not re-entrant. */
#include <stddef.h>
#include <stdint.h>

#define ARGON2_QWORDS 128
#define ARGON2_BLOCK_BYTES 1024

typedef struct {
    void *ctx;
    /* block `index` (0 .. argon2_blocks() - 1; lane * lane_length + column) from / to the memory */
    void (*get)(void *ctx, uint32_t index, uint64_t blk[ARGON2_QWORDS]);
    void (*put)(void *ctx, uint32_t index, const uint64_t blk[ARGON2_QWORDS]);
    /* optional, after every segment (pass, slice) */
    void (*progress)(void *ctx, uint32_t pass, uint32_t slice);
} argon2_mem;

typedef struct {
    uint32_t       t_cost;        /* passes */
    uint32_t       m_cost_kib;    /* memory, KiB: rounded down to a multiple of 4 * lanes */
    uint32_t       lanes;         /* parallelism p (run one after the other here) */
    uint32_t       taglen;        /* 4 .. 1024 bytes */
    const uint8_t *pwd;    size_t pwdlen;
    const uint8_t *salt;   size_t saltlen;
    const uint8_t *secret; size_t secretlen;
    const uint8_t *ad;     size_t adlen;
} argon2_params;

/* The number of 1 KiB blocks the parameters need (0 for bad parameters). */
uint32_t argon2_blocks(const argon2_params *p);
/* 0, or -1 for bad parameters. */
int argon2id(const argon2_params *p, const argon2_mem *mem, uint8_t *tag);

/* The compression function: next = G(prev, ref), with_xor: next = G(prev, ref) ^ next (the old content). `next` may not overlap prev or ref. */
void argon2_fill_block(uint64_t next[ARGON2_QWORDS], const uint64_t prev[ARGON2_QWORDS], const uint64_t ref[ARGON2_QWORDS], int with_xor);
