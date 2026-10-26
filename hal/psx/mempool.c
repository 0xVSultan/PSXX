#include "mempool.h"
#include <string.h>
#include <psxgpu.h>
#include <psxetc.h>
#include <hwregs_c.h>

#define GPU_READY_CMD_DMA 0x14000000u    /* GPUSTAT bit 26 ready for a command word, bit 28 ready for a DMA block */
#define GPU_READY_SEND 0x08000000u       /* bit 27: ready to send VRAM to the CPU */

static void gpu_idle(void)
{
	for (int i = 0; i < 1000000; i++)
		if (!(DMA_CHCR(DMA_GPU) & (1u << 24)) && (GPU_GP1 & GPU_READY_CMD_DMA) == GPU_READY_CMD_DMA) return;
}

static void vram_xy(int block, int *x, int *y)
{
	*x = VRAM_POOL_X + (block & 3) * 64;
	*y = (block >> 2) * 8;
}

static void vram_cmd(uint32_t cmd, int x, int y)
{
	gpu_idle();
	GPU_GP0 = cmd;
	GPU_GP0 = ((uint32_t) y << 16) | (uint32_t) x;
	GPU_GP0 = (8u << 16) | 64u;                                         /* 64 x 8 pixels = 512 halfwords = 256 words */
}

void vram_pool_write(int block, const void *src, int mode)
{
	const uint32_t *w = src;
	int x, y;

	vram_xy(block, &x, &y);
	vram_cmd(0xA0000000u, x, y);
	if (mode == VRAM_DMA) {
		GPU_GP1 = 0x04000002;                                           /* DMA direction: CPU -> GP0 */
		DMA_MADR(DMA_GPU) = (uint32_t) src & 0x00FFFFFF;
		DMA_BCR(DMA_GPU) = (16u << 16) | 16u;                           /* 16 blocks of 16 words */
		DMA_CHCR(DMA_GPU) = 0x01000201;
		for (int i = 0; i < 1000000 && (DMA_CHCR(DMA_GPU) & (1u << 24)); i++) {}
	} else {
		for (int i = 0; i < 256; i++) GPU_GP0 = w[i];
	}
	gpu_idle();
}

void vram_pool_read(int block, void *dst, int mode)
{
	uint32_t *w = dst;
	int x, y;

	vram_xy(block, &x, &y);
	vram_cmd(0xC0000000u, x, y);
	if (mode == VRAM_DMA) {
		GPU_GP1 = 0x04000003;                                           /* DMA direction: GPUREAD -> CPU */
		DMA_MADR(DMA_GPU) = (uint32_t) dst & 0x00FFFFFF;
		DMA_BCR(DMA_GPU) = (16u << 16) | 16u;
		DMA_CHCR(DMA_GPU) = 0x01000200;
		for (int i = 0; i < 1000000 && (DMA_CHCR(DMA_GPU) & (1u << 24)); i++) {}
		GPU_GP1 = 0x04000002;
	} else {
		for (int i = 0; i < 256; i++) {
			for (int n = 0; n < 100000 && !(GPU_GP1 & GPU_READY_SEND); n++) {}
			w[i] = GPU_GP0;                                             /* GPUREAD is at the address of GP0 */
		}
	}
	gpu_idle();
}

/* ---- the SPU RAM ---- */

static int spu_mode(int mode)
{
	SPU_CTRL = (uint16_t) ((SPU_CTRL & ~0x0030) | (mode << 4));
	for (int i = 0; i < 100000; i++)
		if ((SPU_STAT & 0x0030) == (mode << 4)) return 0;
	return -1;
}

void spu_pool_init(void)
{
	SPU_KEY_OFF1 = 0xFFFF;
	SPU_KEY_OFF2 = 0xFFFF;
	SPU_MASTER_VOL_L = 0;
	SPU_MASTER_VOL_R = 0;
	SPU_CTRL = 0xC000;                                                  /* enabled, not muted; no reverb, no CD audio, no IRQ, transfer mode stop */
	SPU_DMA_CTRL = 0x0004;
	DMA_DPCR |= 0x00080000;                                             /* channel 4 (SPU) enabled */
	for (int i = 0; i < 100000; i++) if ((SPU_STAT & 0x003F) == (SPU_CTRL & 0x003F)) break;
}

static int spu_transfer(uint32_t spu_addr, void *buf, uint32_t bytes, int write)
{
	int bad = 0;

	SPU_DMA_CTRL = 0x0004;
	SPU_ADDR = (uint16_t) (spu_addr >> 3);
	if (spu_mode(write ? 2 : 3)) bad = -1;
	DMA_MADR(DMA_SPU) = (uint32_t) buf & 0x00FFFFFF;
	DMA_BCR(DMA_SPU) = ((bytes / 64) << 16) | 16u;
	DMA_CHCR(DMA_SPU) = write ? 0x01000201 : 0x01000200;
	for (int i = 0; i < 1000000 && (DMA_CHCR(DMA_SPU) & (1u << 24)); i++) if (i == 999999) bad = -1;
	for (int i = 0; i < 100000 && (SPU_STAT & 0x0400); i++) if (i == 99999) bad = -1;
	if (spu_mode(0)) bad = -1;
	return bad;
}

int spu_pool_write(uint32_t spu_addr, const void *src, uint32_t bytes) { return spu_transfer(spu_addr, (void *) src, bytes, 1); }
int spu_pool_read(uint32_t spu_addr, void *dst, uint32_t bytes) { return spu_transfer(spu_addr, dst, bytes, 0); }

/* ---- the Argon2 memory ---- */

static void mp_get(void *ctx, uint32_t i, uint64_t b[ARGON2_QWORDS])
{
	mempool *mp = ctx;

	if (mp->poke) mp->poke();
	if (i < mp->ram_blocks) { memcpy(b, mp->ram + (size_t) i * ARGON2_QWORDS, ARGON2_BLOCK_BYTES); mp->n_ram++; }
	else if (i < mp->ram_blocks + mp->vram_blocks) { vram_pool_read((int) (i - mp->ram_blocks), b, mp->vram_mode); mp->n_vram++; }
	else { spu_pool_read(SPU_POOL_BASE + (i - mp->ram_blocks - mp->vram_blocks) * ARGON2_BLOCK_BYTES, b, ARGON2_BLOCK_BYTES); mp->n_spu++; }
}

static void mp_put(void *ctx, uint32_t i, const uint64_t b[ARGON2_QWORDS])
{
	mempool *mp = ctx;

	if (mp->poke) mp->poke();
	if (i < mp->ram_blocks) { memcpy(mp->ram + (size_t) i * ARGON2_QWORDS, b, ARGON2_BLOCK_BYTES); mp->n_ram++; }
	else if (i < mp->ram_blocks + mp->vram_blocks) { vram_pool_write((int) (i - mp->ram_blocks), b, mp->vram_mode); mp->n_vram++; }
	else { spu_pool_write(SPU_POOL_BASE + (i - mp->ram_blocks - mp->vram_blocks) * ARGON2_BLOCK_BYTES, b, ARGON2_BLOCK_BYTES); mp->n_spu++; }
}

void mempool_mem(mempool *mp, argon2_mem *out)
{
	out->ctx = mp;
	out->get = mp_get;
	out->put = mp_put;
	out->progress = NULL;
}
