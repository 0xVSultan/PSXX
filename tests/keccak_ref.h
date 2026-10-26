#pragma once
/* The compact reference Keccak-f[1600] (loops over lanes, tables): what core/hash/keccak.c used before the 32 bit pair
 * version; kept for the tests and the benchmark. */
#include <stdint.h>

static const uint64_t KRC[24] = {
 0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
 0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
 0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
 0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
 0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
 0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const uint8_t KROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const uint8_t KPILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
#define KROL(x,n) (((x) << (n)) | ((x) >> (64 - (n))))

static void ref_f1600(uint64_t st[25])
{
	uint64_t bc[5], t;
	for (int r = 0; r < 24; r++) {
		for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
		for (int i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ KROL(bc[(i + 1) % 5], 1);
			for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
		}
		t = st[1];
		for (int i = 0; i < 24; i++) {
			int j = KPILN[i];
			bc[0] = st[j];
			st[j] = KROL(t, KROTC[i]);
			t = bc[0];
		}
		for (int j = 0; j < 25; j += 5) {
			for (int i = 0; i < 5; i++) bc[i] = st[j + i];
			for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}
		st[0] ^= KRC[r];
	}
}


/* the byte by byte keccak256 that core/hash/keccak.c used before */
static void ref_keccak256(const uint8_t *msg, size_t len, uint8_t out[32])
{
	enum { RATE = 136 };
	uint64_t st[25] = {0};
	uint8_t blk[RATE];

	while (len >= RATE) {
		for (int i = 0; i < RATE / 8; i++) {
			uint64_t v = 0;
			for (int j = 7; j >= 0; j--) v = (v << 8) | msg[8*i + j];
			st[i] ^= v;
		}
		ref_f1600(st);
		msg += RATE; len -= RATE;
	}
	for (int i = 0; i < RATE; i++) blk[i] = 0;
	for (size_t i = 0; i < len; i++) blk[i] = msg[i];
	blk[len] ^= 0x01;
	blk[RATE - 1] ^= 0x80;
	for (int i = 0; i < RATE / 8; i++) {
		uint64_t v = 0;
		for (int j = 7; j >= 0; j--) v = (v << 8) | blk[8*i + j];
		st[i] ^= v;
	}
	ref_f1600(st);
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(st[i / 8] >> (8 * (i % 8)));
}
