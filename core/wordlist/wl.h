#pragma once
#include <stddef.h>
#include <stdint.h>

/* Word lists packed by tools/wl_pack.py: front coding + an adaptive order-2 arithmetic coder (the layout of the blob is described there).
 * The whole list is decoded at once (the coder is adaptive, there is no random access); the result is kept as UTF-8 and the position of a
 * word is its index. Korean (Hangul) and Japanese (kana + dakuten) are put together from the decomposed form while the words are written. */

/* Working memory the decoder needs for this blob (about 25 KB + 66 bytes per context row of the header); 0 if the header is wrong.
 * The memory must be 4 byte aligned. */
size_t wl_work_size(const uint8_t *blob, size_t len);

/* Decodes all the words of the blob. out: the words in UTF-8, each followed by a 0 byte; off[i]: where word i starts in out, off[n]: the
 * length of out. Returns the number of words, or -1 if the blob is malformed or a buffer is too small. */
int wl_decode(const uint8_t *blob, size_t len, void *work, size_t worksize, char *out, size_t outcap, uint16_t *off, size_t offcap);

/* A Monero list made of two (tools/wl_pack.py merge, tools/data_pack.py 0x05xx): the words of list a whose bit is set in mask (one bit per word, from the low bit),
 * and the words of list b, both ascending in the order of their UTF-8 bytes, written out in that order (the form of wl_decode). Returns the number of words, or -1 if
 * the mask is too short, a buffer is too small or the result is not ascending (damaged data). */
int wl_merge(const char *atext, const uint16_t *aoff, int an, const uint8_t *mask, size_t masklen, const char *btext, const uint16_t *boff, int bn,
             char *out, size_t outcap, uint16_t *off, size_t offcap);

/* The range coder of the lists for other data: bit masks and permutations, the Chinese lists and the Monero masks.
 * The stream may end early: the bytes after len read as 0. */
typedef struct {
    const uint8_t *p, *end;
    uint32_t code, range;
} wl_rc;

void wl_rc_init(wl_rc *r, const uint8_t *src, size_t len);
/* One bit, by the bits before it: c[0] zeros and c[1] ones so far (the estimate (2 c + 1) / (2 n + 2)); counts it in c and returns it. */
int wl_rc_bit(wl_rc *r, unsigned c[2]);
/* Puts a[0..n) in the order the stream gives: for k from n - 1 down to 1, a[k] is swapped with a[j], j < k + 1 each as likely (tools/wl_pack.py enc_shuffle). */
void wl_rc_shuffle(wl_rc *r, uint16_t *a, unsigned n);
/* An n bit mask coded alone (tools/wl_pack.py pack_mask) into mask[(n + 7) / 8], bit i at byte i / 8, from the low bit; returns the number of set bits. */
unsigned wl_mask_decode(const uint8_t *src, size_t len, unsigned n, uint8_t *mask);
