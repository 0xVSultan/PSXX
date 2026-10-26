#include "ur.h"

/* The 256 bytewords of BCR-2020-012 (list from Blockchain Commons bc-ur, BSD-2-Clause-Patent) in their minimal form, the first and the last letter, which is all
 * the UR text of this program uses ("able" is "ae"). */
static const char WORDS[] = "aeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackctcxclcpcndkdadsdidedtdrdndwdpdmdldyeheyeoeeecenemetesftfrfnfsfmfhfzfpfwfxfyfefgflfdgagegrgsgtglgwgdgygmgughgohfhghdhkhthphhhlhyhehnhsidiaieihiyioisinimjejzjnjtjljojsjpjkjykpkoktkskkknkgkekikblblalylflslrlplnltloldlelulklgmnmymhmemomumwmdmtmsmknlnyndnsntnnnenboyoeotoxonolospdptpkpypspmplpepfpaprqdqzrerprlrorhrdrkrfryrnrsrtsesasrssskswstspsosgsbsfsntotktitttdtetytltbtstptatnuyuoutueurvtvyvovlvevwvavdvswlwdwmwpwewywswtwnwzwfwkykynylyaytzszoztzczezm";

uint32_t ur_crc32(const uint8_t *p, size_t n)
{
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < n; i++) {
		c ^= p[i];
		for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
	}
	return ~c;
}

/* CBOR head of a byte string of n bytes / unsigned integer v (major type in the top bits of `major`). */
static int cbor_head(uint8_t *o, uint8_t major, uint32_t v)
{
	if (v < 24) { o[0] = (uint8_t) (major | v); return 1; }
	if (v < 256) { o[0] = (uint8_t) (major | 24); o[1] = (uint8_t) v; return 2; }
	if (v < 65536) { o[0] = (uint8_t) (major | 25); o[1] = (uint8_t) (v >> 8); o[2] = (uint8_t) v; return 3; }
	o[0] = (uint8_t) (major | 26);
	o[1] = (uint8_t) (v >> 24); o[2] = (uint8_t) (v >> 16); o[3] = (uint8_t) (v >> 8); o[4] = (uint8_t) v;
	return 5;
}

/* Byte i of the whole message: CBOR byte string head, then the data. */
static uint8_t msg_byte(const ur_plan *p, const uint8_t *data, size_t i, const uint8_t *hd, int hl)
{
	if (i < (size_t) hl) return hd[i];
	i -= (size_t) hl;
	return i < p->data_len ? data[i] : 0;
}

int ur_plan_make(ur_plan *p, const uint8_t *data, size_t n, size_t max_frag)
{
	uint8_t hd[5];
	if (n == 0 || max_frag < 8) return -1;
	int hl = cbor_head(hd, 0x40, (uint32_t) n);
	p->data_len = n;
	p->cbor_len = n + (size_t) hl;
	/* UR: fragment length = ceil(length / ceil(length / max)) */
	size_t cnt = (p->cbor_len + max_frag - 1) / max_frag;
	p->parts = (unsigned) cnt;
	p->frag_len = (p->cbor_len + cnt - 1) / cnt;
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < p->cbor_len; i++) {
		c ^= msg_byte(p, data, i, hd, hl);
		for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
	}
	p->crc = ~c;
	return (int) p->parts;
}

static int uint_len(uint32_t v) { return v < 24 ? 1 : v < 256 ? 2 : v < 65536 ? 3 : 5; }

size_t ur_part_chars(const ur_plan *p)
{
	if (p->parts == 1) return 9 + 2 * (p->cbor_len + 4);
	size_t seq = (size_t) uint_len(p->parts), digs = p->parts >= 1000 ? 4 : p->parts >= 100 ? 3 : p->parts >= 10 ? 2 : 1;
	size_t body = 1 + seq + (size_t) uint_len(p->parts) + (size_t) uint_len((uint32_t) p->cbor_len) + 5 +
	              (size_t) uint_len((uint32_t) p->frag_len) + p->frag_len + 4;
	return 9 + 2 * digs + 2 + 2 * body;
}

typedef struct { char *o; size_t cap, n; uint32_t crc; } bw;

static void bw_byte(bw *w, uint8_t b)
{
	if (w->n + 2 < w->cap) { w->o[w->n] = WORDS[2 * b]; w->o[w->n + 1] = WORDS[2 * b + 1]; }
	w->n += 2;
}

static void bw_crc(bw *w, uint8_t b)
{
	w->crc ^= b;
	for (int k = 0; k < 8; k++) w->crc = (w->crc >> 1) ^ (0xEDB88320u & (0u - (w->crc & 1u)));
	bw_byte(w, b);
}

static void put_str(bw *w, const char *s)
{
	while (*s) { if (w->n + 1 < w->cap) w->o[w->n] = *s; w->n++; s++; }
}

static void put_uint(bw *w, uint32_t v)
{
	char t[11];
	int k = 0;
	do { t[k++] = (char) ('0' + v % 10); v /= 10; } while (v);
	while (k) { if (w->n + 1 < w->cap) w->o[w->n] = t[--k]; else --k; w->n++; }
}

static void bw_finish(bw *w)
{
	uint32_t c = ~w->crc;
	for (int i = 3; i >= 0; i--) bw_byte(w, (uint8_t) (c >> (8 * i)));
}

int ur_part(const ur_plan *p, const uint8_t *data, unsigned seq, char *out, size_t cap)
{
	bw w = { out, cap, 0, 0xFFFFFFFFu };
	uint8_t hd[5], t[5];
	int hl = cbor_head(hd, 0x40, (uint32_t) p->data_len);
	put_str(&w, "ur:bytes/");
	if (p->parts == 1) {
		for (size_t i = 0; i < p->cbor_len; i++) bw_crc(&w, msg_byte(p, data, i, hd, hl));
	} else {
		unsigned s = (seq ? (seq - 1) % p->parts : 0) + 1;
		put_uint(&w, s); put_str(&w, "-"); put_uint(&w, p->parts); put_str(&w, "/");
		bw_crc(&w, 0x85);
		int k = cbor_head(t, 0x00, s);            for (int i = 0; i < k; i++) bw_crc(&w, t[i]);
		k = cbor_head(t, 0x00, p->parts);         for (int i = 0; i < k; i++) bw_crc(&w, t[i]);
		k = cbor_head(t, 0x00, (uint32_t) p->cbor_len); for (int i = 0; i < k; i++) bw_crc(&w, t[i]);
		k = cbor_head(t, 0x00, p->crc);           for (int i = 0; i < k; i++) bw_crc(&w, t[i]);
		k = cbor_head(t, 0x40, (uint32_t) p->frag_len); for (int i = 0; i < k; i++) bw_crc(&w, t[i]);
		for (size_t i = 0; i < p->frag_len; i++) bw_crc(&w, msg_byte(p, data, (size_t) (s - 1) * p->frag_len + i, hd, hl));
	}
	bw_finish(&w);
	if (w.n + 1 > cap) return -1;
	out[w.n] = 0;
	return (int) w.n;
}

int ur_bytewords_decode(const char *s, size_t n, uint8_t *out, size_t cap)
{
	if (n < 10 || (n & 1)) return -1;
	size_t cnt = n / 2;
	if (cnt - 4 > cap) return -1;
	for (size_t i = 0; i < cnt; i++) {
		int b = -1;
		for (int j = 0; j < 256; j++)
			if (WORDS[2 * j] == s[2 * i] && WORDS[2 * j + 1] == s[2 * i + 1]) { b = j; break; }
		if (b < 0) return -1;
		if (i < cnt - 4) out[i] = (uint8_t) b;
		else if ((uint8_t) b != (uint8_t) (ur_crc32(out, cnt - 4) >> (8 * (cnt - 1 - i)))) return -1;
	}
	return (int) (cnt - 4);
}
