#include "coin/words.h"
#include "coin/bip39_words.h"
#include "coin/xmr_words.h"
#include "wordlist/wl.h"

#define BIP39_TEXT 16384                      /* 2048 words of at most 8 letters and a 0 each: 14.3 KB of English */
#define XMR_TEXT 12288                        /* 1626 words of at most 12 letters: 11.5 KB */

static char     bip39_text[BIP39_TEXT], xmr_text[XMR_TEXT];
static uint16_t bip39_off[BIP39_NWORDS + 1], xmr_off[XMR_NWORDS + 1];
static words_list lists[2];
static int ready;

/* the work memory of the decoder, then the Monero words of their own (their offsets and their text) until they are merged with the BIP39 ones */
static size_t decoder_size(void)
{
    size_t a = wl_work_size(BIP39_EN_AC, sizeof BIP39_EN_AC), b = wl_work_size(XMR_EN_AC, sizeof XMR_EN_AC);
    return ((a > b ? a : b) + 3) & ~(size_t) 3;
}

size_t words_work_size(void)
{
    return decoder_size() + 2 * (XMR_EN_OWN + 1) + XMR_TEXT;
}

int words_init(void *work, size_t worksize)
{
    size_t dec = decoder_size();
    uint16_t *own_off = (uint16_t *) ((uint8_t *) work + dec);
    char *own_text = (char *) (own_off + XMR_EN_OWN + 1);

    if (dec < 4 || worksize < words_work_size()) return -1;
    if (wl_decode(BIP39_EN_AC, sizeof BIP39_EN_AC, work, dec, bip39_text, sizeof bip39_text, bip39_off, BIP39_NWORDS + 1) != BIP39_NWORDS) return -1;
    /* the Monero list: the BIP39 words of the mask and the words of its own, merged (tools/gen_words_ac.py) */
    if (wl_decode(XMR_EN_AC, sizeof XMR_EN_AC, work, dec, own_text, XMR_TEXT, own_off, XMR_EN_OWN + 1) != XMR_EN_OWN) return -1;
    wl_mask_decode(XMR_EN_MASK, sizeof XMR_EN_MASK, BIP39_NWORDS, work);  /* the mask is coded; the memory of the decoder is free again */
    if (wl_merge(bip39_text, bip39_off, BIP39_NWORDS, work, BIP39_NWORDS / 8, own_text, own_off, XMR_EN_OWN, xmr_text, sizeof xmr_text, xmr_off, XMR_NWORDS + 1)
        != XMR_NWORDS) return -1;
    lists[WORDS_BIP39].text = bip39_text;
    lists[WORDS_BIP39].off = bip39_off;
    lists[WORDS_BIP39].n = BIP39_NWORDS;
    lists[WORDS_XMR].text = xmr_text;
    lists[WORDS_XMR].off = xmr_off;
    lists[WORDS_XMR].n = XMR_NWORDS;
    ready = 1;
    return 0;
}

#ifdef PSN00BSDK
#define WORK_AREA ((void *) 0x801B4000u)
#define WORK_SIZE 0x49000u
#else
static uint32_t host_work[(96 * 1024) / 4];
#define WORK_AREA ((void *) host_work)
#define WORK_SIZE sizeof host_work
#endif

int words_prepare(void)
{
    if (ready) return 0;
    if (words_work_size() == 0 || words_work_size() > WORK_SIZE) return -1;
    return words_init(WORK_AREA, WORK_SIZE);
}

const words_list *words_get(int which)
{
    if (!ready && words_prepare()) return NULL;
    return which == WORDS_XMR ? &lists[WORDS_XMR] : &lists[WORDS_BIP39];
}
