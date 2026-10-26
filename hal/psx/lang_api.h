#pragma once
#include <stddef.h>
#include <stdint.h>
#include "gpu.h"
#include "input.h"

/* What the language module (lang_ui.c, the overlay in group 2 of the package on the B card) offers the generator once a language is switched on.
 * The generator calls it through psxx_lang, which is NULL while no language is on (and is reset whenever the slot of the module is wiped, ldr_forget_slot). The module keeps the word
 * indexes of the last mnemonic itself and shows them with the right glyphs; the generator only has the sentence that goes into the seed. A call that returns -2 means the
 * language has nothing for it (no list of that kind): the generator then does what it did before, in English. */
typedef struct {
    /* BIP39: the mnemonic of the entropy ent[len] in this language; the sentence (NFKD, a space between the words, what goes into the seed) is written to sentence. Returns the
     * number of words, -1 if the language has no BIP39 list. */
    int (*mnemonic)(const uint8_t *ent, int len, char *sentence, size_t cap);
    /* Monero: the 25 words of the key that the English words encode (the same key, the checksum word is the one of this language). 0, or -1 if there is no Monero list. */
    int (*monero)(const char *english);
    /* The words of the last mnemonic() / monero() call on the screen, in pages; then, after the user held the buttons, the check questions. note: shown top right.
     * 0 when it was all confirmed (the words are forgotten), 1 if the user asked to save the key to the card (Monero), -2 if there is nothing kept for that kind. */
    int (*show)(RenderContext *ctx, input_state *in, int xmr, const char *note);
    /* Typing a mnemonic of n words in this language: xmr 0 a BIP39 mnemonic (its sentence goes to `sentence`, the entropy to ent, the length of the entropy, 16 .. 32, is returned),
     * xmr 1 the 25 words of Monero (the key, 32 bytes, goes to ent, 32 is returned). -1 if the user gave up, -2 if the language has no list of that kind. */
    int (*restore)(RenderContext *ctx, input_state *in, int xmr, int n, char *sentence, size_t cap, uint8_t ent[32]);
    /* forget the words that were kept */
    void (*wipe)(void);
    const char *name;
    uint8_t id;                         /* the language id (core/lang/lang.h, 1 .. 14): the 4 bits of a saved BIP39 key say which words its seed was made from */
} lang_api;

extern const lang_api *psxx_lang;
