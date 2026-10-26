#pragma once
#include "gpu.h"
#include "input.h"

/* The language module: an overlay, group 2 of the package on the B card, loaded by the generator's Language item (ldr_call_args). Choose a language, read its groups from the data card in either slot (the source screens of source_ui.c: Auto / slot 1 / slot 2, the
 * card watch, the progress bar), and look at its word lists, drawn with the right glyphs (hanzi, hangul, kana, Cyrillic), and at test mnemonics whose checksum words are computed
 * in that language. A modal screen: it runs its own loop and returns when the user leaves. The module stays in memory in its slot (memmap.h) with the language that was read: calling it again
 * shows the index with that language marked and opens it without the card; the data of the language is in the data pocket (and what does not fit there, above the module in its slot),
 * the decoders work in the scratch pocket. START in the viewer switches the language on (psxx_lang), the square button on the index switches it off. */
int ovl_main(RenderContext *ctx, input_state *in, int hz);
