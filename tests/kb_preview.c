/* The on-screen keyboard (hal/psx/keyboard.c) drawn to PNG files on the host: the real font and button icons of the console, the rectangles in the order the console draws them (a higher
 * slot first), the picture of 640 x 240 shown with doubled lines as a TV shows it (4 : 3).  kb_preview [directory]  writes kb_*.png there (default build/kbview).
 * Not a test: it is there to look at a change of the keyboard before it goes on a card. */
#include "pix_render.h"
#include "keyboard.h"
#include "pad.h"
#include "ui_text.h"

/* ---- the scenes ---- */

static RenderContext ctx;

static void shot(const char *dir, const char *name, const kb_state *k)
{
	char path[512];
	kb_draw(&ctx, k);
	render();
	snprintf(path, sizeof path, "%s/%s.png", dir, name);
	write_png(path);
	printf("%s\n", path);
}

/* the byte offset of the character with index c */
static int off_of_char(const char *t, int c) { int o = 0; while (t[o] && c > 0) { do o++; while (t[o] && ((unsigned char) t[o] & 0xC0) == 0x80); c--; } return o; }

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "build/kbview";
	static kb_state k;
	const char *poem = "A longer text that the keyboard wraps into several lines, because the upper window shows one line only. Enter starts a new line.\n"
	                   "	Second paragraph with a tab.\n\nThird, short line.";

	/* the accent strip, the key o, an entry in the middle of the list */
	kb_init(&k, "Label (shown with the password)", NULL, 0, 1);
	kb_set(&k, 400, 0);
	k.row = 1; k.idx = 8;                                        /* the key o */
	k.var = 11;
	shot(dir, "kb_accent_mid", &k);
	k.var = 0;
	shot(dir, "kb_accent_first", &k);
	k.var = 20;
	shot(dir, "kb_accent_late", &k);

	/* a text of several lines, the cursor in the second line: the counters, the line keys */
	kb_init(&k, "Text to encrypt", poem, 0, 1);
	k.multiline = 1;
	kb_set(&k, 400, 0);
	k.cur = off_of_char(k.text, 70);
	k.row = 3; k.idx = 8;                                        /* the cursor-up key */
	shot(dir, "kb_lines", &k);

	/* overwrite on (the Ins key lit, a block cursor) */
	k.ovr = 1;
	shot(dir, "kb_overwrite", &k);
	k.ovr = 0;

	/* a field of one line (a password, a label): Enter and Tab are off */
	k.multiline = 0;
	shot(dir, "kb_single", &k);
	k.multiline = 1;

	/* the symbols layer: Enter instead of the line down key */
	k.sym = 1;
	k.row = 4; k.idx = 5;
	shot(dir, "kb_symbols", &k);

	/* the full view of the same text */
	k.sym = 0; k.full = 1; k.row = 1; k.idx = 0;
	shot(dir, "kb_full", &k);
	k.nowrap = 1;                                                /* L1: no wrapping, the long line scrolls sideways */
	k.cur = off_of_char(k.text, 100);
	shot(dir, "kb_full_nowrap", &k);
	return 0;
}
