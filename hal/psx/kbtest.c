/* Keyboard test: the on-screen keyboard in accent mode (Latin-1 / Extended-A/B variants through L1 / L2), plain mode on a second
 * press of START. Shows the typed text as UTF-8 afterwards. For emulator runs of the keyboard widget. */
#include <string.h>
#include <psxgpu.h>
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "keyboard.h"
#include "timer.h"
#include "ui_text.h"
#include "ui_ids.h"

static RenderContext ctx;
static input_state   in;
static kb_state      kb;

int main(void)
{
	int last_frame = -1, accents = 1, done = 0;
	char result[KB_MAX + 1] = "";

	ui_reg_a();
	gpu_init(&ctx, 20, 20, 60);
	font_init(1);
	ticks_init();
	input_init(&in);
	kb_init(&kb, "Keyboard test (accents)", NULL, 0, accents);

	for (;;) {
		input_poll(&in, NULL);
		int f = VSync(-1);
		if (f == last_frame) continue;
		last_frame = f;
		uint16_t pr = input_take_pressed(&in);
		if (!done) {
			int r = kb_update(&kb, pr);
			if (r != KB_EDITING) {
				strcpy(result, kb.text);
				done = 1;
			} else {
				kb_draw(&ctx, &kb);
			}
		}
		if (done) {
			font_draw(&ctx, 0, 16, 16, "You typed:", 150, 160, 200);
			font_draw(&ctx, 0, 16, 40, result, 255, 255, 255);
			font_draw(&ctx, 0, 16, 80, "Latin-1:  \xc3\xa1\xc3\xa9\xc3\xad\xc3\xb3\xc3\xb6\xc5\x91\xc3\xba\xc3\xbc\xc5\xb1 \xc3\x81\xc3\x89\xc3\x8d\xc3\x93\xc3\x96\xc5\x90\xc3\x9a\xc3\x9c\xc5\xb0", 255, 255, 255);
			font_draw(&ctx, 0, 16, 100, ICO_CROSS " new text", 150, 160, 200);
			if (pr & PAD_CROSS) {
				kb_wipe(&kb);
				kb_init(&kb, "Keyboard test (accents)", NULL, 0, accents);
				done = 0;
			}
		}
		gpu_present(&ctx);
	}
	return 0;
}
