/* The console as far as the screens of tests/test_screens_a.c see it, with a picture instead of the layout check: the program built from it (ui_preview) runs the same screens and
 * writes some of their frames as PNG files (tests/pix_render.h), to look at a change of the screens. Not a test.
 *   PIX_DIR    the directory of the PNG files; without it nothing is written (the program only runs)
 *   PIX_NAMES  the names of the frames (the names the test gives them, "secret key", "what to create" ...), separated by commas; the default is every name
 *   PIX_MAX    how many frames of one name are written (default 1)
 * Only the English pass on a 240 line picture is written. */
#define PIX_NO_VSYNC
#include <stdio.h>
#include <string.h>
#include "layout_check.h"
#include "pix_render.h"
#include "gpu.h"
#include "input.h"
#include "timer.h"
#include <psxgpu.h>

int screen_yres = 240;
int gpu_fade = 256;
static int vframe;
int lc_bad, lc_frames;
const char *lc_tag = "";
int (*lc_ext_width)(int cp);

int VSync(int mode) { (void) mode; return ++vframe; }
int GetVideoMode(void) { return screen_yres > 240 ? MODE_PAL : MODE_NTSC; }
void lc_snapshot(int on) { (void) on; }
int lc_width(const char *s) { return font_width(s); }
void lc_text(int x, int y, const char *s) { (void) x; (void) y; (void) s; }
void lc_rect(int x, int y, int w, int h) { (void) x; (void) y; (void) w; (void) h; }
void lc_pic(int x, int y, int w, int h, const char *what)                 /* a picture of the console (coin, dice, disc, QR code): a grey box */
{
	(void) what;
	gpu_draw_rect(NULL, 4, x, y, w, h, 120, 130, 150);
	gpu_draw_rect(NULL, 3, x + 2, y + 2, w - 4 > 0 ? w - 4 : 0, h - 4 > 0 ? h - 4 : 0, 230, 230, 235);
}

static void drop(void)
{
	for (int i = 0; i < nops; i++) free(ops[i].s);
	nops = 0;
}

void lc_frame(const char *name, int yres)
{
	static char seen[256][48];
	static int nseen[256], n;
	const char *dir = getenv("PIX_DIR"), *names = getenv("PIX_NAMES"), *mx = getenv("PIX_MAX");
	int max = mx ? atoi(mx) : 1, k;
	char path[512], file[96];

	lc_frames++;
	if (!dir || yres != 240 || lc_tag[0]) { drop(); return; }
	if (names) {
		size_t l = strlen(name);
		const char *p = names;
		int hit = 0;
		while (*p) {
			const char *e = strchr(p, ',');
			size_t m = e ? (size_t) (e - p) : strlen(p);
			if (m == l && !strncmp(p, name, l)) hit = 1;
			p += m + (e ? 1 : 0);
		}
		if (!hit) { drop(); return; }
	}
	for (k = 0; k < n && strcmp(seen[k], name); k++) {}
	if (k == n && n < 256) { snprintf(seen[n], sizeof seen[n], "%s", name); n++; }
	if (k >= 256 || nseen[k] >= max) { drop(); return; }
	snprintf(file, sizeof file, "%s", name);
	for (char *c = file; *c; c++) if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9'))) *c = '_';
	snprintf(path, sizeof path, "%s/%s_%d.png", dir, file, ++nseen[k]);
	render();
	write_png(path);
	printf("%s\n", path);
}

void gpu_init(RenderContext *c, int r, int g, int b) { (void) r; (void) g; (void) b; c->xres = 640; c->yres = screen_yres; }
void gpu_flip(RenderContext *c, int w) { (void) c; (void) w; }
void gpu_present(RenderContext *c) { (void) c; lc_frame("status", screen_yres); }
void gpu_upload_rows(int vx, int vy, int w, int h, gpu_pixels_fn fn, void *user) { (void) vx; (void) vy; (void) w; (void) h; (void) fn; (void) user; }
void gpu_draw_sprite16(RenderContext *c, int z, int x, int y, int w, int h, int px, int py, int u, int v) { (void) c; (void) z; (void) px; (void) py; (void) u; (void) v; lc_pic(x, y, w, h, "sprite"); }
void gpu_draw_stretched16(RenderContext *c, int z, int x, int y, int w, int h, int dw, int px, int py) { (void) c; (void) z; (void) w; (void) px; (void) py; lc_pic(x, y, dw, h, "QR code"); }
void *gpu_new_primitive(RenderContext *c, int z, size_t size) { static uint8_t b[256]; (void) c; (void) z; (void) size; return b; }
void gpu_set_fade(RenderContext *c, int f) { (void) c; gpu_fade = f; }

void font_init(int scale) { (void) scale; }

void input_init(input_state *in_) { memset(in_, 0, sizeof *in_); }
int input_poll(input_state *in_, entropy_pool *p) { (void) in_; (void) p; return 1; }
uint16_t input_take_pressed(input_state *in_) { (void) in_; return 0; }
int input_present(const input_state *in_) { (void) in_; return 1; }
void ticks_init(void) {}
uint32_t ticks_cycles(void) { return 0; }
