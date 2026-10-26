/* The console as far as the screens of tests/test_screens_a.c and tests/test_screens_b.c see it: what they draw goes to the layout check (tests/layout_check.h), the controller
 * presses nothing, the timer stands still. screen_yres is the height of the picture the test draws (240 NTSC, 256 PAL). */
#include <stdio.h>
#include <string.h>
#include "layout_check.h"
#include "gpu.h"
#include "font.h"
#include "input.h"
#include "timer.h"
#include <psxgpu.h>

int screen_yres = 240;
int gpu_fade = 256;
static int frame_no;

int VSync(int mode) { (void) mode; return ++frame_no; }
int GetVideoMode(void) { return screen_yres > 240 ? MODE_PAL : MODE_NTSC; }
void gpu_init(RenderContext *c, int r, int g, int b) { (void) r; (void) g; (void) b; c->xres = 640; c->yres = screen_yres; }
void gpu_flip(RenderContext *c, int w) { (void) c; (void) w; }
void gpu_present(RenderContext *c) { (void) c; lc_frame("status", screen_yres); }        /* a screen that shows itself: a status, a progress */
void gpu_upload_rows(int vx, int vy, int w, int h, gpu_pixels_fn fn, void *user) { (void) vx; (void) vy; (void) w; (void) h; (void) fn; (void) user; }
void gpu_draw_sprite16(RenderContext *c, int z, int x, int y, int w, int h, int px, int py, int u, int v) { (void) c; (void) z; (void) px; (void) py; (void) u; (void) v; lc_pic(x, y, w, h, "sprite"); }
void gpu_draw_stretched16(RenderContext *c, int z, int x, int y, int w, int h, int dw, int px, int py) { (void) c; (void) z; (void) w; (void) px; (void) py; lc_pic(x, y, dw, h, "QR code"); }
void *gpu_new_primitive(RenderContext *c, int z, size_t size) { static uint8_t b[256]; (void) c; (void) z; (void) size; return b; }
void gpu_draw_rect(RenderContext *c, int z, int x, int y, int w, int h, int r, int g, int b) { (void) c; (void) z; (void) r; (void) g; (void) b; lc_rect(x, y, w, h); }
void gpu_set_fade(RenderContext *c, int f) { (void) c; gpu_fade = f; }

void font_init(int scale) { (void) scale; }
int font_cell_w(void) { return LC_CELL_W; }
int font_cell_h(void) { return LC_CELL_H; }
void font_draw(RenderContext *c, int z, int x, int y, const char *s, int r, int g, int b) { (void) c; (void) z; (void) r; (void) g; (void) b; lc_text(x, y, s); }
int font_width(const char *s) { return lc_width(s); }
void font_draw_big(RenderContext *c, int z, int x, int y, const char *s, int k, font_colour_fn colour, void *user)
{
	(void) c; (void) z; (void) colour; (void) user;
	lc_pic(x, y, (int) strlen(s) * 2 * k * LC_CELL_W, k * LC_CELL_H, "big text");
}
int font_utf8_next(const char **s)
{
	const unsigned char *p = (const unsigned char *) *s;
	int cp;

	if (!*p) return 0;
	if (*p < 0x80) { cp = *p; *s += 1; }
	else if ((*p & 0xE0) == 0xC0) { cp = (p[0] & 31) << 6 | (p[1] & 63); *s += 2; }
	else { cp = (p[0] & 15) << 12 | (p[1] & 63) << 6 | (p[2] & 63); *s += 3; }
	return cp;
}
int font_utf8_len(const char *s) { int n = 0; while (font_utf8_next(&s)) n++; return n; }
int font_utf8_encode(char *out, int cp)
{
	if (cp < 0x80) { out[0] = (char) cp; return 1; }
	if (cp < 0x800) { out[0] = (char) (0xC0 | cp >> 6); out[1] = (char) (0x80 | (cp & 63)); return 2; }
	out[0] = (char) (0xE0 | cp >> 12); out[1] = (char) (0x80 | ((cp >> 6) & 63)); out[2] = (char) (0x80 | (cp & 63));
	return 3;
}

void input_init(input_state *in_) { memset(in_, 0, sizeof *in_); }
int input_poll(input_state *in_, entropy_pool *p) { (void) in_; (void) p; return 1; }
uint16_t input_take_pressed(input_state *in_) { (void) in_; return 0; }
int input_present(const input_state *in_) { (void) in_; return 1; }
void ticks_init(void) {}
uint32_t ticks_cycles(void) { return 0; }

/* the key save of the main card (wallet_app.c), which the overlay calls: not run by the screen tests */
__attribute__((weak)) int ks_save_modal(int type, const uint8_t *ent, int elen, int flags, const char *label) { (void) type; (void) ent; (void) elen; (void) flags; (void) label; return 0; }
__attribute__((weak)) void addr_modal(const void *s, const char *pass) { (void) s; (void) pass; }

/* what the main card's key save leaves for the overlay to finish a key of two frames (wallet_app.c): not run by the screen tests */
#include "keystore.h"
__attribute__((weak)) ksd_state ks_st;
__attribute__((weak)) int ks_target, ks_new_pw, ks_use_store;
__attribute__((weak)) uint8_t ks_k[32], ks_work[KS_DATA];
__attribute__((weak)) ks_dir ks_pwd;
__attribute__((weak)) char ks_label[KS_LABEL_STORE + 1], ks_plabel[KS_PUBLIC + 1], ks_slabel[KS_STORE_LABEL + 1], ks_pass[2305];
__attribute__((weak)) void ks_wipe(void) {}
