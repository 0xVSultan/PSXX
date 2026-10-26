#pragma once
/* The drawing primitives the screens of the main card (wallet_app.c) and of the signer (signer_app.c) have in common. Header only, static: each program has its own copy, as the
 * signer is an overlay that cannot call into the main card. Needs `ctx` (the RenderContext), ui.h and font.h to be there before it is included. */

/* the colours of the screens: white text, dim (hints, descriptions), yellow (the selected row) */
#define UI_SEL_RGB 255, 220, 80

static void ctext(int x, int y, const char *s, int r, int g, int b) { font_draw(&ctx, 0, x, y, s, r, g, b); }
static void text(int x, int y, const char *s) { ctext(x, y, s, 255, 255, 255); }
static void dim(int x, int y, const char *s) { ctext(x, y, s, 150, 160, 200); }

/* a text that is yellow if it is the selected one, white if not (a row that has its marker in it already) */
static void ui_hl(int x, int y, int sel, const char *s)
{
	if (sel) ctext(x, y, s, UI_SEL_RGB);
	else text(x, y, s);
}

/* a row of a list: "> " in front if it is the selected one, "  " if not */
static void ui_row(int x, int y, int sel, const char *s)
{
	char line[128];

	snprintf(line, sizeof line, "%c %s", sel ? '>' : ' ', s);
	ui_hl(x, y, sel, line);
}

/* `s` right-aligned (16 pixels from the edge) on the line y, in the colour r, g, b */
static void ui_right(int y, const char *s, int r, int g, int b) { ctext(GPU_XRES - 16 - font_width(s), y, s, r, g, b); }

/* a menu: the title, the items, the description of the selected one under them (none if desc is NULL), the hint line; returns the line of the description, where a caller may put a
 * message instead. More items are closer together, so that the description stays above the hints (ui.h). */
static int ui_menu(const char *title, const char *const *name, const char *const *desc, int n, int sel, const char *hint)
{
	int pitch = n > 6 ? 18 : n > 5 ? 19 : n > 4 ? 24 : n > 3 ? 28 : 26, y0 = n > 6 ? 26 : 32;

	text(16, UI_TOP, title);
	for (int i = 0; i < n; i++) ui_row(16, y0 + i * pitch, i == sel, name[i]);
	if (desc) dim(16, y0 + n * pitch + 2, desc[sel]);
	dim(16, UI_HINT1, hint);
	return y0 + n * pitch + 2;
}

/* Up / down in a list of n rows: stops at the first and the last row. */
static void ui_nav(int *sel, int n, uint16_t pr)
{
	if ((pr & PAD_DOWN) && *sel < n - 1) (*sel)++;
	if ((pr & PAD_UP) && *sel > 0) (*sel)--;
}

/* Up / down in a list of n rows that goes round (nothing for an empty list). */
static void ui_wrap(int *sel, int n, uint16_t pr)
{
	if (n <= 0) return;
	if (pr & PAD_DOWN) *sel = (*sel + 1) % n;
	if (pr & PAD_UP) *sel = (*sel + n - 1) % n;
}

/* ui_menu() for a menu whose texts are all fixed: the identifiers of the n names, then (if with_desc) of the n descriptions, in one table, and those of the title and the hint. */
static int ui_menu_ids(uint16_t title, const uint16_t *id, int n, int with_desc, int sel, uint16_t hint)
{
	const char *name[8], *desc[8];

	for (int i = 0; i < n; i++) { name[i] = T(id[i]); desc[i] = T(id[n + i]); }
	return ui_menu(T(title), name, with_desc ? desc : NULL, n, sel, T(hint));
}
