/* the layout check of the screens on the host: see layout_check.h */
#include "layout_check.h"
#include <stdio.h>
#include <string.h>
#include "icons_data.h"
#include <stdlib.h>

/* The snapshot of everything the screens draw (the English texts, with their positions): every distinct "x,y,text" line, sorted. With LC_SNAPSHOT_WRITE=<file> the test writes it at the end,
 * with LC_SNAPSHOT_CHECK=<file> it compares with that file and fails when a text or a position differs: an edit of the screens that must not change what is shown leaves it unchanged. Control characters (the icons) and backslashes are written as a backslash, x and two hex digits. */
#define LC_SNAP_SLOTS 65536
static char *lc_snap_tab[LC_SNAP_SLOTS];
static int   lc_snap_n, lc_snap_hooked, lc_snap_on = 1;
const char  *lc_tag = "";

static unsigned lc_snap_hash(const char *s) { unsigned h = 2166136261u; for (; *s; s++) h = (h ^ (unsigned char) *s) * 16777619u; return h; }

void lc_snapshot(int on) { lc_snap_on = on; }

static void lc_snap_add(int x, int y, const char *s)
{
	char line[512];
	int o;

	if (!lc_snap_on) return;
	o = snprintf(line, sizeof line, "%d,%d,", x, y);

	for (; *s && o < (int) sizeof line - 6; s++) {
		unsigned char c = (unsigned char) *s;
		if (c < 32 || c == '\\') o += snprintf(line + o, sizeof line - (size_t) o, "\\x%02x", c);
		else line[o++] = (char) c;
	}
	line[o] = 0;
	for (unsigned h = lc_snap_hash(line) % LC_SNAP_SLOTS;; h = (h + 1) % LC_SNAP_SLOTS) {
		if (!lc_snap_tab[h]) {
			if (lc_snap_n >= LC_SNAP_SLOTS / 2) return;
			lc_snap_tab[h] = strdup(line);
			lc_snap_n++;
			return;
		}
		if (!strcmp(lc_snap_tab[h], line)) return;
	}
}

static int lc_snap_cmp(const void *a, const void *b) { return strcmp(*(char *const *) a, *(char *const *) b); }

static char **lc_snap_sorted(int *n)
{
	char **v = malloc((size_t) (lc_snap_n + 1) * sizeof *v);
	int k = 0;

	for (int i = 0; i < LC_SNAP_SLOTS; i++) if (lc_snap_tab[i]) v[k++] = lc_snap_tab[i];
	qsort(v, (size_t) k, sizeof *v, lc_snap_cmp);
	*n = k;
	return v;
}

static void lc_snap_finish(void)
{
	const char *w = getenv("LC_SNAPSHOT_WRITE"), *c = getenv("LC_SNAPSHOT_CHECK");
	int n;
	char **v;

	if (!w && !c) return;
	v = lc_snap_sorted(&n);
	if (w) {
		FILE *f = fopen(w, "w");
		if (f) { for (int i = 0; i < n; i++) fprintf(f, "%s\n", v[i]); fclose(f); }
		printf("snapshot: %d texts written to %s\n", n, w);
	}
	if (c) {
		FILE *f = fopen(c, "r");
		char line[600];
		int diff = 0, i = 0;

		if (!f) { printf("SNAPSHOT: cannot read %s\n", c); fflush(stdout); _Exit(1); }
		while (fgets(line, sizeof line, f)) {
			line[strcspn(line, "\r\n")] = 0;
			while (i < n && strcmp(v[i], line) < 0) { if (diff++ < 20) printf("SNAPSHOT: new text drawn: %s\n", v[i]); i++; }
			if (i < n && !strcmp(v[i], line)) i++;
			else if (diff++ < 20) printf("SNAPSHOT: text no longer drawn: %s\n", line);
		}
		while (i < n) { if (diff++ < 20) printf("SNAPSHOT: new text drawn: %s\n", v[i]); i++; }
		fclose(f);
		if (diff) { printf("SNAPSHOT: %d differences from %s\n", diff, c); fflush(stdout); _Exit(1); }
		printf("snapshot: %d texts equal to %s\n", n, c);
	}
}

#define LC_BOXES 1200
#define LC_ITEMS 400
#define LC_SEEN 400
#define LC_LEFT 8
#define LC_RIGHT (640 - 8)
#define LC_TOP 4
#define LC_MARGIN_BOTTOM 12

typedef struct { int x0, y0, x1, y1, item; } lc_box;
typedef struct { char what[72]; char kind; } lc_item;      /* kind: 't' text, 'r' filled rectangle, 'p' picture */

static lc_box  lc_b[LC_BOXES];
static lc_item lc_it[LC_ITEMS];
static int     lc_nb, lc_ni, lc_nseen;
int            lc_bad, lc_frames;
static char    lc_seen[LC_SEEN][160];
int          (*lc_ext_width)(int cp);

static int lc_item_new(const char *what, char kind)
{
	if (lc_ni >= LC_ITEMS) return -1;
	snprintf(lc_it[lc_ni].what, sizeof lc_it[lc_ni].what, "%s", what);
	for (char *p = lc_it[lc_ni].what; *p; p++) if ((unsigned char) *p < 32) *p = '#';     /* the icons, readable in the report */
	lc_it[lc_ni].kind = kind;
	return lc_ni++;
}

static void lc_box_add(int item, int x0, int y0, int x1, int y1)
{
	if (item < 0 || lc_nb >= LC_BOXES || x1 <= x0 || y1 <= y0) return;
	lc_b[lc_nb++] = (lc_box) {x0, y0, x1, y1, item};
}

static int lc_next(const char **s)
{
	const unsigned char *p = (const unsigned char *) *s;
	int cp;

	if (!*p) return 0;
	if (*p < 0x80) { cp = *p; *s += 1; }
	else if ((*p & 0xE0) == 0xC0) { cp = (p[0] & 31) << 6 | (p[1] & 63); *s += 2; }
	else { cp = (p[0] & 15) << 12 | (p[1] & 63) << 6 | (p[2] & 63); *s += 3; }
	return cp;
}

/* the width of a string as font_width counts it */
int lc_width(const char *s)
{
	int w = 0, cp, e;

	while ((cp = lc_next(&s)) != 0) {
		if (cp >= 1 && cp <= ICON_COUNT) w += ICON_RECT[cp - 1].w + 2;
		else if (lc_ext_width && (e = lc_ext_width(cp)) > 0) w += e;
		else w += LC_CELL_W;
	}
	return w;
}

void lc_text(int x, int y, const char *s)
{
	int item, cp, run = -1, e;
	const char *p = s;

	if (!s || !*s) return;
	if (!lc_snap_hooked) { lc_snap_hooked = 1; atexit(lc_snap_finish); }
	lc_snap_add(x, y, s);
	item = lc_item_new(s, 't');
	while ((cp = lc_next(&p)) != 0) {
		if (cp >= 1 && cp <= ICON_COUNT) {
			int w = ICON_RECT[cp - 1].w, h = ICON_RECT[cp - 1].h;
			if (run >= 0) { lc_box_add(item, run, y, x, y + LC_CELL_H); run = -1; }
			lc_box_add(item, x, y + (LC_CELL_H - h) / 2, x + w, y + (LC_CELL_H - h) / 2 + h);
			x += w + 2;
		} else if (cp == ' ') {
			if (run >= 0) { lc_box_add(item, run, y, x, y + LC_CELL_H); run = -1; }
			x += LC_CELL_W;
		} else if (lc_ext_width && (e = lc_ext_width(cp)) > 0) {
			if (run >= 0) { lc_box_add(item, run, y, x, y + LC_CELL_H); run = -1; }
			lc_box_add(item, x, y, x + e, y + 16);
			x += e;
		} else {
			if (run < 0) run = x;
			x += LC_CELL_W;
		}
	}
	if (run >= 0) lc_box_add(item, run, y, x, y + LC_CELL_H);
}

void lc_rect(int x, int y, int w, int h) { if (w > 2 && h > 2) lc_box_add(lc_item_new("(rectangle)", 'r'), x, y, x + w, y + h); }   /* thinner: a line (the underline cursor) */
void lc_pic(int x, int y, int w, int h, const char *what) { lc_box_add(lc_item_new(what, 'p'), x, y, x + w, y + h); }

static int lc_inter(const lc_box *a, const lc_box *b) { return a->x0 < b->x1 && b->x0 < a->x1 && a->y0 < b->y1 && b->y0 < a->y1; }
static int lc_inside(const lc_box *a, const lc_box *b) { return a->x0 >= b->x0 && a->x1 <= b->x1 && a->y0 >= b->y0 && a->y1 <= b->y1; }

static void lc_report(const char *screen, const char *a, const char *b, const char *text)
{
	char key[160];

	snprintf(key, sizeof key, "%.30s|%.60s|%.60s", screen, a, b);
	for (int i = 0; i < lc_nseen; i++) if (!strcmp(lc_seen[i], key)) return;
	if (lc_nseen < LC_SEEN) strcpy(lc_seen[lc_nseen++], key);
	lc_bad++;
	printf("LAYOUT %s%s: %s\n", lc_tag, screen, text);
}

/* checks the frame drawn since the last call and forgets it */
void lc_frame(const char *screen, int yres)
{
	char t[400];

	lc_frames++;
	for (int i = 0; i < lc_nb; i++) {
		const lc_box *a = &lc_b[i];
		const lc_item *ia = &lc_it[a->item];
		if (a->x0 < LC_LEFT || a->x1 > LC_RIGHT || a->y0 < LC_TOP || a->y1 > yres - LC_MARGIN_BOTTOM) {
			snprintf(t, sizeof t, "outside the safe area (%d lines): \"%s\" at %d,%d .. %d,%d", yres, ia->what, a->x0, a->y0, a->x1, a->y1);
			lc_report(screen, ia->what, "", t);
		}
		for (int j = i + 1; j < lc_nb; j++) {
			const lc_box *b = &lc_b[j];
			const lc_item *ib = &lc_it[b->item];
			if (a->item == b->item || !lc_inter(a, b)) continue;
			if (ia->kind == 't' && ib->kind == 't') snprintf(t, sizeof t, "\"%s\" (%d,%d .. %d,%d) overlaps \"%s\" (%d,%d .. %d,%d)", ia->what, a->x0, a->y0, a->x1, a->y1, ib->what, b->x0, b->y0, b->x1, b->y1);
			else if ((ia->kind == 't' && ib->kind == 'p') || (ia->kind == 'p' && ib->kind == 't'))
				snprintf(t, sizeof t, "\"%s\" lies on the picture \"%s\"", ia->kind == 't' ? ia->what : ib->what, ia->kind == 'p' ? ia->what : ib->what);
			else if (ia->kind == 't' && ib->kind == 'r' && !lc_inside(a, b)) snprintf(t, sizeof t, "\"%s\" (%d,%d .. %d,%d) crosses a rectangle (%d,%d .. %d,%d)", ia->what, a->x0, a->y0, a->x1, a->y1, b->x0, b->y0, b->x1, b->y1);
			else if (ia->kind == 'r' && ib->kind == 't' && !lc_inside(b, a)) snprintf(t, sizeof t, "\"%s\" (%d,%d .. %d,%d) crosses a rectangle (%d,%d .. %d,%d)", ib->what, b->x0, b->y0, b->x1, b->y1, a->x0, a->y0, a->x1, a->y1);
			else continue;
			lc_report(screen, ia->what, ib->what, t);
		}
	}
	lc_nb = lc_ni = 0;
}
