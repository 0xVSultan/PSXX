#pragma once
#include <stdint.h>
#include "gpu.h"

/* On-screen keyboard in the style of a phone keyboard, driven by the controller:
 *   D-pad  move between keys        X  type the key          O  delete       Square  space
 *   Triangle  shift: once = next letter, twice = lock, again = off    START  accept            SELECT  cancel  L2  show / hide the text
 *   L2 + R2  full view: the whole text over several lines, back to the keys with L2 + R2 again. There:
 *              D-pad  move the text cursor         O  delete the character before the cursor
 *              X  mark: first press starts a block at the cursor, second ends it (both characters included); any number
 *                 of separate blocks; Triangle unmarks the last block (or the one being marked)
 *              O with something marked: delete the marked text, asks first (O again = yes, any other button = no)
 *              START  copy the marked text (all of the text if nothing is marked) into the clipboard
 *              SELECT  the clipboard (10 entries, newest first): X pastes at the cursor, O deletes an entry
 *            Typed characters are inserted at the cursor in both views. The clipboard lives in RAM until kb_clip_wipe().
 *   L2       (alone) show / hide a masked text
 *   L1 / R1  (accent mode only) step through the variants of the key under the cursor, shown in a strip above the keys: the highlighted one
 *            (drawn larger) stays at the centre and the strip moves under it; X then types it (the plain letter is the first entry)
 * L1 without a strip (a key that has no variants, or ASCII mode) switches the wrapping of the lines, as in the full view.
 * The text field shows one line of the text, the one with the cursor. A line ends at a new line character or where it is full. The keys at the right of the last
 * two rows move the text cursor one line up / down (in the symbols layer the lower one is Enter: a new line). Under the field: line n of m, the characters of the
 * text, the column of the cursor. The keypads (hex, path) keep one long line that scrolls. START accepts, O deletes.
 * Layers: lower case, upper case (shift), symbols (the "?123" key). The text is UTF-8.
 * ASCII mode (accents = 0): only the keys themselves, no variants row; the text stays plain ASCII (use it wherever the
 * text feeds a derivation that other software has to reproduce, e.g. a BIP39 passphrase, which would need NFKD
 * normalisation for anything else).
 * The text is edited in RAM only; the caller wipes it. */

#define KB_MAX 2304             /* bytes of text the buffer can hold; `limit` (default KB_DEFAULT_LIMIT) is what can be typed */
#define KB_DEFAULT_LIMIT 48
#define KB_BLOCKS 8             /* marked blocks at most */
#ifndef KB_CLIP
#define KB_CLIP 10              /* clipboard entries (the signer builds with fewer: every entry is 2.3 KB of RAM) */
#endif

#define KB_SUG 6                /* suggestions shown at once */
#define KB_SUGLEN 12

/* Word completion: for the letters before the cursor (back to the last space) the callback returns how many words start with
 * them and fills out[0..] with the ones from number `from` on (at most `max`). */
typedef int (*kb_suggest_fn)(const char *prefix, int len, int from, char out[][KB_SUGLEN], int max);

typedef struct {
	char       text[KB_MAX + 1];
	int        len;             /* bytes */
	int        row, idx;        /* cursor key */
	int        var;             /* selected entry of the variants row, 0 = the key itself */
	int        shift;           /* 0 off, 1 next letter only, 2 locked (caps) */
	int        sym, reveal;
	int        type_frame;      /* VSync counter at the last typed character (the last star is shown briefly) */
	int        mask;            /* 1: show the text as stars (except the last typed character) unless revealed */
	int        accents;
	int        cur;             /* text cursor: byte offset where typed characters go (always at a character boundary) */
	int        full;            /* 1: the whole text is shown over several lines, D-pad moves the text cursor (L2+R2) */
	int        multiline;       /* 1: Enter and Tab type (a text that may have lines); the caller sets it after kb_init, otherwise they are off and a paste leaves them out */
	int        ovr;             /* 1: overwrite: a typed character replaces the one under the cursor (the Ins key) */
	int        nowrap;          /* 1: lines are broken only at Enter, a long line scrolls sideways (L1 in the full view) */
	uint16_t   held;            /* buttons held right now (PAD_*): the caller sets it before kb_update, for the L2+R2 chord */
	int        limit;           /* most bytes that can be typed */
	int        hex;             /* 1: hex digit keypad (0-9, a-f), 2: derivation path keypad (0-9 ' / m h); 0: the full keyboard */
	const char *note;           /* optional, set by the caller before kb_draw: shown top right (size / capacity meter) */
	int        warn;            /* colour of the note: 0 normal, 1 warning (near a limit), 2 error (over it) */
	int        nb, ba[KB_BLOCKS], bb[KB_BLOCKS];   /* marked blocks: byte offsets of the first and the last character */
	int        marking, mark_from;                  /* a block is being marked (it started at mark_from) */
	int        confirm;         /* waiting for the second O that deletes the marked text */
	int        clip_view, clip_sel;                 /* the clipboard is open, the entry under the cursor */
	uint16_t   rep_btn;         /* the button that is repeating while held */
	int        rep_cnt;
	int        msg_until;       /* VSync counter until which `msg` is shown */
	const char *msg;
	const char *title;
	int        goal;            /* word mode: how many words are to be typed (for the counter) */
	kb_suggest_fn suggest;      /* word completion (kb_set_suggest), NULL = off */
	int        sug_total, sug_sel, sug_from;        /* matches, the highlighted one, the first one shown */
	char       sug_pre[KB_SUGLEN];                  /* the prefix the list was made for */
	char       sug[KB_SUG][KB_SUGLEN];
} kb_state;

enum { KB_EDITING = 0, KB_DONE = 1, KB_CANCEL = -1 };

/* Start editing `initial` (may be NULL). */
void kb_init(kb_state *k, const char *title, const char *initial, int mask, int accents);
/* Change the limit (bytes, at most KB_MAX) and/or switch to a keypad: hex = 1 (0-9 a-f), 2 (path: 0-9 ' / m h), 0 = the full
 * keyboard. Call right after kb_init. */
void kb_set(kb_state *k, int limit, int hex);
/* Turn on word mode (set k->goal for the counter): only the letter keys, OK and Del; the words that fit the letters typed so far
 * take the place of the text field, below them the counter "word n of goal".
 *   L1 / R1  step through them        Triangle  take the highlighted one (and a space)
 *   Square   with only one candidate left: complete it and add the space; otherwise a plain space */
void kb_set_suggest(kb_state *k, kb_suggest_fn fn);
/* Once per frame with the buttons newly pressed since the last call (PAD_*). */
int kb_update(kb_state *k, uint16_t pressed);
void kb_draw(RenderContext *ctx, const kb_state *k);
/* Wipe the text. */
void kb_wipe(kb_state *k);
/* Wipe the clipboard (texts copied from password fields are in it). */
void kb_clip_wipe(void);
