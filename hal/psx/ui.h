#pragma once
#include <stdio.h>

/* The layout of the screens: 640 x 240 (PAL has 256 lines; the screens use the same 240). TV sets and emulators crop the edges of the picture, so nothing is drawn above
 * UI_TOP or below UI_BOTTOM, nor nearer than 8 pixels to the sides. The text lines are 18 pixels high; the button icons are 22..26 pixels high and centred on the line, so a line
 * with icons reaches 4 pixels above and below it. tests/test_screens_a.c, test_screens_b.c and test_langui.c check every screen (tests/layout_check.h). */
#define UI_TOP 4                        /* the title line */
#define UI_HINT1 176                    /* the upper line of the button hints: its icons cover 172..198, four lines above those of the lower line */
#define UI_HINT2 206                    /* the lower line of the button hints, the last line of a screen: 202..228 */
#define UI_BOTTOM 228
#define UI_MSG (UI_HINT2 - 22)          /* a message line above a one line hint (its icons begin at 202): 184 .. 202, below the 8th row of a list (rows from 26, 20 pixels apart) */

/* The texts of the screens are identifiers, T(TXT_...) (ui_text.h; the list of the texts of every range: tools/strings/en_<range>.txt, the identifiers are generated: ui_ids.h) */
#include "ui_text.h"
#include "ui_ids.h"
