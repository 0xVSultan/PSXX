#pragma once
/* The texts that the core shows to the user (the summaries of the signers, the names of the coins, the error texts) are identifiers, T(TXT_...), like those of the screens: the text is looked up
 * in the table of the current language (hal/psx/ui_text.h; the lists: tools/strings/en_<range>.txt, the identifiers are generated: ui_ids.h). The core has no text of its own; what it
 * needs is the lookup, which a program provides (the console: the tables of the card; the host: tests/ui_autoreg.c registers the English ones before main). */
#include "ui_text.h"
#include "ui_ids.h"
