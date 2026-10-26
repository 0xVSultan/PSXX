#pragma once
#include <stdint.h>
#include "card_watch.h"
#include "gpu.h"
#include "input.h"
#include "loader.h"

/* The screens that choose where the overlay package comes from and load it: the source (Auto, slot 1, slot 2), the state of both slots
 * as the watch sees it, a wait screen while there is no package, the reading with a progress bar and a way to cancel, the error screen. The watch runs only while these
 * screens are open. Whatever happens, nothing runs that was not checked: the loader opens the package against the pin again and checks the hash of what it reads, and the card
 * must still be the one that was looked at before and after the reading (the fingerprint of its directory), else the slot of the overlay is wiped and the screen says so. */

enum { SU_RUNNING = 0, SU_LOADED = 1, SU_CANCEL = -1 };
enum { SU_SELECT = 0, SU_ERROR };
enum { SU_ERR_CHANGED = -100, SU_ERR_CANCELLED = -101 };

typedef struct {
    RenderContext *ctx;
    input_state   *in;
    cw             cw;
    const char    *title, *name;
    int            kind, hz;
    const uint8_t *pin, *base_id;
    uint16_t       group, group2;                 /* the overlay groups of the package that are loaded together (group2 0: one); the data card has none */
    int            phase, src, frame, found;              /* src: 0, the slot the package is in; found: the frame (+ 1) from which one slot has had the package */
    uint32_t       pbase, ptot;                           /* the progress of a reading of two groups: frames done before this one, frames of all of them */
    int            err_code, err_detail;
    int            pct, port;
    ldr_pkg        pk;
    ldr_overlay    ov;
    char           note[48], what[48];
} su;

void su_init(su *s, RenderContext *ctx, input_state *in, int hz, const char *title, const char *package_name, int kind, const uint8_t pin[32], const uint8_t base_id[32], uint16_t group);
/* Opens the screen (the source is kept from the last time). */
void su_enter(su *s, int frame);
/* One step per frame (the reading blocks for a few seconds, it draws its own progress). SU_LOADED: the overlay is in place, su_overlay() has it. SU_CANCEL: the user gave up. */
int su_update(su *s, uint16_t pressed, int frame);
void su_draw(su *s);
/* Reads every group of the package that was read last (from the same slot), with the progress screen and the same checks (the card still the one that was looked at, a way to cancel):
 * a test of the reading of long files, and what a data card will need. The scratch pocket is the buffer, no overlay is touched. SU_LOADED when all is well, else the phase is SU_ERROR. */
int su_verify_all(su *s);
const ldr_overlay *su_overlay(const su *s);
/* the status of a slot, as the watch last saw it, for the main screen */
void su_slot_text(const su *s, int port, char *buf, int n);
/* The package that was opened last (a data card: its groups are read from it, with ldr_unpack_group, as long as the card stays in the slot). */
ldr_pkg *su_package(su *s);
