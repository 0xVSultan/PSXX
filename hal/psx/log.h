#pragma once
#include <stdio.h>

/* The diagnostics on the TTY (the [ldr], [boot], [bg], [prof], [cw] ... lines of the emulators and of a console with a serial line). The production build is made with
 * -DPSXX_QUIET (tools/release.py build --quiet): it has none of them, and none of their strings (about 0.5 KB of the payload of the main card). */
#ifdef PSXX_QUIET
#define LOG(...) ((void) 0)
#else
#define LOG(...) printf(__VA_ARGS__)
#endif
