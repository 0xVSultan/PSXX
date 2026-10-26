#pragma once
/* Timing marks for the console builds: PROF("label") prints the time since the previous mark on the debug console (TTY of the
 * emulator). Empty unless the build defines PSX_PROF (then hal/psx provides prof_mark). */
#ifdef PSX_PROF
void prof_mark(const char *label);
#define PROF(label) prof_mark(label)
#else
#define PROF(label) ((void) 0)
#endif
