#pragma once
/* host stand-in for the SDK header: what the language module and the memory probe use from it */
#define MODE_NTSC 0
#define MODE_PAL 1
int VSync(int mode);
int GetVideoMode(void);
