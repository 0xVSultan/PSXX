#pragma once
/* The fixed places in the main RAM that the overlays and their data use. The numbers are read from here by the build (hal/psx/CMakeLists.txt makes the
 * linker scripts of the overlays from ovl.ld.in) and by tools/release.py, so they are only written once: keep each definition on one line, `#define MM_NAME 0x........u`.
 *
 * The overlay region 0x801B4000 .. 0x801FD000 is cut into two slots, so the signer and the language module are in memory together and neither is thrown out for the other:
 *
 *   MM_SIG    the signer: code, rodata and data (its bss is in pocket 1)
 *   MM_LANG   the language module: code, rodata, data, bss; what is left above is the second segment of the module's data arena
 *
 * The pockets are stretches of the RAM that the BIOS shell leaves alone while a program runs from a FreePSXBoot card. They are outside the span of the generator (0x80110000 ..) and of the BIOS heap:
 *
 *   MM_P1     0x800D1C00 .. 0x800F31FF (133.5 KB): the bss of the signer while it runs; when the signer is not running the scratch of the loader (the packed bytes of an overlay,
 *             the work areas of the decoders of the language module). Wiped when the signer returns and when it is left.
 *   MM_P0     0x80010000 .. 0x8002FFFF (128 KB): the data of the language that is on (glyphs, word lists, typing keys). */

#define MM_SIG_LO 0x801B4000u
#define MM_SIG_HI 0x801E5000u
#define MM_LANG_LO 0x801E5000u
#define MM_LANG_HI 0x801FD000u
#define MM_P1_LO 0x800D1C00u
#define MM_P1_HI 0x800F3200u
#define MM_P0_LO 0x80010000u
#define MM_P0_HI 0x80030000u

/* The LZMA decoder of the program (tools/stub/lzdec.c) lives here in a release build (PSXX_EXT_DEC): the unpacking stub of the boot card (tools/stub/lzmastub.c) copies it here, uses it to
 * unpack the main card, and the loader calls it for the packages afterwards, so the main card does not carry a second copy. 0x800F5000 .. 0x800F5800 lies in 0x800F4F00 .. 0x800F94FF (17.5 KB), the stretch that is free on every BIOS that was probed (tools/memprobe-card.ps1 -All, 17.68); the pocket that
 * the first probe found free (17.29) is busy on the 2.1 - 3.0 I BIOSes. The last word of it is the tag that says the decoder is there (MM_DEC_MAGIC), so a pocket that was written over is noticed. */
#define MM_DEC_LO 0x800F5000u
#define MM_DEC_HI 0x800F5800u
#define MM_DEC_TAG 0x800F57FCu
#define MM_DEC_MAGIC 0x434E4C5Au
