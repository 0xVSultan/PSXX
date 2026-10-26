# Third-party material

The project's own code is MIT (see `LICENSE`). The following is not, or is derived from other work.

## In this repository

| what | where | licence |
|---|---|---|
| FreePSXBoot (brad-lin): the exploit's second stage and builder, as sources used by the boot cards | `tools/stage2min/orig/`, `tools/stage2min/builder.cc.patched` (the builder with one fix: it keeps the whole payload of a card) | MIT, `tools/stage2min/orig/LICENSE.FreePSXBoot` |
| Terminus font 4.49.1, 10x18 bold (bitmap glyphs) | `hal/psx/font_bdf.h` | SIL OFL 1.1, `hal/psx/LICENSE.font` |
| GNU Unifont 18.0.01 (glyphs of the hanzi, hangul and kana sets on card C, some Vietnamese letters) | generated into the card C package and `hal/psx/font_bdf.h` by `tools/gen_*.py` | SIL OFL 1.1 or GPLv2+ with the font embedding exception |
| Kenney "Input Prompts" (PlayStation button icons) | `ui/buttons/kenney/Double/` | CC0 1.0 |
| PSn00bSDK basic graphics example (adapted) | `hal/psx/main.c` | MPL 2.0 (this file keeps it) |
| Test vectors of NIP-44 and other published vectors | `tests/*vectors*.txt`, `spa/test/vectors.json` | as published by their projects (the generators in `tools/gen_*vectors.py` say which reference made each file) |

The coin picture in `ui/coin/` was supplied by the repository owner.

## Fetched by `tools/fetch.py` (not in the repository)

See `tools/SOURCES.md` for URLs and SHA-256 sums.

- BIP39 word lists (bitcoin/bips), Monero mnemonic lists (monero-project/monero): their projects' licences apply to the lists. The lists are compressed into the card images.
- Unifont and Terminus: see above.
- PSn00bSDK 0.24 (MPL 2.0, linked into the programs), gcc 12.3 for mipsel-none-elf (GPL, a tool only), FreePSXBoot sources (MIT).

Nothing from a PlayStation BIOS is included. The BIOS images that the emulators and `tools/bios_matrix.py` need are the user's own dumps and are not distributed.
