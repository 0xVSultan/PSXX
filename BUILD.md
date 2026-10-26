# Building

The toolchain here is Windows x64. Everything the build needs is either in this repository or fetched, with SHA-256 checks, by `tools/fetch.py`.

## 1. What you install yourself

- Windows 10/11, PowerShell, Git.
- Python 3.13 (`py -3.13`).
- MSYS2 with the UCRT64 environment in `C:\msys64` (`env.ps1` expects it): `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja`. gcc builds the host tests and the FreePSXBoot builder, `g++` is needed too.
- For the card package step and the vector generators, Python packages. They are looked up in `build/refpkgs` (and the small stand-ins in `tools/refshim`):

  ```powershell
  py -3.13 -m pip install --target build/refpkgs bip_utils ecdsa pycryptodomex cryptography
  ```

  The generators of test vectors (`tools/gen_*vectors.py`, not needed for a normal build) use more references, named at the top of each script (`zcash-test-vectors` cloned into `build/refzcash`, `unicorn`, `pytoniq-core`, `coincurve`, `PyNaCl`, `Pillow`, `numpy`).

## 2. What `tools/fetch.py` puts in place

```powershell
py -3.13 tools/fetch.py all
py -3.13 tools/fetch.py all --check     # only verify what is there
```

- `sources`: BIP39 and Monero word lists, Unifont, Terminus (into `tools/wordlist_dl*`, `tools/font_dl*`, see `tools/SOURCES.md`).
- `toolchain`: PSn00bSDK 0.24 and gcc 12.3 (mipsel-none-elf) into `toolchain/`, and FreePSXBoot cloned at a fixed commit with `tools/stage2min/builder.cc.patched` copied over its `builder.cc` and compiled to `toolchain/FreePSXBoot/builder/builder.exe`. The patch makes the builder keep the whole payload of the card (the original copied the first 64 KB of the card over the rest, which cut off programs above about 57 KB).

A download whose SHA-256 differs is deleted and the run stops. If a word list changed upstream, compare with `tools/SOURCES.md` before you accept it.

## 3. Host build and tests

```powershell
. .\env.ps1
cmake -S . -B build/host -G Ninja
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

The test list includes the cryptography against references, the signers against vectors, the key store with power cuts at every write position, the card packages and the screen layouts (every drawn frame is checked for overlaps and compared with `tests/snap_screens_*.txt`).

## 4. The console programs and the cards

```powershell
. .\env.ps1
cmake -S hal/psx -B build/psx -G Ninja --toolchain "$env:PSN00BSDK_LIBS/cmake/sdk.cmake"     # once
py -3.13 tools/data_pack.py build --out build/release/r1/data.pkg                            # card C: word lists, glyphs
py -3.13 tools/release.py build --base psxx_a --overlay psxx_b --lang psxx_l --data build/release/r1/data.pkg --out build/release/r1 --quiet
py -3.13 tools/packexe.py build/release/r1/base.exe build/release/r1/base_packed.exe --ext-dec
py -3.13 tools/release.py cards build/release/r1 --minload [--bios 4.1-19971216-A]
```

- `--quiet` is the production build (no diagnostic output on the console TTY).
- `packexe.py` prints the size of the LZMA stream of card A: it has to stay within 120,072 bytes for the fast loader of the boot card.
- `release.py cards` writes `A-boot-<bios>-min.mcd` (the FreePSXBoot card for one BIOS version), `B-ok.mcd`, and the test cards. `tools/bios_matrix.py build` makes the boot card for every supported BIOS version.
- The first build creates a development signing key in `build/keys/psxx_sign.key` (or set `PSXX_SIGN_KEY` to a file with 64 hex digits). The public key is written into the main card, so cards signed with different keys do not mix.
- Memory card images are written to a real card with the tools described in the FreePSXBoot README (a PS2 with MCA, Memcarduino, MemcardRex, ...). Use the image for the slot your card is in.

## 5. Emulators

Emulators and PlayStation BIOS images are not included (the BIOS is copyrighted: use your own dump). `tools/bios_matrix.py` sets up DuckStation, no$psx or PCSX-Redux for a boot-card test run per BIOS version and records OK/BAD verdicts. Swap tests (card B to card C) need DuckStation with the card type set to Shared; no$psx cannot swap cards.

## 6. Layout facts worth knowing

- Cards: A is the FreePSXBoot boot card (the generator and the loader). B holds the package `PSXXPK01` (signer overlay and language module, read together) and the key store files. C holds `PSXXPK02` (word lists and glyphs).
- A card boot leaves the BIOS shell alive and the GPU DMA interrupt never reaches the program, so all drawing is polled (`hal/psx/gpu.h`). The program is linked at `0x80110000` (`hal/psx/exe_hi.ld`), above the shell's data and heap.
