# PSX crypto multitool

An offline crypto wallet tool that runs on an original **PlayStation 1**. There is no network, no radio and no operating system: the console starts the program straight from a memory card (FreePSXBoot), and all secrets live in RAM until you restart.

It does three jobs, spread over three memory cards:

- **Generator (card A, boot):** makes seeds from entropy you collect (button timing, sticks, coin flips, dice), shows the words with check questions, addresses and QR codes, restores a wallet from typed words, encrypts text, saves password-protected keys.
- **Signer (card B):** reads a signing request from a memory card file (or typed hex), shows a readable summary, signs after a long button hold, writes the result back as a card file, a QR code or an animated UR code. Bitcoin family (PSBT, multisig), Ethereum/EVM, Tron, XRP, Cosmos, Nostr, Solana, Stellar, NEAR, Polkadot, TON, Cardano, Kaspa, Zcash (transparent and Orchard), Monero. It also searches for vanity addresses.
- **Language module (card B code, card C data):** word lists and glyphs of 14 languages and a replaceable menu language.

Card packages are signed (BIP340 Schnorr); the main card holds the public key and refuses a package that is damaged, unsigned, signed by another key or built for another main card.

See `FEATURES_EN.txt` for what the program does in detail.

## Status: read this first

- The cryptography, the transaction summaries, the key store, the card packages and the screen layouts are checked by 51 host tests against independent references and official test vectors.
- Parts have run in emulators (no$psx, DuckStation, PCSX-Redux).
- **Nothing has run on a real console yet.** Do not keep funds you cannot lose behind it. Verify every release yourself.
- Builds from this source are signed with a **development key** that `tools/sign_key.py` creates on your machine (`build/keys/`, never committed). They are different cards from any official release; the official release is signed by the project's own key.

## Consoles and BIOS versions

The boot card (FreePSXBoot) has to match the BIOS of the console, so there is one boot card per BIOS version (`tools/release.py cards --bios <version>`, `tools/bios_matrix.py build` makes all of them). Region letters in the BIOS names: A = North America, E = Europe (PAL), I = Japan.

**The BIOS 1.0 of the SCPH-1000 (Japan, 1994) does not work.** The program does not support it (the matrix test marks it BAD, "yet unsupported"). Do not use a SCPH-1000 console. Every other BIOS version below is supported.

Model numbers are from Wikipedia ([PlayStation models](https://en.wikipedia.org/wiki/PlayStation_models); the last digit of an SCPH number is the region: 0 Japan, 1 North America, 2 Europe, 3 Asia). The test column is the boot test of the 22 boot cards in the DuckStation emulator (`tools/bios_matrix.py`) with an earlier build; the current build is expected to boot the same way. No real console has been tried yet.

| BIOS version | Models (Wikipedia) | Boot test |
|---|---|---|
| 1.0 (1994-09-22, I) | SCPH-1000 | **does not work** |
| 1.1 (1995-01-22, I) | SCPH-3000 | OK |
| 2.0 (1995-05-07, A) | not listed | OK |
| 2.0 (1995-05-10, E) | SCPH-1002 | OK |
| 2.1 (1995-07-17, A) | not listed | OK |
| 2.1 (1995-07-17, E) | SCPH-1002 | OK |
| 2.1 (1995-07-17, I) | SCPH-3500 | OK |
| 2.2 (1995-12-04, A) | SCPH-1001 | OK |
| 2.2 (1995-12-04, E) | SCPH-1002 | OK |
| 2.2 (1995-12-04, I) | SCPH-5000, SCPH-5003, SCPH-5903 | OK |
| 3.0 (1996-09-09, I) | SCPH-5500 | OK |
| 3.0 (1996-11-18, A) | SCPH-5501, SCPH-5503, SCPH-7003 | OK |
| 3.0 (1997-01-06, E) | SCPH-5502, SCPH-5552 | OK |
| 4.0 (1997-08-18, I) | SCPH-7000, SCPH-9000 | OK |
| 4.1 (1997-11-14, A) | SCPH-7000W (listed as a Japanese promotional model) | OK |
| 4.1 (1997-12-16, A) | SCPH-7001, SCPH-7501, SCPH-9001 | OK |
| 4.1 (1997-12-16, E) | SCPH-7002, SCPH-7502, SCPH-9002 | OK |
| 4.3 (2000-03-11, I) | SCPH-100 (PS one) | OK |
| 4.4 (2000-03-24, A) | not listed | OK |
| 4.4 (2000-03-24, E) | SCPH-102 (PS one) | OK |
| 4.5 (2000-05-25, A) | SCPH-101 (PS one) | OK |
| 4.5 (2000-05-25, E) | SCPH-102, SCPH-103 (PS one) | OK |

The main target of the project is the SCPH-1002 (BIOS 2.0 E). Models whose BIOS dump is not in the table (for example the Japanese 4.1 of the SCPH-7500) were not part of the test.

## Verifying a release

Every release has a signed manifest (a Nostr event, kind 30078) that lists the SHA-256 of each memory card file, and the card packages are signed by the project key. The verifier is one static HTML page (`spa/`, built reproducibly by `tools/build_spa.py`): it makes no network requests and checks the cards, the package events and the manifest in your browser.

- IPFS CID of the verifier page (`psxx-verify.html`, CIDv1 raw, so the CID is the SHA-256 of the file): `bafkreibufcdxdvwkdcripaiw5jchwvbicbcekd2iwps7ohbz6lg7e46ayu`
- Gateway link: <https://bafkreibufcdxdvwkdcripaiw5jchwvbicbcekd2iwps7ohbz6lg7e46ayu.ipfs.inbrowser.link/>
- File SHA-256: `34288771d6ca18a2878116ea447b54281044450f48b3e5f71c39f2cdf273c0c5`

Build the page yourself with `py -3.13 tools/build_spa.py` and compare the hash, or use the command line twin `py -3.13 tools/release.py check-cards`. The project public key that signs the releases:

- npub: `npub1x3jrmnnmzstz4xw7uasrjsrvwj5and82tr4sdnd5f45qv5th7uwqheg2qd`
- hex: `34643dce7b14162a99dee76039406c74a9d9b4ea58eb06cdb44d68065177f71c`

Do not take the key from the verifier page, and compare it with other places where the project publishes it before you trust a release.

## Layout

| directory | contents |
|---|---|
| `core/` | portable C: hashes, curves, coins, signers, key store format, card packages, QR/UR |
| `hal/psx/` | the console programs (A, the signer overlay, the language module), the loader, drivers |
| `tests/` | host tests (`ctest`), screen layout checks and their snapshots |
| `tools/` | build and packaging tools, vector generators, the card builder helpers, `fetch.py` |
| `spa/` | a static page that verifies a release (signatures, hashes) in the browser |
| `ui/` | picture sources for the button icons and the coin |

## Build

Windows, PowerShell. Short version (details in `BUILD.md`):

```powershell
py -3.13 tools/fetch.py all            # word lists, fonts, toolchain, FreePSXBoot builder (SHA-256 checked)
. .\env.ps1
cmake -S . -B build/host -G Ninja ; cmake --build build/host ; ctest --test-dir build/host
```

## Donations

If the project is useful to you, you can support it here.

| coin | address |
|---|---|
| Bitcoin (BTC) | `bc1q5pw3esmkcym5cq3hj96fezlhz7fdtgxvg5tsjc` |
| Ethereum (ETH) | `0xca39C9965599a365C22973BD97CFc5C4c80595B5` |
| Monero (XMR) | `46SFFZKZvrwDn3XDcGpb9PXKmGXX9Tc9cjNRwPGFNTw7hBycAQtRSRrMxA5K3kZYAaUmMpHMSRspidLbwndGtc4L4c2FJiC` |
| Litecoin (LTC) | `ltc1q0myv8k2pyfna9x2cwh552qyz6zxuwx8qst4fx3` |
| Bitcoin Cash (BCH) | `qzst44m4dfgmheasra94ntm9agh7xgf7qufc2qsump` |
| Dogecoin (DOGE) | `DQkioaWJomSC3dKGk1JE6b2SvRtWSPrCaj` |

## Licence

MIT, see `LICENSE`. Third-party material: `THIRD_PARTY.md`.
