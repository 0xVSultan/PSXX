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
- Parts have run in emulators (no$psx, DuckStation, PCSX-Redux). The newest work has been built and host-tested but not fully run in an emulator.
- **Nothing has run on a real console yet.** Do not keep funds you cannot lose behind it. Verify every release yourself.
- Builds from this source are signed with a **development key** that `tools/sign_key.py` creates on your machine (`build/keys/`, never committed). They are different cards from any official release; the official release is signed by the project's own key.

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

## Licence

MIT, see `LICENSE`. Third-party material: `THIRD_PARTY.md`.
