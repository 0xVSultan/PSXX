# Downloaded sources (not in the repository)

The directories `tools/wordlist_dl/`, `tools/wordlist_dl_xmr/`, `tools/font_dl/` and `tools/font_dl_terminus/` hold files downloaded from the
projects below; they are in `.gitignore`. Download them again to the same names and check the SHA-256 before the generators (`tools/gen_*.py`,
`tools/wl_pack.py`) use them.

## BIP39 word lists, `tools/wordlist_dl/<name>.txt`
Source: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/<name>.txt (documentation: bip-0039/bip-0039-wordlists.md)

| list | SHA-256 |
|---|---|
| chinese_simplified | 5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726 |
| chinese_traditional | 417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f |
| czech | 7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc |
| english | 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda |
| french | ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59 |
| italian | d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2 |
| japanese | 2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd |
| korean | 9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60 |
| portuguese | 2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f |
| spanish | 46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b |

Russian is not a BIP39 list (only Monero has one); the unofficial Trezor `russian.txt` was dropped on purpose.

## Monero mnemonic lists, `tools/wordlist_dl/monero/`
Source: https://raw.githubusercontent.com/monero-project/monero/master/src/mnemonics/<name>

| file | SHA-256 |
|---|---|
| chinese_simplified.h | 4a38fbe7279616aa78aa11dbcf425d0ba5305fd2089cb4421d544f2c540d50fd |
| dutch.h | 775d05f737f453d6798876d99961bb3bcfc49d47cb57860d3c0b2a03b9a64822 |
| english.h | 9bd756d29e689aae0e6e7f8b1196c4f35df350225c4668d4f6f41842f05fc2ca |
| english_old.h | 20c9090994c5b441f2e550cddbf266d604b64e495d9b172e45a8031e1aa5d578 |
| esperanto.h | 382d9f9bfcf293e4dc9f156042fe5a3f2a151191bae368a494eaf53c77e16043 |
| french.h | f4e42ab4eb9824a2cd829f132e33dfc46ae31c5788a37c9726d393e7cc809a82 |
| german.h | 7b910a96bc94d19eb3e4edd8179db383a68b03a7608396bbee0fdc46a7d4e88e |
| italian.h | d02956b528db827646a1f6f78c1a19716b9334985cb893eb09409834a04045db |
| japanese.h | 3701f067006b60e95e266e7a385b472c5bddeb6f476e737eed6d3b7febefe6d5 |
| lojban.h | 6c84dedd2609060f30368b92b5e377207e28afcda5401b5060d57c633e623a04 |
| portuguese.h | 0a6b191930a29f1ae827c1f5f8905548035bac5e5b41386f0978cf39e4adcfa1 |
| russian.h | 2d3f282d11e917fcdd6248b87002f5b982b6abaa773e9676d21886b6a50a4762 |
| spanish.h | 994a941260f53e066753204f4b92c20bb1d830b58e76ff89c2caa71c34d546ef |
| language_base.h | 2bc256f01c6904af914cb7c6526254267ed463882e216fd0eb1d9bbdf4bf5bb4 |
| singleton.h | f540c185cd745a39e6780916163e3710ea20e8e97569e842b5b15e80adfb2256 |
| electrum-words.cpp | f92675503096425c92f6cc8b38946a707db6999cfcd95657f87a58d364051e4f |

`tools/wordlist_dl_xmr/english.h` is the same file as `monero/english.h`. The unique prefix lengths of the lists (checksum) are in the
constructors of the headers.

## Fonts
| file | source | SHA-256 | licence |
|---|---|---|---|
| `tools/font_dl/unifont/unifont-18.0.01.hex.gz` | https://unifoundry.com/pub/unifont/unifont-18.0.01/font-builds/unifont-18.0.01.hex.gz | e66385c79a0b8b24a466f3129930e08a966a935b4bf3b28c6bb17a9df9bf791d | SIL OFL 1.1 or GNU GPLv2+ with the font embedding exception |
| `tools/font_dl_terminus/terminus-font-4.49.1.tar.gz` | https://sourceforge.net/projects/terminus-font/ (`py -3.13 tools/fetch.py sources`) | d961c1b781627bf417f9b340693d64fc219e0113ad3a3af1a3424c7aa373ef79 | SIL OFL 1.1 |

`tools/font_dl/mmh/` (Make Me a Hanzi, Arphic licence) and `tools/font_dl/ids/` (cjkvi-ids, CHISE) were downloaded to evaluate a stroke
font and are not used; the bitmap font is Unifont.
