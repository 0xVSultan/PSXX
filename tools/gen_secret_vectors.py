#!/usr/bin/env python3
"""Known-answer vectors for chain_secret() in core/coin/chains.c (the secret key export).

References: bip_utils (BIP32 / SLIP-10 / CIP-1852 / Substrate derivation, WIF, Base58, Bech32), hashlib, base64. Run with
    python -I tools/gen_secret_vectors.py
Output: tests/secret_vectors.txt, lines
    secret  <id> <seed hex> <path> <expected>
    secrete <id> <entropy hex> <password | -> <path | junctions | _> <expected>      (Cardano, Substrate)
"""
import base64, os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import *

rnd = random.Random(0x534543)
out = []
def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))

MNEMS = [
    ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""),
    ("legal winner thank year wave sausage worth useful legal winner thank yellow", "TREZOR"),
    (str(Bip39MnemonicGenerator().FromEntropy(rb(32))), "x"),
]
SEEDS = [Bip39SeedGenerator(m, Bip39Languages.ENGLISH).Generate(p) for m, p in MNEMS]

def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

CONF = {"btc84": Bip44Conf.BitcoinMainNet, "btc86": Bip44Conf.BitcoinMainNet, "btc49": Bip44Conf.BitcoinMainNet,
        "btc44": Bip44Conf.BitcoinMainNet, "ltc84": Bip44Conf.LitecoinMainNet, "ltc49": Bip44Conf.LitecoinMainNet,
        "ltc44": Bip44Conf.LitecoinMainNet, "doge": Bip44Conf.DogecoinMainNet, "dash": Bip44Conf.DashMainNet,
        "bch": Bip44Conf.BitcoinCashMainNet, "zec": Bip44Conf.ZcashMainNet}
HEXC = ["eth", "etc", "trx", "xrp", "atom", "osmo"]
PATHS = {
    "btc84": "m/84'/0'/0'/0/0", "btc86": "m/86'/0'/0'/0/0", "btc49": "m/49'/0'/0'/0/0", "btc44": "m/44'/0'/0'/0/0",
    "ltc84": "m/84'/2'/0'/0/0", "ltc49": "m/49'/2'/0'/0/0", "ltc44": "m/44'/2'/0'/0/0", "doge": "m/44'/3'/0'/0/0",
    "dash": "m/44'/5'/0'/0/0", "bch": "m/44'/145'/0'/0/0", "zec": "m/44'/133'/0'/0/0", "eth": "m/44'/60'/0'/0/0",
    "etc": "m/44'/61'/0'/0/0", "trx": "m/44'/195'/0'/0/0", "xrp": "m/44'/144'/0'/0/0", "atom": "m/44'/118'/0'/0/0",
    "osmo": "m/44'/118'/0'/0/0", "nostr": "m/44'/1237'/0'/0/0",
    "sol": "m/44'/501'/0'/0'", "xlm": "m/44'/148'/0'", "near": "m/44'/397'/0'", "dot": "m/44'/354'/0'/0'/0'",
    "ton": "m/44'/607'/0'", "ton5": "m/44'/607'/0'",
}
def vary(path, ed25519):
    seg = path.split("/")
    a = seg[:]
    if ed25519: a[3] = str(int(a[3].rstrip("'")) + 2) + "'"
    else: a[-1] = str(int(a[-1]) + 7)
    return [path, "/".join(a)]

for si, seed in enumerate(SEEDS):
    for cid in list(CONF) + HEXC + ["nostr"]:
        for p in vary(PATHS[cid], False)[: 2 if si == 0 else 1]:
            priv = Bip32Slip10Secp256k1.FromSeedAndPath(seed, p).PrivateKey().Raw().ToBytes()
            if cid in CONF:
                want = WifEncoder.Encode(priv, CONF[cid].WifNetVersion(), WifPubKeyModes.COMPRESSED)
            elif cid == "nostr":
                want = Bech32Encoder.Encode("nsec", priv)
            else:
                want = priv.hex()
            out.append("secret %s %s %s %s" % (cid, seed.hex(), p, want))
    for cid in ("sol", "xlm", "near", "dot", "ton", "ton5"):
        for p in vary(PATHS[cid], True)[: 2 if si == 0 else 1]:
            k = Bip32Slip10Ed25519.FromSeedAndPath(seed, p)
            priv = k.PrivateKey().Raw().ToBytes()
            pub = k.PublicKey().RawCompressed().ToBytes()[1:]
            if cid == "sol": want = Base58Encoder.Encode(priv + pub)
            elif cid == "near": want = "ed25519:" + Base58Encoder.Encode(priv + pub)
            elif cid == "xlm":
                b = bytes([18 << 3]) + priv
                b += crc16(b).to_bytes(2, "little")
                want = base64.b32encode(b).decode().rstrip("=")
            else: want = priv.hex()
            out.append("secret %s %s %s %s" % (cid, seed.hex(), p, want))

# Cardano: bech32 addr_xsk of the 96 byte payment node (kL || kR || chain code)
for ent in (rb(16), rb(24), rb(32)):
    seed = CardanoIcarusSeedGenerator(str(Bip39MnemonicGenerator().FromEntropy(ent))).Generate()
    root = Cip1852.FromSeed(seed, Cip1852Coins.CARDANO_ICARUS)
    for acct, idx in ((0, 0), (1, 3)):
        k = root.Purpose().Coin().Account(acct).Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx)
        raw = k.PrivateKey().Raw().ToBytes() + k.PrivateKey().ChainCode().ToBytes()
        out.append("secrete ada %s - m/1852'/1815'/%d'/0/%d %s" % (ent.hex(), acct, idx, Bech32Encoder.Encode("addr_xsk", raw)))

# Substrate: the polkadot-js secret URI = 0x mini secret + junctions
for ent, pw in ((rb(16), ""), (rb(32), "pw")):
    m = str(Bip39MnemonicGenerator().FromEntropy(ent))
    mini = SubstrateBip39SeedGenerator(m).Generate(pw)[:32]
    for path in ("", "//polkadot//0", "//hard/0/soft"):
        out.append("secrete dotsr %s %s %s %s" % (ent.hex(), pw or "-", path or "_", "0x" + mini.hex() + path))

open(os.path.join(HERE, "..", "tests", "secret_vectors.txt"), "w").write("\n".join(out) + "\n")
print(len(out), "vectors")
