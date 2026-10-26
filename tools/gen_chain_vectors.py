#!/usr/bin/env python3
"""Known-answer vectors for core/coin/chains.c (multi chain addresses), core/coin/path.c and core/hash/blake2b.c.

References: bip_utils (BIP32 / SLIP-10 derivation and every address encoder), hashlib (BLAKE2b). They are not part of
the build: install the wheels into build/refpkgs (see tools/refshim/README) and run with
    python -I tools/gen_chain_vectors.py
Output: tests/chain_vectors.txt, lines `chain <id> <seed hex> <path> <address>`, `path <text> <canonical | err N>`,
`blake2b <outlen> <key|-> <salt|-> <person|-> <msg|-> <digest>`.
"""
import hashlib, os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import *
from bip_utils.ton.mnemonic.ton_seed_utils import TonSeedUtils
from bip_utils.bip.bip39.bip39_mnemonic_utils import Bip39WordsListGetter

rnd = random.Random(0x434841494E)        # "CHAIN"
out = []
def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))
def hx(b): return b.hex() if b else "-"

# --- seeds: the standard test mnemonic, one with a passphrase, random entropy ---
MNEMS = [
    ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""),
    ("legal winner thank year wave sausage worth useful legal winner thank yellow", "TREZOR"),
]
for n in (16, 32, 32):
    MNEMS.append((str(Bip39MnemonicGenerator().FromEntropy(rb(n))), "" if n == 16 else "x"))
SEEDS = [Bip39SeedGenerator(m, Bip39Languages.ENGLISH).Generate(p) for m, p in MNEMS]

def secp(seed, path): return Bip32Slip10Secp256k1.FromSeedAndPath(seed, path).PublicKey().KeyObject()
def ed(seed, path): return Bip32Slip10Ed25519.FromSeedAndPath(seed, path).PublicKey().KeyObject()

def kaspa_addr(k):
    """kaspa:q... of a schnorr key (x only), written out from the rusty-kaspa spec (CashAddr style 40 bit checksum); checked against rusty-kaspa's vectors in tests/test_chains.c"""
    def pm(vals):
        c = 1
        for d in vals:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            for i, g in enumerate((0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)):
                if (c0 >> i) & 1: c ^= g
        return c ^ 1
    x = k.RawCompressed().ToBytes()[1:]
    bits = "".join(format(b, "08b") for b in bytes([0]) + x)
    bits += "0" * (-len(bits) % 5)
    d5 = [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    cs = pm([ord(c) & 31 for c in "kaspa"] + [0] + d5 + [0] * 8)
    cs5 = [(cs >> (5 * (7 - i))) & 31 for i in range(8)]
    return "kaspa:" + "".join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[v] for v in d5 + cs5)

ENC = {
    "kas": kaspa_addr,
    "btc84": lambda k: P2WPKHAddrEncoder.EncodeKey(k, hrp="bc"),
    "btc86": lambda k: P2TRAddrEncoder.EncodeKey(k, hrp="bc"),
    "btc49": lambda k: P2SHAddrEncoder.EncodeKey(k, net_ver=b"\x05"),
    "btc44": lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x00"),
    "ltc84": lambda k: P2WPKHAddrEncoder.EncodeKey(k, hrp="ltc"),
    "ltc49": lambda k: P2SHAddrEncoder.EncodeKey(k, net_ver=b"\x32"),
    "ltc44": lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x30"),
    "doge": lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x1e"),
    "dash": lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x4c"),
    "bch": lambda k: BchP2PKHAddrEncoder.EncodeKey(k, hrp="bitcoincash", net_ver=b"\x00"),
    "zec": lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x1c\xb8"),
    "eth": lambda k: EthAddrEncoder.EncodeKey(k),
    "etc": lambda k: EthAddrEncoder.EncodeKey(k),
    "trx": lambda k: TrxAddrEncoder.EncodeKey(k),
    "xrp": lambda k: XrpAddrEncoder.EncodeKey(k),
    "atom": lambda k: AtomAddrEncoder.EncodeKey(k, hrp="cosmos"),
    "osmo": lambda k: AtomAddrEncoder.EncodeKey(k, hrp="osmo"),
}
ENC_ED = {
    "sol": lambda k: SolAddrEncoder.EncodeKey(k),
    "xlm": lambda k: XlmAddrEncoder.EncodeKey(k, addr_type=XlmAddrTypes.PUB_KEY),
    "near": lambda k: NearAddrEncoder.EncodeKey(k),
    "dot": lambda k: SubstrateEd25519AddrEncoder.EncodeKey(k, ss58_format=0),
    "ton": lambda k: TonAddrEncoder.EncodeKey(k.RawCompressed().ToBytes()[1:], version=TonAddrVersions.V4, is_bounceable=False),
    "ton5": lambda k: TonAddrEncoder.EncodeKey(k.RawCompressed().ToBytes()[1:], version=TonAddrVersions.V5R1, is_bounceable=False),
}
PATHS = {
    "kas": "m/44'/111111'/0'/0/0",
    "btc84": "m/84'/0'/0'/0/0", "btc86": "m/86'/0'/0'/0/0", "btc49": "m/49'/0'/0'/0/0", "btc44": "m/44'/0'/0'/0/0",
    "ltc84": "m/84'/2'/0'/0/0", "ltc49": "m/49'/2'/0'/0/0", "ltc44": "m/44'/2'/0'/0/0", "doge": "m/44'/3'/0'/0/0",
    "dash": "m/44'/5'/0'/0/0", "bch": "m/44'/145'/0'/0/0", "zec": "m/44'/133'/0'/0/0", "eth": "m/44'/60'/0'/0/0",
    "etc": "m/44'/61'/0'/0/0", "trx": "m/44'/195'/0'/0/0", "xrp": "m/44'/144'/0'/0/0", "atom": "m/44'/118'/0'/0/0",
    "osmo": "m/44'/118'/0'/0/0",
    "sol": "m/44'/501'/0'/0'", "xlm": "m/44'/148'/0'", "near": "m/44'/397'/0'", "dot": "m/44'/354'/0'/0'/0'",
    "ton": "m/44'/607'/0'", "ton5": "m/44'/607'/0'",
}
def variants(path, ed25519):
    """the usual path, the next index / account, and a deeper or odd one"""
    seg = path.split("/")
    v = [path]
    if ed25519:
        a = seg[:]; a[3] = str(int(a[3].rstrip("'")) + 1) + "'"; v.append("/".join(a))
        v.append(path + "/7'")
    else:
        a = seg[:]; a[-1] = str(int(a[-1]) + 5); v.append("/".join(a))
        a = seg[:]; a[-2] = "1"; a[3] = "2'"; v.append("/".join(a))
        v.append("m/0'/1/2")
    return v

for si, seed in enumerate(SEEDS):
    for cid, enc in ENC.items():
        for p in variants(PATHS[cid], False)[: 3 if si == 0 else 2]:
            out.append("chain %s %s %s %s" % (cid, seed.hex(), p, enc(secp(seed, p))))
    for cid, enc in ENC_ED.items():
        for p in variants(PATHS[cid], True)[: 3 if si == 0 else 2]:
            out.append("chain %s %s %s %s" % (cid, seed.hex(), p, enc(ed(seed, p))))

# --- Litecoin MWEB stealth addresses, written from Litecoin Core's mw::Keychain (src/libmw) and doc/mweb/stealth-addresses.md with the blake3 wheel
# and the ecdsa package for the curve: scan secret a = m/0'/100'/0', spend secret b = m/0'/100'/1', b_i = b + BLAKE3('A' || i LE32 || a), B_i = b_i G,
# a_i = a b_i, A_i = a_i G; the address is A_i || B_i as Bech32 (not Bech32m) with a leading 0 symbol and the prefix "ltcmweb" (line: chain ltcmweb ...,
# the fourth path level is the index, 2 without it) ---
import blake3 as _blake3
from ecdsa.ecdsa import generator_secp256k1 as _G
_N = _G.order()
def _pt(k):
    P = _G * k
    return bytes([2 + (P.y() & 1)]) + P.x().to_bytes(32, "big")
def _b32(hrp, data5):
    CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    def pm(vals):
        chk = 1
        for v in vals:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if (top >> i) & 1 else 0
        return chk
    exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    c = pm(exp + data5 + [0] * 6) ^ 1
    return hrp + "1" + "".join(CS[v] for v in data5) + "".join(CS[(c >> (5 * (5 - i))) & 31] for i in range(6))
def mweb_addr(seed, path):
    seg = path.split("/")
    if seg[:2] == ["m", "1000'"]:                      # Cake Wallet and Electrum-LTC: scan m/1000'/0', spend m/1000'/1', the first receiving index is 1
        pre, lv, first = "m/1000'", 2, 1
    else:                                              # Litecoin Core
        assert seg[:3] == ["m", "0'", "100'"]
        pre, lv, first = "m/0'/100'", 3, 2
    acc = int(seg[lv].rstrip("'"))
    idx = int(seg[lv + 1]) if len(seg) > lv + 1 else first
    a = int.from_bytes(Bip32Slip10Secp256k1.FromSeedAndPath(seed, "%s/%d'" % (pre, acc)).PrivateKey().Raw().ToBytes(), "big")
    b = int.from_bytes(Bip32Slip10Secp256k1.FromSeedAndPath(seed, "%s/%d'" % (pre, acc + 1)).PrivateKey().Raw().ToBytes(), "big")
    mi = int.from_bytes(_blake3.blake3(b"A" + idx.to_bytes(4, "little") + a.to_bytes(32, "big")).digest(), "big")
    assert 0 < mi < _N
    bi = (b + mi) % _N
    ai = a * bi % _N
    raw = _pt(ai) + _pt(bi)
    acc_, bits, d5 = 0, 0, [0]
    for byte in raw:
        acc_ = (acc_ << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; d5.append((acc_ >> bits) & 31)
        acc_ &= (1 << bits) - 1
    if bits: d5.append((acc_ << (5 - bits)) & 31)
    return _b32("ltcmweb", d5)
for si, seed in enumerate(SEEDS):
    for p in ("m/0'/100'/0'/2", "m/0'/100'/0'/3", "m/0'/100'/0'", "m/0'/100'/0'/0", "m/0'/100'/2'/2")[: 5 if si == 0 else 3]:
        out.append("chain ltcmweb %s %s %s" % (seed.hex(), p, mweb_addr(seed, p)))
    for p in ("m/1000'/0'/1", "m/1000'/0'/2", "m/1000'/0'", "m/1000'/0'/0")[: 4 if si == 0 else 2]:
        out.append("chain ltcmweb %s %s %s" % (seed.hex(), p, mweb_addr(seed, p)))
# Litecoin Core's own test vector (src/wallet/test/scriptpubkeyman_tests.cpp, the MWEB keychain of a fresh HD seed): line `mweb <scan hex> <spend hex> <index> <address>`
for _i, _a in ((0, "ltcmweb1qq20e2arnhvxw97katjkmsd35agw3capxjkrkh7dk8d30rczm8ypxuq329nwh2twmchhqn3jqh7ua4ps539f6aazh79jy76urqht4qa59ts3at6gf"),
               (1, "ltcmweb1qqg5hddkl4uhspjwg9tkmatxa4s6gswdaq9swl8vsg5xxznmye7phcqatzc62mzkg788tsrfcuegxe9q3agf5cplw7ztqdusqf7x3n2tl55x4gvyt"),
               (2, "ltcmweb1qq0yq03ewm830ugmkkvrvjmyyeslcpwk8ayd7k27qx63sryy6kx3ksqm3k6jd24ld3r5dp5lzx7rm7uyxfujf8sn7v4nlxeqwrcq6k6xxwqdc6tl3")):
    out.append("mweb 918271168655385e387907612ee09d755be50c4685528f9f53eabae380ecba97 2396e5c33b07dfa2d9e70da1dcbdad0ad2399e5672ff2d4afbe3b20bccf3ba1b %d %s" % (_i, _a))
# BIP47 payment code (BIP47 text, version 1): Base58Check of 0x47 || 0x01 || 0x00 || compressed public key || chain code || 13 zero bytes, of m/47'/0'/0' (the xpub line, kind 4, descriptor "-")
for _seed in SEEDS[:3]:
    _n = Bip32Slip10Secp256k1.FromSeedAndPath(_seed, "m/47'/0'/0'")
    _pl = bytes([0x47, 0x01, 0x00]) + _n.PublicKey().RawCompressed().ToBytes() + _n.ChainCode().ToBytes() + bytes(13)
    out.append("xpub %s 4 %s -" % (_seed.hex(), Base58Encoder.CheckEncode(_pl)))
# BLAKE3 (line: blake3 <msg hex | -> <digest>): the empty message and lengths around the 64 byte block and the 1024 byte chunk edges
for _n in (0, 1, 3, 37, 63, 64, 65, 127, 128, 129, 1023, 1024):
    _m = bytes((_i * 251 + 7) % 251 for _i in range(_n))
    out.append("blake3 %s %s" % (hx(_m), _blake3.blake3(_m).hexdigest()))

# --- watch-only export: the account key as zpub / ypub / xpub and the output descriptor with Bitcoin Core's checksum (line: xpub <seed hex> <kind> <key> <descriptor>) ---
def _desc_checksum(desc):
    INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#" + chr(34) + chr(92) + " "
    CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GEN = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]
    def pm(symbols):
        chk = 1
        for v in symbols:
            top = chk >> 35
            chk = (chk & 0x7ffffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if (top >> i) & 1 else 0
        return chk
    symbols, groups = [], []
    for ch in desc:
        v = INPUT.find(ch)
        assert v >= 0
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2]); groups = []
    if len(groups) == 1: symbols.append(groups[0])
    elif len(groups) == 2: symbols.append(groups[0] * 3 + groups[1])
    c = pm(symbols + [0] * 8) ^ 1
    return "".join(CS[(c >> (5 * (7 - i))) & 31] for i in range(8))
assert _desc_checksum("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)") == "8zl0zxma", "Bitcoin Core's documented descriptor checksum"
for _seed in SEEDS[:3]:
    _mfp = Hash160.QuickDigest(Bip32Slip10Secp256k1.FromSeed(_seed).PublicKey().RawCompressed().ToBytes())[:4].hex()
    for _kind, (_cls, _coin, _pur, _fmt) in enumerate([(Bip84, Bip84Coins.BITCOIN, 84, "wpkh(%s)"), (Bip49, Bip49Coins.BITCOIN, 49, "sh(wpkh(%s))"), (Bip44, Bip44Coins.BITCOIN, 44, "pkh(%s)"), (Bip86, Bip86Coins.BITCOIN, 86, "tr(%s)")]):
        _acct = _cls.FromSeed(_seed, _coin).Purpose().Coin().Account(0)
        _ext = _acct.PublicKey().ToExtended()
        _xpub = Bip44.FromSeed(_seed, Bip44Coins.BITCOIN).PublicKey().ToExtended() and Bip32Slip10Secp256k1.FromSeed(_seed).DerivePath("%d'/0'/0'" % _pur).PublicKey().ToExtended()
        _body = _fmt % ("[%s/%dh/0h/0h]%s/<0;1>/*" % (_mfp, _pur, _xpub))
        out.append("xpub %s %d %s %s#%s" % (_seed.hex(), _kind, _ext, _body, _desc_checksum(_body)))

# --- Cardano (Icarus master from the BIP39 entropy, CIP-1852, Shelley base address) ---
# line: chaine <id> <entropy hex> <password | -> <payment path> <address>
for ent in (rb(16), rb(20), rb(24), rb(32), bytes(16)):
    seed = CardanoIcarusSeedGenerator(str(Bip39MnemonicGenerator().FromEntropy(ent))).Generate()
    assert seed == ent
    root = Cip1852.FromSeed(seed, Cip1852Coins.CARDANO_ICARUS)
    for acct, idx in ((0, 0), (0, 5), (1, 3), (7, 0)):
        shelley = CardanoShelley.FromCip1852Object(root.Purpose().Coin().Account(acct))
        addr = shelley.Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx).PublicKeys().ToAddress()
        out.append("chaine ada %s - m/1852'/1815'/%d'/0/%d %s" % (ent.hex(), acct, idx, addr))

# --- Polkadot / Kusama sr25519 (Substrate mini secret from the BIP39 entropy, junction paths) ---
# line: chains <id> <entropy hex> <password | -> <junction path | _> <address>   ("_" is the empty path)
for ent, pw in ((rb(16), ""), (rb(32), ""), (rb(16), "pw"), (bytes.fromhex("1a486a5fbe53639984cb64b070755f7b"), "")):
    m = str(Bip39MnemonicGenerator().FromEntropy(ent))
    seed = SubstrateBip39SeedGenerator(m).Generate(pw)
    for coin, cid in ((SubstrateCoins.POLKADOT, "dotsr"), (SubstrateCoins.KUSAMA, "ksm")):
        root = Substrate.FromSeed(seed[:32], coin)
        for path in ("", "//polkadot", "//polkadot//0", "/1", "//a/b", "//Alice", "//hard/0/soft", "/5//6/7",
                     "//thisisaverylongjunctionnamethatgetshashed12345", "//1234567890123456789"):
            if path == "":
                key = root
            else:
                key = Substrate.FromSeed(seed[:32], coin).DerivePath(path)
            out.append("chains %s %s %s %s %s" % (cid, ent.hex(), pw or "-", path.replace("/", "/") or "_", key.PublicKey().ToAddress()))

# --- TON: wallet contract addresses, TON phrase -> key ---
# lines: tonaddr <version 0..3> <bounceable> <public key hex> <address>
#        tonseed <phrase with _ for spaces> <password | -> <entropy hex> <basic 0|1> <ed25519 public key hex> <address v4r2 non-bounceable>
VERS = [TonAddrVersions.V3R1, TonAddrVersions.V3R2, TonAddrVersions.V4, TonAddrVersions.V5R1]
import nacl.signing
for i in range(8):
    pub = bytes(nacl.signing.SigningKey(rb(32)).verify_key)
    for v in range(4):
        for bo in (False, True):
            if i < 2 or (i + v) % 3 == 0:
                out.append("tonaddr %d %d %s %s" % (v, int(bo), pub.hex(), TonAddrEncoder.EncodeKey(pub, version=VERS[v], is_bounceable=bo)))
for pw in ("", "", "secret"):
    mn = TonMnemonicGenerator().FromWordsNumber(24, pw)
    phrase = mn.ToStr()
    ent = TonSeedUtils.GetEntropyBytes(phrase, pw)
    seed = TonSeedGenerator(mn, pw).Generate()
    pub = Ton.FromSeed(seed).PublicKey()
    out.append("tonseed %s %s %s %d %s %s" % (phrase.replace(" ", "_"), pw or "-", ent.hex(), int(TonSeedUtils.IsBasicSeed(ent)),
                                          pub.RawCompressed().ToBytes()[1:].hex(),
                                          TonAddrEncoder.EncodeKey(pub.RawCompressed().ToBytes()[1:], version=TonAddrVersions.V4, is_bounceable=False)))
for k in range(3):   # a random phrase is almost never a basic seed
    words = [Bip39WordsListGetter().GetByLanguage(Bip39Languages.ENGLISH).GetWordAtIdx(rnd.randrange(2048)) for _ in range(24)]
    phrase = " ".join(words)
    ent = TonSeedUtils.GetEntropyBytes(phrase, "")
    out.append("tonseed %s - %s %d - -" % (phrase.replace(" ", "_"), ent.hex(), int(TonSeedUtils.IsBasicSeed(ent))))

# --- Zcash Orchard unified address from the BIP39 seed (ZIP-32 m/32'/133'/account', default diversifier) ---
ZREF = os.path.join(HERE, "..", "build", "refzcash")
if os.path.isdir(ZREF):
    sys.path.insert(0, ZREF)
    from zcash_test_vectors.unified_encoding import encode_unified
    from zcash_test_vectors.orchard.key_components import ExtendedSpendingKey, FullViewingKey
    from zcash_test_vectors.hd_common import hardened
    for seed in SEEDS[:2]:
        for acct in (0, 3):
            k = ExtendedSpendingKey.master(seed).child(hardened(32)).child(hardened(133)).child(hardened(acct))
            fvk = FullViewingKey.from_spending_key(k)
            out.append("chain zecu %s m/32'/133'/%d' %s" % (seed.hex(), acct, encode_unified([(3, fvk.default_d() + bytes(fvk.default_pkd()))], "u")))

# --- custom coins: a two byte base58 version, and the public key as hex ---
# line: custom <curve 0 secp | 1 ed25519> <kind: p2pkh | pubhex> <param> <hrp | -> <seed hex> <path> <expected>
for seed in SEEDS[:2]:
    for p in ("m/44'/133'/0'/0/0", "m/44'/9'/1'/0/4"):
        k = secp(seed, p)
        out.append("custom 0 p2pkh %d - %s %s %s" % (0x1cb8, seed.hex(), p, P2PKHAddrEncoder.EncodeKey(k, net_ver=bytes([0x1c, 0xb8]))))
        out.append("custom 0 pubhex 0 - %s %s %s" % (seed.hex(), p, k.RawCompressed().ToHex()))
    for p in ("m/44'/501'/0'/0'", "m/44'/9'/3'/2'"):
        k = ed(seed, p)
        out.append("custom 1 pubhex 0 - %s %s %s" % (seed.hex(), p, k.RawCompressed().ToBytes()[1:].hex()))

# --- derivation path parsing ---
for t, want in [
    ("m/44'/0'/0'/0/0", "m/44'/0'/0'/0/0"), ("m/44h/0H/0'/0/0", "m/44'/0'/0'/0/0"), ("M/1/2", "m/1/2"), ("m", "m"),
    ("44'/60'/0'", "m/44'/60'/0'"), ("m/2147483647'", "m/2147483647'"), ("m/0", "m/0"),
    ("m/2147483648", "err -2"), ("m/99999999999", "err -2"), ("m/1//2", "err -1"), ("m/", "err -1"), ("m/a", "err -1"),
    ("m/1'/", "err -1"), ("x/1", "err -1"), ("m/1''", "err -1"), ("m/-1", "err -1"), ("m/1 /2", "err -1"),
    ("m/0/1/2/3/4/5/6/7/8/9", "m/0/1/2/3/4/5/6/7/8/9"), ("m/0/1/2/3/4/5/6/7/8/9/10", "err -3"),
]:
    out.append("path %s %s" % (t.replace(" ", "_"), want.replace(" ", "_")))

# --- BLAKE2b ---
for n in [0, 1, 3, 63, 64, 65, 127, 128, 129, 200, 256, 1000]:
    m = rb(n)
    for ol in (64, 32, 28, 1):
        out.append("blake2b %d - - - %s %s" % (ol, hx(m), hashlib.blake2b(m, digest_size=ol).hexdigest()))
for kl in (1, 32, 64):
    k, m = rb(kl), rb(130)
    out.append("blake2b 64 %s - - %s %s" % (hx(k), hx(m), hashlib.blake2b(m, digest_size=64, key=k).hexdigest()))
    out.append("blake2b 32 %s - - - %s" % (hx(k), hashlib.blake2b(b"", digest_size=32, key=k).hexdigest()))
for pers in (b"ZcashIP32Orchard", b"Zcash_ExpandSeed", b"z.cash:Orchard-gd"[:16]):
    m = rb(77)
    out.append("blake2b 64 - - %s %s %s" % (hx(pers), hx(m), hashlib.blake2b(m, digest_size=64, person=pers).hexdigest()))
    s = rb(16)
    out.append("blake2b 32 - %s %s %s %s" % (hx(s), hx(pers), hx(m), hashlib.blake2b(m, digest_size=32, salt=s, person=pers).hexdigest()))

with open(os.path.join(HERE, "..", "tests", "chain_vectors.txt"), "w", newline="\n") as f:
    f.write("\n".join(out) + "\n")
print(len(out), "vectors")
