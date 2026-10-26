#!/usr/bin/env python3
"""Known-answer vectors for the multisig wallets of the signer (core/sign/mswallet.c, core/ec/secp_pub.c).

References: bip_utils (BIP32 public derivation, extended key text), hashlib. Run with
    python -I tools/gen_ms_vectors.py
Output: tests/ms_vectors.txt, lines
    ckd <parent pub> <chain code> <index> <child pub> <child chain code>
    msdesc <seed hex> <descriptor> <ours index | -1> <m> <n> <type 1 wsh 2 sh-wsh 3 sh> <sorted> <k> { <chain> <index> <script hex> <output script hex> }*k
    mserr <descriptor> <error code>
"""
import hashlib, os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import Bip32Slip10Secp256k1

rnd = random.Random(0x4D53494720)
out = []


def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))
def sha256(b): return hashlib.sha256(b).digest()
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()


def desc_checksum(desc):
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


assert desc_checksum("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)") == "8zl0zxma"


def master_fp(seed):
    return hash160(Bip32Slip10Secp256k1.FromSeed(seed).PublicKey().RawCompressed().ToBytes())[:4]


def child(node, i):
    return node.ChildKey(i)


# ---- CKDpub ----
for _ in range(24):
    node = Bip32Slip10Secp256k1.FromSeed(rb(32))
    node = node.DerivePath("m/%d'/%d" % (rnd.randrange(100), rnd.randrange(5)))
    pub = Bip32Slip10Secp256k1.FromExtendedKey(node.PublicKey().ToExtended())            # a public node
    for idx in (0, 1, rnd.randrange(1 << 20), rnd.randrange(1 << 31), (1 << 31) - 1):
        c = child(pub, idx)
        out.append("ckd %s %s %d %s %s" % (pub.PublicKey().RawCompressed().ToBytes().hex(), pub.ChainCode().ToBytes().hex(), idx,
                                           c.PublicKey().RawCompressed().ToBytes().hex(), c.ChainCode().ToBytes().hex()))

# ---- descriptors ----
TYPES = {1: ("wsh(%s)", "m/48'/0'/0'/2'"), 2: ("sh(wsh(%s))", "m/48'/0'/0'/1'"), 3: ("sh(%s)", "m/45'")}


def build(seeds, m, typ, sorted_, suffixes, checksum, our_seed):
    fmt, path = TYPES[typ]
    keys = []
    for sd, suf in zip(seeds, suffixes):
        acc = Bip32Slip10Secp256k1.FromSeed(sd).DerivePath(path)
        x = acc.PublicKey().ToExtended()
        origin = path.replace("m", master_fp(sd).hex(), 1).replace("'", "h")
        keys.append(("[%s]%s%s" % (origin, x, suf), Bip32Slip10Secp256k1.FromExtendedKey(x)))
    body = fmt % (("sortedmulti(%d," if sorted_ else "multi(%d,") % m + ",".join(k[0] for k in keys) + ")")
    desc = body + ("#" + desc_checksum(body) if checksum else "")
    ours = -1
    for i, sd in enumerate(seeds):
        if sd == our_seed: ours = i
    addrs = []
    for chain, idx in ((0, 0), (1, 0), (0, 5), (1, 19), (0, rnd.randrange(1 << 31)), (1, (1 << 31) - 1)):
        pubs = [child(child(k[1], chain), idx).PublicKey().RawCompressed().ToBytes() for k in keys]
        if sorted_: pubs.sort()
        script = bytes([0x50 + m]) + b"".join(bytes([33]) + p for p in pubs) + bytes([0x50 + len(pubs), 0xae])
        if typ == 1: spk = b"\x00\x20" + sha256(script)
        elif typ == 2: spk = b"\xa9\x14" + hash160(b"\x00\x20" + sha256(script)) + b"\x87"
        else: spk = b"\xa9\x14" + hash160(script) + b"\x87"
        addrs.append((chain, idx, script, spk))
    return desc, ours, addrs, body


SUFS = ["/<0;1>/*", "/0/*", "/**", "/1/*", ""]
cases = [(2, 3), (1, 1), (2, 2), (3, 5), (5, 8), (1, 2), (4, 4), (2, 7)]
first = None
for case in range(24):
    m, n = cases[case % len(cases)]
    typ = 1 + case % 3
    sorted_ = case % 4 != 3
    seeds = [rb(64) for _ in range(n)]
    our = seeds[rnd.randrange(n)] if case % 6 != 5 else rb(64)           # now and then a seed that is not in it
    if case % 6 != 5: pass
    desc, ours, addrs, body = build(seeds, m, typ, sorted_, [rnd.choice(SUFS) for _ in seeds], case % 2 == 0, our)
    out.append("msdesc %s %s %d %d %d %d %d %d%s" % (our.hex(), desc, ours, m, n, typ, int(sorted_), len(addrs),
               "".join(" %d %d %s %s" % (c, i, s.hex(), k.hex()) for c, i, s, k in addrs)))
    if first is None: first = (desc, body)

# ---- descriptors that must be refused ----
desc, body = first
bad = desc[:-1] + ("q" if desc[-1] != "q" else "p")
out.append("mserr %s -2" % bad)                                              # checksum
out.append("mserr %s -4" % body.replace("[", "", 1).replace("]", "", 1) if False else "mserr %s -4" % (body[:body.index("[")] + body[body.index("]") + 1:]))   # no origin on the first key
out.append("mserr %s -1" % body.replace("wsh(", "wpkh(", 1))                # not a multisig form
out.append("mserr %s -1" % (body + ")"))                                    # an extra parenthesis
out.append("mserr wsh(sortedmulti(2,%s) -1" % body[body.index("["):-2])               # a missing parenthesis
sd = rb(64)
acc = Bip32Slip10Secp256k1.FromSeed(sd).DerivePath("m/48'/0'/0'/2'")
prv = acc.PrivateKey().ToExtended() if hasattr(acc.PrivateKey(), "ToExtended") else None
if prv:
    out.append("mserr wsh(sortedmulti(1,[%s/48h/0h/0h/2h]%s/<0;1>/*)) -3" % (master_fp(sd).hex(), prv))   # a private key
x = acc.PublicKey().ToExtended()
out.append("mserr wsh(sortedmulti(1,[%s/48h/0h]%s/<0;1>/*)) -4" % (master_fp(sd).hex(), x))                # the depth does not fit the origin
out.append("mserr wsh(sortedmulti(2,[%s/48h/0h/0h/2h]%s/<0;1>/*)) -5" % (master_fp(sd).hex(), x))         # m > n
nine = ",".join("[%s/48h/0h/0h/2h]%s" % (master_fp(sd).hex(), x) for _ in range(9))
out.append("mserr wsh(sortedmulti(2,%s)) -5" % nine)                                                        # nine keys
out.append("mserr wsh(sortedmulti(1,[%s/48h/0h/0h/2h]%s/2/*)) -1" % (master_fp(sd).hex(), x))               # a suffix that is neither chain pair nor 0 / 1

open(os.path.join(HERE, "..", "tests", "ms_vectors.txt"), "w", newline="\n").write("\n".join(out) + "\n")
print("wrote tests/ms_vectors.txt (%d vectors)" % len(out))
