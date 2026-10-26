#!/usr/bin/env python3
"""Known-answer vectors for the signature primitives of core/ec (secp256k1: ECDSA, BIP340, taproot tweak).

References: python-ecdsa (RFC 6979 nonce, deterministic ECDSA), the BIP340 reference algorithm written out below (checked against
the first official test vector). Run with
    python -I tools/gen_sign_vectors.py
Output: tests/sign_vectors.txt, lines
    ecdsa   <priv> <hash> <r||s> <recid>
    schnorr <priv> <aux> <msg> <sig>
    tweak   <priv> <merkle | -> <tweaked priv>
    ed25519 <seed> <message> <sig>
    edext   <kL> <kR> <message> <sig>        (Cardano BIP32-Ed25519: the scalar kL as is, kR the nonce prefix)
    sr25519 <mini secret> <message> <sig>    (made by build/host/sign_tool, checked with py-sr25519 here; needs the 3.13 Python)
"""
import hashlib, os, random, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from ecdsa import SigningKey, SECP256k1, util
from ecdsa.ellipticcurve import Point

G = SECP256k1.generator
CURVE = SECP256k1.curve
P = CURVE.p()
N = SECP256k1.order
rnd = random.Random(0x5349474E)
out = []


def rb(n):
    return bytes(rnd.getrandbits(8) for _ in range(n))


def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def point_from_x(x, odd):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y & 1) != odd:
        y = P - y
    return Point(CURVE, x, y)


def ecdsa_sign(priv, h):
    sk = SigningKey.from_string(priv, curve=SECP256k1, hashfunc=hashlib.sha256)
    sig = sk.sign_digest_deterministic(h, hashfunc=hashlib.sha256, sigencode=util.sigencode_string)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if s > N // 2:
        s = N - s
    pub = G * int.from_bytes(priv, "big")
    z = int.from_bytes(h, "big")
    for rec in range(4):
        x = r + (N if rec & 2 else 0)
        if x >= P:
            continue
        R = point_from_x(x, rec & 1)
        Q = (R * s + G * ((-z) % N)) * pow(r, -1, N)
        if Q == pub:
            return r, s, rec
    raise SystemExit("no recovery id")


def schnorr_sign(priv, msg, aux):
    d0 = int.from_bytes(priv, "big")
    Pt = G * d0
    d = d0 if Pt.y() % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + Pt.x().to_bytes(32, "big") + msg), "big") % N
    R = G * k0
    k = k0 if R.y() % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", R.x().to_bytes(32, "big") + Pt.x().to_bytes(32, "big") + msg), "big") % N
    return R.x().to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


# the first BIP340 test vector
sig0 = schnorr_sign((3).to_bytes(32, "big"), bytes(32), bytes(32))
assert sig0.hex().upper() == ("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                              "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"), "BIP340 vector 0"

# ECDSA: small and large keys, hashes close to n, repeated hashes
privs = [(1).to_bytes(32, "big"), (N - 1).to_bytes(32, "big"), bytes.fromhex("46" * 32)]
privs += [rb(32) for _ in range(60)]
for pr in privs:
    for h in [rb(32) for _ in range(3)] + [bytes(32), b"\xff" * 32, (N - 1).to_bytes(32, "big"), N.to_bytes(32, "big")]:
        r, s, rec = ecdsa_sign(pr, h)
        out.append("ecdsa %s %s %s %d" % (pr.hex(), h.hex(), r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex(), rec))

# BIP340
for pr in [(3).to_bytes(32, "big"), (N - 2).to_bytes(32, "big")] + [rb(32) for _ in range(60)]:
    for _ in range(3):
        aux, msg = rb(32), rb(32)
        out.append("schnorr %s %s %s %s" % (pr.hex(), aux.hex(), msg.hex(), schnorr_sign(pr, msg, aux).hex()))
    out.append("schnorr %s %s %s %s" % (pr.hex(), "00" * 32, "00" * 32, schnorr_sign(pr, bytes(32), bytes(32)).hex()))

# taproot key path tweak (BIP341): d' = (d or n - d) + t
for pr in [rb(32) for _ in range(40)]:
    d0 = int.from_bytes(pr, "big")
    Pt = G * d0
    d = d0 if Pt.y() % 2 == 0 else N - d0
    for merkle in (b"", rb(32)):
        t = int.from_bytes(tagged("TapTweak", Pt.x().to_bytes(32, "big") + merkle), "big")
        out.append("tweak %s %s %s" % (pr.hex(), merkle.hex() or "-", ((d + t) % N).to_bytes(32, "big").hex()))

# ---- Ed25519 (RFC 8032) and the Cardano extended key variant ----
from ecdsa import Ed25519
EG = Ed25519.generator
EL = EG.order()


def ed_sign_scalar(a, prefix, msg):
    A = (EG * a).to_bytes()
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % EL
    R = (EG * r).to_bytes()
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % EL
    return A, R + ((r + k * a) % EL).to_bytes(32, "little")


def ed_seed_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248; a[31] &= 127; a[31] |= 64
    return ed_sign_scalar(int.from_bytes(a, "little"), h[32:], msg)


# RFC 8032 test 1
A0, s0 = ed_seed_sign(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), b"")
assert s0.hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"), "RFC 8032 vector 1"
for i in range(80):
    seed = rb(32)
    msg = rb([0, 1, 31, 32, 33, 64, 100, 300, 1232][i % 9])
    A, sig = ed_seed_sign(seed, msg)
    Ed25519vk = __import__("ecdsa").VerifyingKey.from_string(A, curve=Ed25519)
    assert Ed25519vk.verify(sig, msg)
    out.append("ed25519 %s %s %s" % (seed.hex(), msg.hex() or "-", sig.hex()))
for i in range(60):
    kl, kr = bytearray(rb(32)), rb(32)
    kl[0] &= 248; kl[31] &= 31; kl[31] |= 64
    msg = rb([0, 32, 33, 100, 500][i % 5])
    A, sig = ed_sign_scalar(int.from_bytes(kl, "little"), kr, msg)
    assert __import__("ecdsa").VerifyingKey.from_string(A, curve=Ed25519).verify(sig, msg)
    out.append("edext %s %s %s %s" % (bytes(kl).hex(), kr.hex(), msg.hex() or "-", sig.hex()))

# ---- sr25519 (Schnorrkel, signing context "substrate"): C signs, py-sr25519 verifies ----
TOOL = os.path.join(HERE, "..", "build", "host", "sign_tool.exe")
try:
    import sr25519
except ImportError:
    sr25519 = None
if sr25519 and os.path.exists(TOOL):
    for i in range(40):
        mini = rb(32)
        msg = rb([0, 1, 32, 33, 100, 300][i % 6])
        sig = bytes.fromhex(subprocess.check_output([TOOL, "sr25519", mini.hex(), msg.hex()]).decode().strip())
        pub = sr25519.pair_from_seed(mini)[0]
        assert sr25519.verify(sig, msg, pub), "sr25519 signature rejected (vector %d)" % i
        out.append("sr25519 %s %s %s" % (mini.hex(), msg.hex() or "-", sig.hex()))
else:
    print("note: sr25519 vectors skipped (need the 3.13 Python with py-sr25519 and build/host/sign_tool.exe)")

open(os.path.join(HERE, "..", "tests", "sign_vectors.txt"), "w", newline="\n").write("\n".join(out) + "\n")
print("wrote tests/sign_vectors.txt (%d vectors)" % len(out))
