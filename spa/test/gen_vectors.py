"""Test vectors of the verifier page from the Python reference code (tools/bip340.py, lzma, hashlib): spa/test/vectors.json.

  py -3.13 spa/test/gen_vectors.py"""
import hashlib, json, lzma, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import bip340

rnd = random.Random(340)
v = {"sha256": [], "bip340": [], "lzma": [], "bech32": []}
for n in (0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 1000, 4097):
    m = bytes(rnd.randrange(256) for _ in range(n))
    v["sha256"].append({"msg": m.hex(), "digest": hashlib.sha256(m).hexdigest(), "tagged": bip340.tagged("PSXX/package", m).hex()})
for i in range(6):
    sk = bytes(rnd.randrange(256) for _ in range(32))
    msg = bytes(rnd.randrange(256) for _ in range(32))
    sig = bip340.sign(sk, msg)
    v["bip340"].append({"pub": bip340.pubkey(sk).hex(), "msg": msg.hex(), "sig": sig.hex(), "ok": True})
    bad = bytearray(sig)
    bad[40 + i] ^= 1
    v["bip340"].append({"pub": bip340.pubkey(sk).hex(), "msg": msg.hex(), "sig": bytes(bad).hex(), "ok": False})
    v["bip340"].append({"pub": bip340.pubkey(sk).hex(), "msg": bytes(32).hex(), "sig": sig.hex(), "ok": False})
words = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"\0\0\0\0", b"\xff\xfe"]
for lc, lp, pb in ((1, 2, 2), (0, 0, 0), (3, 0, 2), (2, 1, 1), (4, 0, 0)):
    raw = b"".join(words[rnd.randrange(len(words))] + bytes(rnd.randrange(3) for _ in range(rnd.randrange(6))) for _ in range(3000))
    c = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 9, "dict_size": 1 << 18, "lc": lc, "lp": lp, "pb": pb}])
    v["lzma"].append({"lc": lc, "lp": lp, "pb": pb, "raw_sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "stream": c.hex()})
# an npub: the key of the trophy release
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(vals):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for x in vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ x
        for k in range(5):
            if (b >> k) & 1:
                chk ^= gen[k]
    return chk


def b32(hrp, data):
    acc, bits, five = 0, 0, []
    for x in data:
        acc = (acc << 8) | x
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
            acc &= (1 << bits) - 1
    if bits:
        five.append((acc << (5 - bits)) & 31)
    hv = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(hv + five + [0] * 6) ^ 1
    return hrp + "1" + "".join(CH[x] for x in five + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


for _ in range(3):
    k = bytes(rnd.randrange(256) for _ in range(32))
    v["bech32"].append({"npub": b32("npub", k), "key": k.hex()})
json.dump(v, open(os.path.join(HERE, "vectors.json"), "w"), indent=1)
print("vectors.json:", {k: len(x) for k, x in v.items()})
