"""The vectors of the C verifier of BIP340 signatures (core/ec/secp256k1.c secp256k1_schnorr_verify, tests/test_schnorrv.c): lines  ok|bad <pub> <msg> <sig>  (hex).
Made with tools/bip340.py (written from the BIP; vector 0 of the BIP is checked there). Random keys and messages: a fixed seed, so the file does not change between runs.
  py -3.13 tools/gen_schnorr_vectors.py"""
import hashlib, os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340 as B

rng = random.Random(340)
rows = []


def row(ok, pub, msg, sig):
    assert B.verify(pub, msg, sig) == ok, (ok, pub.hex())
    rows.append("%s %s %s %s" % ("ok" if ok else "bad", pub.hex(), msg.hex(), sig.hex()))


sk0 = (3).to_bytes(32, "big")
row(True, B.pubkey(sk0), b"\0" * 32, B.sign(sk0, b"\0" * 32))
for i in range(10):
    sk = rng.randrange(1, B.N).to_bytes(32, "big")
    msg = hashlib.sha256(b"message %d" % i).digest()
    pub = B.pubkey(sk)
    sig = B.sign(sk, msg, rng.randbytes(32))
    row(True, pub, msg, sig)
    flip = bytearray(sig); flip[rng.randrange(64)] ^= 1 << rng.randrange(8)
    row(False, pub, msg, bytes(flip))                                                       # one bit of the signature
    row(False, pub, hashlib.sha256(b"other %d" % i).digest(), sig)                          # another message
    row(False, B.pubkey(rng.randrange(1, B.N).to_bytes(32, "big")), msg, sig)              # another key
sk = rng.randrange(1, B.N).to_bytes(32, "big")
msg = hashlib.sha256(b"edge").digest()
pub, sig = B.pubkey(sk), B.sign(sk, msg)
row(False, pub, msg, (B.P).to_bytes(32, "big") + sig[32:])                                 # r = p
row(False, pub, msg, sig[:32] + (B.N).to_bytes(32, "big"))                                 # s = n
row(False, pub, msg, sig[:32] + b"\0" * 32)                                                # s = 0
row(False, (B.P).to_bytes(32, "big"), msg, sig)                                            # x = p
x = 5
while B.lift_x(x) is not None:
    x += 1
row(False, x.to_bytes(32, "big"), msg, sig)                                                # x not on the curve
row(False, b"\0" * 32, msg, sig)
open(os.path.join(HERE, "..", "tests", "schnorr_vectors.txt"), "w", newline="\n").write("\n".join(rows) + "\n")
print(len(rows), "vectors")
