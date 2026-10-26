"""tests/chacha_vectors.txt: ChaCha20-Poly1305 (no additional data) vectors from the cryptography package, for tests/test_chacha.c."""
import os, random
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
HERE = os.path.dirname(os.path.abspath(__file__))
rnd = random.Random(8439)
out = []
lens = list(range(0, 70)) + [127, 128, 129, 563, 564, 580, 600]
for n in lens:
    key, nonce, pt = (bytes(rnd.randrange(256) for _ in range(k)) for k in (32, 12, n))
    ct = ChaCha20Poly1305(key).encrypt(nonce, pt, None)
    out.append("cc %s %s %s %s" % (key.hex(), nonce.hex(), pt.hex() or "-", ct.hex()))
# the nonce of the Zcash note encryption is all zero
for n in (564, 64):
    key, pt = bytes(rnd.randrange(256) for _ in range(32)), bytes(rnd.randrange(256) for _ in range(n))
    out.append("cc %s %s %s %s" % (key.hex(), bytes(12).hex(), pt.hex(), ChaCha20Poly1305(key).encrypt(bytes(12), pt, None).hex()))
open(os.path.join(HERE, "..", "tests", "chacha_vectors.txt"), "w").write("\n".join(out) + "\n")
print(len(out), "vectors")
