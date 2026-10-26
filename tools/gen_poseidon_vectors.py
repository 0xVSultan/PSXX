"""tests/poseidon_vectors.txt from the reference implementation (build/refzcash): permutations and hashes of random inputs."""
import os, sys, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "build", "refzcash"))
from zcash_test_vectors.orchard import poseidon as P
from zcash_test_vectors.orchard.pallas import Fp, p
rnd = random.Random(7)
def h(x): return x.s.to_bytes(32, "little").hex()
out = []
ins = [[Fp(0), Fp(1), Fp(2)]] + [[Fp(rnd.randrange(p)) for _ in range(3)] for _ in range(6)]
for i in ins:
    out.append("perm %s %s" % (" ".join(h(x) for x in i), " ".join(h(x) for x in P.perm(i))))
for _ in range(8):
    x, y = Fp(rnd.randrange(p)), Fp(rnd.randrange(p))
    out.append("hash %s %s %s" % (h(x), h(y), h(P.hash(x, y))))
open(os.path.join(HERE, "..", "tests", "poseidon_vectors.txt"), "w").write("\n".join(out) + "\n")
print(len(out), "vectors")
