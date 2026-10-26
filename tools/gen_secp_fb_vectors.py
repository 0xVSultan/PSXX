#!/usr/bin/env python3
"""Vectors for secp256k1_pubkey_create (fixed base table): k and the uncompressed public key, from bip_utils (python -I).
Edge cases of the signed 4 bit digit recoding: small k, runs of nibbles 8 / 9 / 15 / 0, k near n. Output: tests/secp_fb_vectors.txt"""
import os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import Secp256k1PrivateKey

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ks = list(range(1, 41)) + [N - i for i in range(1, 21)]
for nib in (0x8, 0x9, 0xF, 0x7, 0x1, 0xA):
    for run in (1, 2, 17, 32, 63):
        ks.append(int(("%x" % nib) * run, 16) % N or 1)
for b in range(0, 256, 5):
    ks.append((1 << b) % N or 1)
    ks.append(((1 << b) - 1) % N or 1)
rnd = random.Random(0x4642)
ks += [rnd.randrange(1, N) for _ in range(60)]
out = []
for k in ks:
    pub = Secp256k1PrivateKey.FromBytes(k.to_bytes(32, "big")).PublicKey().RawUncompressed().ToHex()
    out.append("%064x %s" % (k, pub))
open(os.path.join(HERE, "..", "tests", "secp_fb_vectors.txt"), "w").write("\n".join(out) + "\n")
print(len(out), "vectors")
