#!/usr/bin/env python3
"""Vectors for ed25519_scalarmult_base (fixed base table): a scalar as 32 little-endian bytes (used as is, up to 2^256 - 1) and
the encoded point scalar * B, computed here with plain integer Edwards arithmetic (RFC 8032), no libraries.
Edge cases of the signed 4 bit digit recoding. Output: tests/ed_fb_vectors.txt"""
import os, random
HERE = os.path.dirname(os.path.abspath(__file__))
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
L = 2**252 + 27742317777372353535851937790883648493
BY = 4 * pow(5, P - 2, P) % P
def recover_x(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P: x = x * pow(2, (P - 1) // 4, P) % P
    if x & 1 != sign: x = P - x
    return x
BX = recover_x(BY, 0)
def add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a = (y1 - x1) * (y2 - x2) % P; b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P; d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)
def mul(k):
    q = (0, 1, 1, 0); b = (BX, BY, 1, BX * BY % P)
    while k:
        if k & 1: q = add(q, b)
        b = add(b, b); k >>= 1
    return q
def enc(p):
    zi = pow(p[2], P - 2, P); x = p[0] * zi % P; y = p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

ks = list(range(1, 41)) + [L - i for i in range(1, 11)] + [L + i for i in range(0, 6)] + [2**256 - 1 - i for i in range(6)]
for nib in (0x8, 0x9, 0xF, 0x7, 0x1, 0xA):
    for run in (1, 2, 17, 32, 63, 64):
        ks.append(int(("%x" % nib) * run, 16))
for b in range(0, 256, 5):
    ks.append(1 << b)
    ks.append((1 << b) - 1 if b else 1)
rnd = random.Random(0x4544)
ks += [rnd.randrange(1, L) for _ in range(40)]
ks += [rnd.getrandbits(256) | 1 for _ in range(20)]
for h in range(10):                                   # clamped, like a SHA-512 half
    v = rnd.getrandbits(256); v &= ~7; v &= ~(1 << 255); v |= 1 << 254; ks.append(v)
out = ["%s %s" % (k.to_bytes(32, "little").hex(), enc(mul(k)).hex()) for k in ks]
open(os.path.join(HERE, "..", "tests", "ed_fb_vectors.txt"), "w").write("\n".join(out) + "\n")
print(len(out), "vectors")
