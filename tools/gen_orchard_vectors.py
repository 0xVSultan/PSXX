#!/usr/bin/env python3
"""Known-answer vectors for core/ec/pallas.c and core/coin/orchard.c.

Sources: the official zcash-test-vectors JSON files (group hash, Sinsemilla, F4Jumble, ZIP-32 Orchard, Orchard key components)
and its Python reference for the unified addresses. Clone https://github.com/zcash/zcash-test-vectors into build/refzcash
and run with  python -I tools/gen_orchard_vectors.py
Output: tests/orchard_vectors.txt
  ogh <domain hex> <msg hex | -> <point hex>
  osin <domain hex> <bits as 0/1 characters> <hash hex>
  of4 <normal hex> <jumbled hex>
  okeys <sk> <ak> <nk> <rivk> <ivk> <dk> <ovk> <default d> <default pk_d>
  ozip <seed hex> <hardened index list, comma separated> <sk> <chain code>
  oua <sk hex> <default d + pk_d hex> <unified address>
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(HERE, "..", "build", "refzcash")
sys.path.insert(0, REF)
J = os.path.join(REF, "test-vectors", "json")
out = []

def rows(name):
    return [r for r in json.load(open(os.path.join(J, name + ".json"))) if len(r) > 1]   # the two header rows have one entry

def hx(s): return s if s else "-"

for d, m, pt in rows("orchard_group_hash"):
    if True:
        out.append("ogh %s %s %s" % (d, hx(m), pt))
for d, bits, pt, h in rows("orchard_sinsemilla"):
    if isinstance(bits, list):
        bits = "".join(str(int(b)) for b in bits)
    else:                                  # a hex string of bytes, one byte (0 or 1) per bit
        bits = "".join("1" if b else "0" for b in bytes.fromhex(bits))
    out.append("osin %s %s %s" % (d, bits, h))
for n, j in rows("f4jumble"):
    out.append("of4 %s %s" % (n, j))
for r in rows("orchard_key_components")[:4]:
    sk, ask, ak, nk, rivk, ivk, ovk, dk, d, pkd = r[:10]
    out.append("okeys %s %s %s %s %s %s %s %s %s" % (sk, ak, nk, rivk, ivk, dk, ovk, d, pkd))
seed = bytes(range(32)).hex()
z = rows("orchard_zip32")
for steps, r in zip(["", "1", "1,2", "1,2,3"], z):
    out.append("ozip %s %s %s %s" % (seed, steps or "-", r[0], r[1]))

# unified addresses (Orchard receiver only) from the reference implementation
from zcash_test_vectors.unified_encoding import encode_unified
from zcash_test_vectors.orchard.key_components import SpendingKey, FullViewingKey
for sk in (bytes(range(32)), bytes.fromhex("5d7a8f739a2d9e945b0ce152a8049e294c4d6e66b164939daffa2ef6ee692148")):
    fvk = FullViewingKey.from_spending_key(SpendingKey(sk))
    raw = fvk.default_d() + bytes(fvk.default_pkd())
    out.append("oua %s %s %s" % (sk.hex(), raw.hex(), encode_unified([(3, raw)], "u")))

with open(os.path.join(HERE, "..", "tests", "orchard_vectors.txt"), "w", newline="\n") as f:
    f.write("\n".join(out) + "\n")
print(len(out), "vectors")
