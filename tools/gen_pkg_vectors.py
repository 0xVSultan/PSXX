"""Test vectors of the card packages for tests/test_pkg.c (tests/pkg_vectors.txt): valid packages and damaged ones, each with what core/pkg/pkg.c has to answer.

  py -3.13 tools/gen_pkg_vectors.py

Line:  name|kind|key|open|groups|package hex
  kind: the kind the caller asks for (0 any, 1 overlay, 2 data); key: the public key the signature has to be valid for, hex, or -; open: OK, MAGIC, VERSION, KIND, HEADER, PIN, TABLE, SIZE;
  groups: for every entry of the table OK (the hash of the group is right) or HASH, or - when the package is refused.
The answers are computed here by tools/pkg_pack.py (parse, group_ok), independent of the C code."""
import hashlib, os, random, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pkg_pack as P

rng = random.Random(20261022)
TESTKEY = hashlib.sha256(b"psxx test signing key").digest()               # the vectors are signed with a fixed key of their own, not the key of the releases (tools/sign_key.py)
OTHERKEY = hashlib.sha256(b"psxx another signing key").digest()
rows = []


def rnd(n):
    return bytes(rng.randrange(256) for _ in range(n))


def text(n):
    s = b"the quick brown fox jumps over the lazy dog 0123456789 "
    return (s * (n // len(s) + 1))[:n]


def answer(data, kind, pin):
    try:
        info = P.parse(data, pin, kind or None)
    except P.PkgError as e:
        return e.code, "-"
    return "OK", ",".join("OK" if P.group_ok(data, e) else "HASH" for e in info["entries"])


def add(name, data, kind=0, pin=None, expect=None):
    code, groups = answer(data, kind, pin)
    if expect is not None:
        assert code == expect, (name, code, expect)
    rows.append("%s|%d|%s|%s|%s|%s" % (name, kind, pin.hex() if pin else "-", code, groups, data.hex()))


def patch(data, off, val):
    d = bytearray(data)
    d[off] = val if isinstance(val, int) else d[off] ^ 1
    return bytes(d)


def poke32(data, off, v):
    return data[:off] + struct.pack("<I", v) + data[off + 4:]


def table_case(base_pkg, idx, **fields):
    """a package whose table has a changed field in entry idx, signed again (the signature is valid for the changed header and table)"""
    n = struct.unpack_from("<H", base_pkg, 6)[0]
    d = bytearray(base_pkg)
    o = P.HEADER + idx * P.ENTRY
    gid, fl, off, ln, raw = struct.unpack_from("<HHIII", d, o)
    gid, fl, off, ln, raw = fields.get("id", gid), fields.get("flags", fl), fields.get("offset", off), fields.get("len", ln), fields.get("rawlen", raw)
    d[o:o + 16] = struct.pack("<HHIII", gid, fl, off, ln, raw)
    return P.resign(bytes(d), TESTKEY)


base_id = hashlib.sha256(b"base image").digest()
overlay, pin_o = P.build(1, [(1, rnd(300), "stored")], base_id, key=TESTKEY)
data3, pin_d = P.build(2, [(1, rnd(200), "stored"), (7, text(1000), "lzma"), (300, rnd(5), "stored")], key=TESTKEY)
many, pin_m = P.build(2, [(i, bytes([i]), "stored") for i in range(1, 49)], key=TESTKEY)
n3 = 3
total3 = struct.unpack_from("<I", data3, 8)[0]
off7 = struct.unpack_from("<I", data3, P.HEADER + P.ENTRY + 4)[0]
len1 = struct.unpack_from("<I", data3, P.HEADER + 8)[0]
off1 = struct.unpack_from("<I", data3, P.HEADER + 4)[0]

add("valid_overlay", overlay, 1, pin_o, "OK")
add("valid_data", data3, 2, pin_d, "OK")
add("valid_any_kind", data3, 0, pin_d, "OK")
add("valid_48_groups", many, 2, pin_m, "OK")
add("valid_no_pin", data3, 0, None, "OK")
add("wrong_kind_asked", data3, 1, pin_d, "KIND")
add("bad_magic", patch(data3, 0, 1), 0, pin_d, "MAGIC")
add("bad_version", patch(data3, 4, 4), 0, pin_d, "VERSION")
add("version_1_has_no_signature", patch(data3, 4, 1), 0, pin_d, "VERSION")
add("version_2_signs_a_raw_hash", patch(data3, 4, 2), 0, pin_d, "VERSION")
# the event the signature is of: the text of NIP-01 as core/pkg/pkg.c builds it by hand has to be what json.dumps makes (no spaces), the signature is of its id
te3 = P.HEADER + 3 * P.ENTRY
pub3 = P.bip340.pubkey(TESTKEY)
hand = '[0,"%s",1792774136,30078,[["d","%s"]],"%s"]' % (pub3.hex(), P.digest(data3[:te3]).hex(), P.digest(data3[:te3]).hex())
assert P.event_json(pub3, data3[:te3]) == hand
assert P.bip340.verify(pub3, hashlib.sha256(hand.encode()).digest(), data3[te3:te3 + P.SIG])
add("signature_of_the_bare_digest", data3[:te3] + P.bip340.sign(TESTKEY, P.digest(data3[:te3])) + data3[te3 + P.SIG:], 0, pin_d, "PIN")      # the old format: the digest itself, not the event
add("bad_kind_value", patch(data3, 5, 3), 0, pin_d, "KIND")
add("header_flags", patch(data3, 12, 1), 0, pin_d, "HEADER")
add("ngroups_zero", patch(data3, 6, 0), 0, pin_d, "HEADER")
add("ngroups_49", patch(data3, 6, 49), 0, pin_d, "HEADER")
add("total_below_table", poke32(data3, 8, 190), 0, pin_d, "HEADER")
add("total_beyond_file", poke32(data3, 8, len(data3) + 128), 0, pin_d, "HEADER")
add("data_with_base_id", patch(data3, 16, 1), 0, pin_d, "HEADER")
add("table_tampered", patch(data3, P.HEADER + P.ENTRY + 12, 1), 0, pin_d, "PIN")
add("overlay_base_id_tampered", patch(overlay, 20, 1), 0, pin_o, "PIN")
add("key_of_another_signer", data3, 0, P.bip340.pubkey(OTHERKEY), "PIN")
add("signature_tampered", patch(data3, P.HEADER + 3 * P.ENTRY + 5, 1), 0, pin_d, "PIN")
add("signed_by_another_key", P.resign(data3, OTHERKEY)[0], 0, pin_d, "PIN")
add("signature_zero", data3[:P.HEADER + 3 * P.ENTRY] + bytes(P.SIG) + data3[P.HEADER + 3 * P.ENTRY + P.SIG:], 0, pin_d, "PIN")
add("group_tampered", patch(data3, off7 + 3, 1), 0, pin_d, "OK")
add("padding_tampered", patch(data3, off1 + len1 + 1, 1), 0, pin_d, "OK")
add("truncated_file", data3[:total3 - 130], 0, pin_d, "HEADER")
add("tiny_file", data3[:40], 0, pin_d, "SIZE")

# a table the signature covers (the package was built wrongly): the checks of the table itself
TABLE = {
    "unaligned_offset": (1, dict(offset=off7 + 1)),
    "overlap": (1, dict(offset=off1 + 128)),
    "ids_descending": (1, dict(id=0)),
    "duplicate_id": (1, dict(id=1)),
    "offset_in_table": (0, dict(offset=128)),                  # aligned, but before the end of the table (192)
    "offset_in_signature": (0, dict(offset=192)),              # aligned, after the table, but the signature is there (192 .. 255)
    "group_beyond_total": (1, dict(len=total3)),
    "zero_len": (2, dict(len=0)),
    "stored_rawlen_differs": (0, dict(rawlen=len1 + 1)),
    "unknown_codec": (0, dict(flags=3)),                     # 2 is LZMA against the base image
    "reserved_flag_bits": (0, dict(flags=0x1000)),
    "lzma_props_too_big": (1, dict(flags=1 | (225 << 4))),
    "lzma_rawlen_zero": (1, dict(rawlen=0)),
}
for name, (idx, f) in TABLE.items():
    d, pin = table_case(data3, idx, **f)
    add("table_" + name, d, 0, pin, "TABLE")

with open(os.path.join(HERE, "..", "tests", "pkg_vectors.txt"), "w") as fh:
    fh.write("# generated by tools/gen_pkg_vectors.py: name|kind|key|open|groups|package hex\n")
    fh.write("\n".join(rows) + "\n")
print("%d vectors written (%d bytes of hex)" % (len(rows), sum(len(r) for r in rows)))
