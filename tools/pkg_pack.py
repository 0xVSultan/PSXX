"""Packs and checks the card packages.

  py -3.13 tools/pkg_pack.py build --kind overlay|data [--base-id HEX64|@file] --group ID=path[,lzma] ... -o out.pkg [--key-out out.key]   (signed with tools/sign_key.py)
  py -3.13 tools/pkg_pack.py info out.pkg [--key HEX64] [--kind overlay|data]

A package is: a 48 byte header, a table of 48 byte group entries, a 64 byte signature, the groups (each at a multiple of 16 bytes). Little endian.
  header: "PSXP", version u8 (3), kind u8 (1 overlay, 2 data), ngroups u16, total_len u32, flags u32 (0), base_id[32] (the id of the base image for an overlay, zeros for data)
  entry : id u16 (ascending), flags u16 (bits 0-3 codec: 0 stored, 1 LZMA; bits 4-11 the LZMA properties byte; the rest 0), offset u32, len u32 (stored bytes), rawlen u32, sha256[32] of the stored bytes
The signature is BIP340 (tools/bip340.py) over the id of a Nostr event (event_json) that carries the digest of the header and the table; so a Nostr signer can make it (`event`, `attach`); the main card holds the public key (x only), so the packages are
trusted through the signature and through the hashes of the groups in the table: a package of another release, or a language of the data card, opens if the same key signed it."""
import argparse, hashlib, lzma, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bip340, sign_key

HEADER = 48
ENTRY = 48
SIG = 64                                                # core/pkg/pkg.h PKG_SIG_SIZE
VERSION = 3
EVENT_TIME = 1792774136                                  # core/pkg/pkg.h PKG_EVENT_TIME: fixed, so that the build is repeatable
EVENT_KIND = 30078                                      # NIP-78, application specific data
ALIGN = 16                                              # core/pkg/pkg.h PKG_ALIGN
MAX_GROUPS = 48
MAX_SIZE = 122624                                       # 15 blocks of 8192 bytes less the header and icon frames of the first block (tools/mkcard.py capacity)
MAX_RAW = 4 << 20
KIND = {"overlay": 1, "data": 2}
LZMA_LC, LZMA_LP, LZMA_PB = 1, 2, 2                   # as tools/packexe.py (the stub of the image)


class PkgError(Exception):
    def __init__(self, code, text=""):
        super().__init__("%s %s" % (code, text))
        self.code = code


def up(n):
    return (n + ALIGN - 1) // ALIGN * ALIGN


def props_byte(lc=LZMA_LC, lp=LZMA_LP, pb=LZMA_PB):
    return (pb * 5 + lp) * 9 + lc


def lzma_pack(raw, lc=LZMA_LC, lp=LZMA_LP, pb=LZMA_PB):
    return lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME, "dict_size": 1 << 18,
                                                                "lc": lc, "lp": lp, "pb": pb, "nice_len": 273}])


def lzma_best(raw):
    """the smallest stream over the lc, lp, pb the unpacker takes (lc + lp <= 4, core/pkg/ovl.c; pb up to 2: more never helped here), and its properties byte"""
    best = None
    for lc in range(5):
        for lp in range(5 - lc):
            for pb in range(3):
                s = lzma_pack(raw, lc, lp, pb)
                if best is None or len(s) < len(best[0]):
                    best = (s, props_byte(lc, lp, pb))
    return best


def lzma_base_best(raw, base_image):
    """the smallest stream against the preset dictionary base_image over the lc, lp, pb the loader takes with one (lc + lp <= 4, and the dictionary a multiple of
    1 << max(lp, pb) bytes long: core/pkg/ovl.c), and its properties byte; the signer and the module of m18 came out best with 0, 2, 2 (-152 B against 1, 2, 2)"""
    import lzma_dict
    best = None
    for lc in range(5):
        for lp in range(5 - lc):
            for pb in range(5):
                if len(base_image) % (1 << max(lp, pb)):
                    continue
                s = lzma_dict.compress(raw, base_image, lc, lp, pb)
                if best is None or len(s) < len(best[0]):
                    best = (s, props_byte(lc, lp, pb))
    return best


def entry_bytes(gid, flags, offset, ln, rawlen, sha):
    return struct.pack("<HHIII", gid, flags, offset, ln, rawlen) + sha


def header_bytes(kind, n, total, base_id, version=VERSION, flags=0, magic=b"PSXP"):
    return magic + struct.pack("<BBHII", version, kind, n, total, flags) + base_id


def digest(head):
    """the SHA-256 of the header and the table under the tag of the packages"""
    return bip340.tagged("PSXX/package", head)


def event_json(pub, head):
    """the Nostr event (NIP-01 serialisation: no spaces) that the signature is of; it carries the digest of the header and the table. A Nostr signer signs its id"""
    import json
    return json.dumps([0, pub.hex(), EVENT_TIME, EVENT_KIND, [["d", digest(head).hex()]], digest(head).hex()], separators=(",", ":"), ensure_ascii=False)


def message(head, pub):
    """what the signature covers: the id of the event (core/pkg/pkg.c event_id)"""
    return hashlib.sha256(event_json(pub, head).encode()).digest()


def build(kind, groups, base_id=b"\0" * 32, base_image=None, key=None, pub=None):
    """groups: list of (id, raw bytes, codec) with codec "stored", "lzma" (lc, lp, pb 1, 2, 2), "lzma_best" (the best lc, lp, pb for the group), "lzma_base" (LZMA with
    base_image, the image of the base up to its release record, as the preset dictionary: tools/lzma_dict.py; lc, lp, pb 1, 2, 2) or "lzma_base_best" (the same with the
    best lc, lp, pb); returns (package bytes, the public key that signed it: x only, 32 bytes); key: the secret key (default: tools/sign_key.py); pub (without key): the public key of a Nostr signer, the package comes out with a zero signature, to be attached (attach)"""
    n = len(groups)
    off = up(HEADER + ENTRY * n + SIG)
    entries, body = [], bytearray()
    for gid, raw, codec in groups:
        if codec == "lzma_base":
            import lzma_dict
            stored, flags = lzma_dict.compress(raw, base_image, LZMA_LC, LZMA_LP, LZMA_PB), 2 | (props_byte() << 4)
        elif codec == "lzma_base_best":
            stored, props = lzma_base_best(raw, base_image)
            flags = 2 | (props << 4)
        elif codec == "lzma_best":
            stored, props = lzma_best(raw)
            flags = 1 | (props << 4)
        else:
            stored = lzma_pack(raw) if codec == "lzma" else raw
            flags = 1 | (props_byte() << 4) if codec == "lzma" else 0
        entries.append(entry_bytes(gid, flags, off + len(body), len(stored), len(raw), hashlib.sha256(stored).digest()))
        body += stored + b"\0" * (up(len(stored)) - len(stored))
    total = off + len(body)
    head = header_bytes(kind, n, total, base_id) + b"".join(entries)
    if pub is not None and key is None:
        sig = bytes(SIG)
    else:
        key = key or sign_key.secret()
        pub = bip340.pubkey(key)
        sig = bip340.sign(key, message(head, pub))             # deterministic (aux 0, a fixed event time): the same package comes out of the same inputs
    pkg = head + sig + b"\0" * (off - len(head) - SIG) + bytes(body)
    return pkg, pub


def resign(pkg, key):
    """the package with the signature of its (changed) header and table made again with `key`; returns (package, public key)"""
    te = HEADER + struct.unpack_from("<H", pkg, 6)[0] * ENTRY
    return pkg[:te] + bip340.sign(key, message(pkg[:te], bip340.pubkey(key))) + pkg[te + SIG:], bip340.pubkey(key)


def parse(data, key=None, kind=None):
    """The checks of core/pkg/pkg.c in the same order; returns the list of entries (dicts), raises PkgError(code)"""
    size = len(data)
    if size < HEADER + ENTRY:
        raise PkgError("SIZE")
    if data[:4] != b"PSXP":
        raise PkgError("MAGIC")
    if data[4] != VERSION:
        raise PkgError("VERSION")
    k = data[5]
    if k not in (1, 2) or (kind and k != kind):
        raise PkgError("KIND")
    n, total, flags = struct.unpack_from("<HII", data, 6)
    base_id = data[16:48]
    if n == 0 or n > MAX_GROUPS or flags != 0 or (k == 2 and any(base_id)):
        raise PkgError("HEADER")
    tbl_end = HEADER + n * ENTRY
    if total < tbl_end + SIG or total > size or total > MAX_SIZE:
        raise PkgError("HEADER")
    if key is not None and not bip340.verify(key, message(data[:tbl_end], key), data[tbl_end:tbl_end + SIG]):
        raise PkgError("PIN")
    entries, prev_id, prev_end = [], -1, up(tbl_end + SIG)
    for i in range(n):
        gid, fl, off, ln, raw = struct.unpack_from("<HHIII", data, HEADER + i * ENTRY)
        sha = data[HEADER + i * ENTRY + 16:HEADER + (i + 1) * ENTRY]
        codec, props, rsv = fl & 15, (fl >> 4) & 255, fl >> 12
        if gid <= prev_id or off % ALIGN or off < prev_end or ln == 0 or off + ln > total or rsv:
            raise PkgError("TABLE")
        if codec == 0:
            if raw != ln:
                raise PkgError("TABLE")
        elif codec in (1, 2):
            if props > 224 or raw == 0 or raw > MAX_RAW:
                raise PkgError("TABLE")
        else:
            raise PkgError("TABLE")
        entries.append({"id": gid, "flags": fl, "offset": off, "len": ln, "rawlen": raw, "sha": sha})
        prev_id, prev_end = gid, off + up(ln)
    return {"kind": k, "base_id": base_id, "total": total, "entries": entries}


def group_ok(data, e):
    return hashlib.sha256(data[e["offset"]:e["offset"] + e["len"]]).digest() == e["sha"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--kind", choices=KIND, required=True)
    b.add_argument("--base-id", default="")
    b.add_argument("--group", action="append", required=True, help="ID=path[,lzma]")
    b.add_argument("-o", required=True)
    b.add_argument("--key-out")
    b.add_argument("--pub", help="sign later with a Nostr signer: the x only public key (hex) of it; the package gets a zero signature, `event` shows what to sign")
    e = sub.add_parser("event", help="the Nostr event (and its id) of a package: what a Nostr signer has to sign")
    e.add_argument("file")
    e.add_argument("--pub", required=True)
    t = sub.add_parser("attach", help="put the signature (hex, 64 bytes) a Nostr signer made into the package; it is checked first")
    t.add_argument("file")
    t.add_argument("--pub", required=True)
    t.add_argument("--sig", required=True)
    i = sub.add_parser("info")
    i.add_argument("file")
    i.add_argument("--key")
    i.add_argument("--kind", choices=KIND)
    a = ap.parse_args()
    if a.cmd == "build":
        base = b"\0" * 32
        if a.base_id.startswith("@"):
            base = open(a.base_id[1:], "rb").read(32)
        elif a.base_id:
            base = bytes.fromhex(a.base_id)
        groups = []
        for g in a.group:
            gid, rest = g.split("=", 1)
            path, _, codec = rest.partition(",")
            groups.append((int(gid, 0), open(path, "rb").read(), codec or "stored"))
        pkg, pub = build(KIND[a.kind], groups, base, pub=bytes.fromhex(a.pub) if a.pub else None)
        open(a.o, "wb").write(pkg)
        if a.key_out:
            open(a.key_out, "w").write(pub.hex() + "\n")
        print("%s: %d bytes, %d groups, signed by %s" % (a.o, len(pkg), len(groups), pub.hex()))
    elif a.cmd in ("event", "attach"):
        data = open(a.file, "rb").read()
        pub = bytes.fromhex(a.pub)
        te = HEADER + struct.unpack_from("<H", data, 6)[0] * ENTRY
        if a.cmd == "event":
            print(event_json(pub, data[:te]))
            print("id " + message(data[:te], pub).hex())
        else:
            sig = bytes.fromhex(a.sig)
            if not bip340.verify(pub, message(data[:te], pub), sig):
                sys.exit("the signature is not valid for this package and key")
            open(a.file, "wb").write(data[:te] + sig + data[te + SIG:])
            print("signature attached to %s" % a.file)
    else:
        data = open(a.file, "rb").read()
        try:
            info = parse(data, bytes.fromhex(a.key) if a.key else None, KIND[a.kind] if a.kind else None)
        except PkgError as e:
            print("refused: %s" % e.code)
            sys.exit(1)
        print("kind %d, total %d bytes, base id %s" % (info["kind"], info["total"], info["base_id"].hex()))
        for e in info["entries"]:
            print("  group %5d: offset %6d, %6d bytes stored, %6d unpacked, codec %d, hash %s" % (e["id"], e["offset"], e["len"], e["rawlen"], e["flags"] & 15,
                                                                                               "ok" if group_ok(data, e) else "WRONG"))
        te = HEADER + len(info["entries"]) * ENTRY
        print("signature of the header and the table: %s" % ("valid" if a.key and bip340.verify(bytes.fromhex(a.key), message(data[:te], bytes.fromhex(a.key)), data[te:te + SIG]) else "not checked (no --key)"))


if __name__ == "__main__":
    main()
