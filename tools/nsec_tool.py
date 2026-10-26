"""Signs a Nostr event with a key you have as an nsec (or as 64 hex digits), on your own machine, until the signer of the console can import it. Not production code: the key is a plain argument.

  py -3.13 tools/nsec_tool.py sign <event.json> <nsec1...|64 hex> [--expect HEX64]   the signature (128 hex digits); attach it with release.py attach-manifest / attach --sig
  py -3.13 tools/nsec_tool.py hex <nsec1...>                                          the nsec as 64 hex digits (what the Raw key (hex) import of the generator takes)
  py -3.13 tools/nsec_tool.py npub <nsec1...|64 hex>                                  the public key (hex and npub) of the key
  py -3.13 tools/nsec_tool.py selftest

The key stays in your shell history (it is an argument), nothing is written to a file and nothing uses the network. `sign` takes an event without id, pubkey and sig (manifest_event.json):
kind, created_at, tags, content. The public key of the key is shown; with --expect (default: the key of the release.json next to the event) the signature is refused when the key is another
one, so a wrong nsec cannot make a signature that fails later."""
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340

CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)


def _poly(vals):
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for k in range(5):
            if (b >> k) & 1:
                chk ^= GEN[k]
    return chk


def _hrp(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]


def bech32_encode(hrp, data):
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
    pm = _poly(_hrp(hrp) + five + [0] * 6) ^ 1
    return hrp + "1" + "".join(CH[v] for v in five + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def bech32_decode(s):
    s = s.strip()
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    hrp, sep, rest = s.rpartition("1")
    if not sep or not hrp or len(rest) < 6 or any(c not in CH for c in rest):
        raise ValueError("not a bech32 string")
    vals = [CH.index(c) for c in rest]
    if _poly(_hrp(hrp) + vals) != 1:
        raise ValueError("invalid checksum")
    acc, bits, out = 0, 0, bytearray()
    for v in vals[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
            acc &= (1 << bits) - 1
    return hrp, bytes(out)


def key_of(text):
    """the 32 byte secret key of an nsec1... or of 64 hex digits"""
    t = text.strip().strip("\"'")
    if len(t) == 64 and not t.lower().startswith("nsec"):
        try:
            k = bytes.fromhex(t)
        except ValueError:
            raise ValueError("not hex")
    else:
        hrp, k = bech32_decode(t)
        if hrp != "nsec" or len(k) != 32:
            raise ValueError("not an nsec")
    if not 1 <= int.from_bytes(k, "big") < bip340.N:
        raise ValueError("not a valid secp256k1 key")
    return k


def sign_event(sk, ev):
    """(public key, event id, signature) of an event dict with kind, created_at, tags, content"""
    pub = bip340.pubkey(sk)
    body = json.dumps([0, pub.hex(), ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(body.encode()).digest()
    return pub, eid, bip340.sign(sk, eid)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign")
    s.add_argument("event")
    s.add_argument("key", help="nsec1... or 64 hex digits")
    s.add_argument("--expect", help="the public key (64 hex digits) the signature has to be for")
    sub.add_parser("hex").add_argument("key")
    sub.add_parser("npub").add_argument("key")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "selftest":
        sys.exit(selftest())
    try:
        sk = key_of(a.key)
    except ValueError as e:
        sys.exit("cannot read the key (%d characters): %s" % (len(a.key.strip()), e))
    if a.cmd == "hex":
        print(sk.hex())
    elif a.cmd == "npub":
        pub = bip340.pubkey(sk)
        print(pub.hex())
        print(bech32_encode("npub", pub))
    else:
        ev = json.load(open(a.event, encoding="utf-8"))
        exp = a.expect
        rj = os.path.join(os.path.dirname(os.path.abspath(a.event)), "release.json")
        if not exp and os.path.exists(rj):
            exp = json.load(open(rj))["key"]
        pub, eid, sig = sign_event(sk, ev)
        print("public key %s\nevent id   %s" % (pub.hex(), eid.hex()), file=sys.stderr)
        if exp and exp.lower() != pub.hex():
            sys.exit("this is not the release key (%s): no signature made" % exp)
        print(sig.hex())


def selftest():
    import sign_key
    import pkg_pack as P
    bad = 0

    def check(name, cond):
        nonlocal bad
        print("%-60s %s" % (name, "ok" if cond else "FAILED"))
        bad += not cond
    sk = hashlib.sha256(b"psxx nsec_tool throwaway").digest()
    nsec = bech32_encode("nsec", sk)
    check("nsec round trip", key_of(nsec) == sk and key_of(sk.hex()) == sk and key_of(nsec.upper()) == sk)
    check("a wrong checksum is refused", not any(_try(lambda: key_of(nsec[:-1] + c)) for c in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" if c != nsec[-1]))
    check("an npub is not taken as a key", not _try(lambda: key_of(bech32_encode("npub", bip340.pubkey(sk)))))
    check("zero and a key above the order are refused", not _try(lambda: key_of("00" * 32)) and not _try(lambda: key_of("ff" * 32)))
    ev = {"kind": 30078, "created_at": 1793010205, "tags": [["d", "psxx/release/x"]], "content": "{\"a\":\"é\"}"}
    pub, eid, sig = sign_event(sk, ev)
    check("the signature verifies", bip340.verify(pub, eid, sig))
    # the same algorithm signs the package event of the repo: the dev key gives the signature that pkg_pack made
    dk = sign_key.secret()
    pkg, dpub = P.build(P.KIND["overlay"], [(1, b"x" * 100, "stored")], b"\0" * 32, key=dk)
    te = P.HEADER + P.ENTRY
    dg = P.digest(pkg[:te]).hex()
    p2, e2, s2 = sign_event(dk, {"kind": P.EVENT_KIND, "created_at": P.EVENT_TIME, "tags": [["d", dg]], "content": dg})
    check("same signature as pkg_pack for the same event", s2 == pkg[te:te + P.SIG] and p2 == dpub)
    print("selftest: %d failed" % bad)
    return 1 if bad else 0


def _try(f):
    try:
        f()
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()
