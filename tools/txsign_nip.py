# The NIP-44 / NIP-04 encryption and the NIP-19 forms of Nostr (core/sign/nip44.c, nip19.c, nostr.c); run inside tools/gen_txsign_vectors.py (exec'd after txsign_more.py).
# References: the NIP-44 text and its official test vectors (paulmillr/nip44: nip44.vectors.json, found in build/refpkgs/nip44ref/), python-ecdsa for the curve, the `cryptography`
# package for ChaCha20 and AES-CBC, the NIP-19 text. The nonce / IV of a request is the HMAC of the conversation key over the time and the text (a choice of this signer, see
# core/sign/nostr.h). Lines:
#   ecdh <priv> <x only pub> <x>                      nip44key <priv> <x only pub> <conversation key>          nip44keybad <priv> <pub>
#   nip44enc <conversation key> <nonce> <text hex> <payload>      nip44bad <conversation key> <payload>
#   nip04enc <key> <iv> <text hex> <payload>                       nip04bad <key> <payload>
#   nip19enc <hrp> <hex> <string>                     nip19dec <string> <type> <id|-> <author|-> <kind|-> <relay|-> <d|-> <number of relays>        nip19bad <string>
#   nostr / nostrview (as before, with "encrypt"), nostrdec <priv> <request> <text hex>, nostrdecview <priv> <request> <fields>, nostrdecfail <priv> <request>, nostrfail <priv> <request>
import hmac as _hmac, base64 as _b64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as _padding
from ecdsa.ellipticcurve import Point as _Pt

nrnd = random.Random(0x4e495034)
_P = SECP256k1.curve.p()


def nrb(n): return bytes(nrnd.getrandbits(8) for _ in range(n))
def xonly(priv): return (G * int.from_bytes(priv, "big")).x().to_bytes(32, "big")


def lift_x_even(x):
    y = pow((pow(x, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if y * y % _P != (pow(x, 3, _P) + 7) % _P:
        return None
    return _Pt(SECP256k1.curve, x, y if y % 2 == 0 else _P - y)


def ecdh_x(priv, pubx):
    pt = lift_x_even(int.from_bytes(pubx, "big"))
    return (pt * int.from_bytes(priv, "big")).x().to_bytes(32, "big")


def hmac256(k, m): return _hmac.new(k, m, hashlib.sha256).digest()


def n44_conv(priv, pubx): return hmac256(b"nip44-v2", ecdh_x(priv, pubx))


def n44_padlen(n):
    if n <= 32: return 32
    npow = 1 << (n - 1).bit_length()
    chunk = 32 if npow <= 256 else npow // 8
    return chunk * ((n - 1) // chunk + 1)


def hkdf_expand(prk, info, length):
    t, o = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac256(prk, t + info + bytes([i])); o += t
    return o[:length]


def n44_encrypt(ck, nonce, pt):
    okm = hkdf_expand(ck, nonce, 76)
    key, cn, hk = okm[:32], okm[32:44], okm[44:76]
    padded = len(pt).to_bytes(2, "big") + pt + bytes(n44_padlen(len(pt)) - len(pt))
    enc = Cipher(algorithms.ChaCha20(key, bytes(4) + cn), mode=None).encryptor().update(padded)
    return _b64.b64encode(b"\x02" + nonce + enc + hmac256(hk, nonce + enc)).decode()


def n44_decrypt(ck, payload):
    raw = _b64.b64decode(payload, validate=True)
    assert raw[0] == 2
    nonce, enc, mac = raw[1:33], raw[33:-32], raw[-32:]
    okm = hkdf_expand(ck, nonce, 76)
    assert hmac256(okm[44:76], nonce + enc) == mac
    padded = Cipher(algorithms.ChaCha20(okm[:32], bytes(4) + okm[32:44]), mode=None).decryptor().update(enc)
    n = int.from_bytes(padded[:2], "big")
    assert 0 < n <= len(padded) - 2 and len(padded) == 2 + n44_padlen(n)
    return padded[2:2 + n]


def n04_encrypt(key, iv, pt):
    pad = _padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    body = ct.update(pad.update(pt) + pad.finalize()) + ct.finalize()
    return _b64.b64encode(body).decode() + "?iv=" + _b64.b64encode(iv).decode()


def n04_decrypt(key, payload):
    c, iv = payload.split("?iv=")
    dec = Cipher(algorithms.AES(key), modes.CBC(_b64.b64decode(iv))).decryptor()
    unpad = _padding.PKCS7(128).unpadder()
    return unpad.update(dec.update(_b64.b64decode(c)) + dec.finalize()) + unpad.finalize()


# ---------------- the official NIP-44 vectors ----------------
_vf = os.path.join(HERE, "..", "build", "refpkgs", "nip44ref", "nip44.vectors.json")
if not os.path.exists(_vf):
    raise SystemExit("the official NIP-44 test vectors are missing: git clone https://github.com/paulmillr/nip44 build/refpkgs/nip44ref")
_off = json.load(open(_vf, encoding="utf-8"))["v2"]
for v in _off["valid"]["get_conversation_key"]:
    ck = n44_conv(bytes.fromhex(v["sec1"]), bytes.fromhex(v["pub2"]))
    assert ck.hex() == v["conversation_key"]
    out.append("nip44key %s %s %s" % (v["sec1"], v["pub2"], ck.hex()))
for v in _off["invalid"]["get_conversation_key"]:
    out.append("nip44keybad %s %s" % (v["sec1"], v["pub2"]))
for v in _off["valid"]["encrypt_decrypt"]:
    sec1, sec2 = bytes.fromhex(v["sec1"]), bytes.fromhex(v["sec2"])
    ck = bytes.fromhex(v["conversation_key"])
    assert n44_conv(sec1, xonly(sec2)) == ck == n44_conv(sec2, xonly(sec1))
    pt = v["plaintext"].encode("utf-8")
    assert n44_encrypt(ck, bytes.fromhex(v["nonce"]), pt) == v["payload"] and n44_decrypt(ck, v["payload"]) == pt
    out.append("nip44enc %s %s %s %s" % (ck.hex(), v["nonce"], pt.hex(), v["payload"]))
for v in _off["invalid"]["decrypt"]:
    out.append("nip44bad %s %s" % (v["conversation_key"], v["payload"]))

# ---------------- more of our own ----------------
for i in range(6):
    a, b = nrb(32), nrb(32)
    out.append("ecdh %s %s %s" % (a.hex(), xonly(b).hex(), ecdh_x(a, xonly(b)).hex()))
    assert ecdh_x(a, xonly(b)) == ecdh_x(b, xonly(a))
LENS = [1, 2, 15, 16, 17, 31, 32, 33, 47, 64, 65, 100, 255, 256, 257, 300, 511, 512, 513, 1000, 1023, 1024]
for i, n in enumerate(LENS):
    a, b = nrb(32), nrb(32)
    ck = n44_conv(a, xonly(b))
    pt = (b"x" * n) if i % 3 else bytes(nrnd.getrandbits(7) | 0x20 for _ in range(n))
    nonce = nrb(32)
    out.append("nip44enc %s %s %s %s" % (ck.hex(), nonce.hex(), pt.hex(), n44_encrypt(ck, nonce, pt)))
    key, iv = nrb(32), nrb(16)
    out.append("nip04enc %s %s %s %s" % (key.hex(), iv.hex(), pt.hex(), n04_encrypt(key, iv, pt)))
_ck, _n = nrb(32), nrb(32)
_good = n44_encrypt(_ck, _n, b"a tampered message")
_raw = bytearray(_b64.b64decode(_good))
for pos in (1, 40, len(_raw) - 1):                                   # the nonce, the ciphertext and the MAC changed by one bit: the MAC fails
    t = bytearray(_raw); t[pos] ^= 1
    out.append("nip44bad %s %s" % (_ck.hex(), _b64.b64encode(bytes(t)).decode()))
out.append("nip44bad %s %s" % (_ck.hex(), _good[:-4]))               # cut
out.append("nip44bad %s %s" % (_ck.hex(), "#" + _good))              # a version marker of a later format
_k4, _iv4 = nrb(32), nrb(16)
_g4 = n04_encrypt(_k4, _iv4, b"hello nip04")
out.append("nip04bad %s %s" % (_k4.hex(), _g4.split("?iv=")[0]))      # no iv
out.append("nip04bad %s %s" % (_k4.hex(), _g4.split("?iv=")[0] + "?iv=" + _b64.b64encode(bytes(8)).decode()))       # an iv of 8 bytes
out.append("nip04bad %s %s" % (_k4.hex(), _b64.b64encode(bytes(17)).decode() + "?iv=" + _g4.split("?iv=")[1]))       # not whole blocks
out.append("nip04bad %s %s" % (nrb(32).hex(), _g4))                                                                   # the wrong key: the padding is not right (almost always)


# ---------------- NIP-19 ----------------
_CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _b32poly(vals):
    chk = 1
    for v in vals:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3][i] if (top >> i) & 1 else 0
    return chk


def _bits(data, f, t, pad):
    acc, bits, o = 0, 0, []
    for d in data:
        acc = (acc << f) | d; bits += f
        while bits >= t:
            bits -= t; o.append((acc >> bits) & ((1 << t) - 1))
        acc &= (1 << bits) - 1
    if pad and bits: o.append((acc << (t - bits)) & ((1 << t) - 1))
    return o


def b32enc(hrp, raw):
    d5 = _bits(raw, 8, 5, True)
    pre = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    chk = _b32poly(pre + d5 + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CS[v] for v in d5) + "".join(_CS[(chk >> (5 * (5 - i))) & 31] for i in range(6))


def b32dec(s):
    """(hrp, bytes) or None"""
    if s != s.lower() and s != s.upper(): return None
    s = s.lower()
    sep = s.rfind("1")
    if sep < 1 or len(s) - sep < 7 or any(c not in _CS for c in s[sep + 1:]): return None
    hrp, d5 = s[:sep], [_CS.index(c) for c in s[sep + 1:]]
    if _b32poly([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + d5) != 1: return None
    d5 = d5[:-6]
    acc, bits, o = 0, 0, []
    for d in d5:
        acc = (acc << 5) | d; bits += 5
        if bits >= 8:
            bits -= 8; o.append((acc >> bits) & 255); acc &= (1 << bits) - 1
    if bits >= 5 or acc: return None
    return hrp, bytes(o)


N19 = {"npub": 1, "nsec": 2, "note": 3, "nprofile": 4, "nevent": 5, "naddr": 6, "nrelay": 7}


def n19_decode(s):
    """the fields of core/sign/nip19.c, or None"""
    r = b32dec(s) if 8 <= len(s) <= 400 else None
    if not r or r[0] not in N19: return None
    hrp, raw = r
    f = dict(type=N19[hrp], id=b"", author=b"", kind=None, relay="", d="", nrelays=0)
    if hrp in ("npub", "nsec", "note"):
        if len(raw) != 32: return None
        f["id"] = raw
        return f
    i, special = 0, False
    while i < len(raw):
        if i + 2 > len(raw): return None
        t, l = raw[i], raw[i + 1]; i += 2
        if i + l > len(raw): return None
        v = raw[i:i + l]
        if t == 0:
            if hrp == "naddr":
                if l >= 64: return None
                f["d"] = v.decode("latin-1")
            else:
                if l != 32: return None
                f["id"] = v
            special = True
        elif t == 1:
            if not f["relay"] and l < 96: f["relay"] = v.decode("latin-1")
            f["nrelays"] += 1
        elif t == 2:
            if l != 32: return None
            f["author"] = v
        elif t == 3:
            if l != 4: return None
            f["kind"] = int.from_bytes(v, "big")
        i += l
    return f if special else None


def tlv(*items): return b"".join(bytes([t, len(v)]) + v for t, v in items)


def npub_of(k): return b32enc("npub", k)


for hrp in ("npub", "nsec", "note", "npub", "note"):
    k = nrb(32)
    out.append("nip19enc %s %s %s" % (hrp, k.hex(), b32enc(hrp, k)))


def n19_line(s, f=None):
    f = f or n19_decode(s)
    assert f
    return "nip19dec %s %d %s %s %s %s %s %d" % (s, f["type"], hx(f["id"]), hx(f["author"]), "-" if f["kind"] is None else f["kind"], f["relay"] or "-", f["d"] or "-", f["nrelays"])


# the examples of the NIP-19 text
for s in ("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg", "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
          "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p"):
    out.append(n19_line(s))
    out.append(n19_line(s.upper()))
for i in range(4):
    pk, ev, au = nrb(32), nrb(32), nrb(32)
    rel = ["wss://relay%d.example.com" % j for j in range(i)]
    out.append(n19_line(b32enc("nprofile", tlv((0, pk), *[(1, r.encode()) for r in rel]))))
    out.append(n19_line(b32enc("nevent", tlv((0, ev), *[(1, r.encode()) for r in rel], *([(2, au)] if i % 2 else []), *([(3, (30023 + i).to_bytes(4, "big"))] if i > 1 else [])))))
    out.append(n19_line(b32enc("naddr", tlv((0, ("id-%d" % i).encode()), (2, au), (3, (30023).to_bytes(4, "big")), *[(1, r.encode()) for r in rel]))))
# not valid
_good19 = npub_of(nrb(32))
_bad = [_good19[:-1] + ("q" if _good19[-1] != "q" else "p"),                                            # the checksum
        _good19[:5] + _good19[5:].upper(),                                                              # mixed case
        b32enc("nxyz", nrb(32)),                                                                        # an unknown prefix
        b32enc("npub", nrb(31)), b32enc("note", nrb(33)),                                               # not 32 bytes
        b32enc("nprofile", tlv((1, b"wss://x.example"))),                                               # no key
        b32enc("nprofile", tlv((0, nrb(31)))),                                                          # a short key
        b32enc("nevent", tlv((0, nrb(32)))[:-3]),                                                       # a cut list
        b32enc("nevent", tlv((0, nrb(32)), (3, b"\x00\x01"))),                                          # a kind of 2 bytes
        "npub1", "", _good19.replace("1", "l", 1)]
for s in _bad:
    assert n19_decode(s) is None, s
    out.append("nip19bad %s" % (s or "-"))


# ---------------- events: encrypt, view, decrypt ----------------
def event_json(priv, created, kind, tags, content):
    pk = xonly(priv).hex()
    ser = json.dumps([0, pk, created, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = sha256(ser.encode("utf-8"))
    sig = schnorr_sign(priv, eid)
    return '{"id":"%s","pubkey":"%s","created_at":%d,"kind":%d,"tags":%s,"content":"%s","sig":"%s"}' % (
        eid.hex(), pk, created, kind, json.dumps(tags, separators=(",", ":"), ensure_ascii=False), json.dumps(content, ensure_ascii=False)[1:-1], sig.hex())


def reqj(d): return json.dumps(d, separators=(",", ":"), ensure_ascii=False)


def count_note(tags, created, content):
    c = json.dumps(content, ensure_ascii=False)[1:-1]
    return "%d tag%s, created_at %d, content %d bytes" % (len(tags), "" if len(tags) == 1 else "s", created, len(c.encode()))


ENC_TEXTS = ["hello bob", "line one\nline two", 'say "hi" and \\ back', "café über, 中文 and \U0001F600", "x", "a/b?iv=c"]


def sane(pt): return pt.decode("utf-8").translate({c: " " for c in range(32)})


def enc_case(i):
    a, b = nrb(32), nrb(32)
    pb = xonly(b)
    mode = 44 if i % 2 == 0 else 4
    created = 1700000000 + nrnd.randrange(10**7)
    text = ENC_TEXTS[i % len(ENC_TEXTS)]
    kind = 4 if mode == 4 else [4, 13, 1][i % 3]
    form = i % 4
    other = xonly(nrb(32)).hex()
    tags = {0: [["p", pb.hex()]], 1: [["p", other]], 2: [["t", "x"]], 3: []}[form]
    req = {"kind": kind, "created_at": created, "tags": tags, "content": text, "encrypt": "nip44" if mode == 44 else "nip04"}
    if form == 1: req["recipient"] = pb.hex()
    if form == 2: req["recipient"] = npub_of(pb)
    if form == 3: req["recipient"] = b32enc("nprofile", tlv((0, pb), (1, b"wss://r.example")))
    pt = text.encode("utf-8")
    key = n44_conv(a, pb) if mode == 44 else ecdh_x(a, pb)
    nonce = hmac256(key, created.to_bytes(8, "big") + pt)
    payload = n44_encrypt(key, nonce, pt) if mode == 44 else n04_encrypt(key, nonce[:16], pt)
    ev = event_json(a, created, kind, tags, payload)
    out.append("nostr %s %s %s" % (a.hex(), reqj(req).encode().hex(), ev.encode().hex()))
    notes = [count_note(tags, created, text), "Encrypted with NIP-%02d for %s" % (mode, npub_of(pb))]
    out.append("nostrview %s %s" % (reqj(req).encode().hex(), "|".join(tl(x) for x in [KINDS.get(kind, "Nostr event (kind %d)" % kind), json.dumps(text, ensure_ascii=False)[1:-1][:111]] + (notes + ["", "", ""])[:3])))
    # the recipient reads it: the event as it is, the sender is the other side
    evd = json.loads(ev)
    out.append("nostrdec %s %s %s" % (b.hex(), ev.encode().hex(), pt.hex()))
    # the sender reads her own message: "with" names the recipient (and "decrypt" the mode)
    evd2 = dict(evd, **{"with": npub_of(pb)})
    if i % 3 == 0: evd2["decrypt"] = "nip44" if mode == 44 else "nip04"
    out.append("nostrdec %s %s %s" % (a.hex(), reqj(evd2).encode().hex(), pt.hex()))
    dnotes = ["With: " + npub_of(xonly(a)), "Message: %d bytes" % len(pt), ""]
    out.append("nostrdecview %s %s %s" % (b.hex(), ev.encode().hex(), "|".join(tl(x) for x in ["Decrypted Nostr message (NIP-%02d)" % mode] + dnotes + [sane(pt)])))
    if i % 2 == 0:
        c = nrb(32)
        out.append("nostrdecfail %s %s" % (c.hex(), ev.encode().hex()))                          # the wrong key
        evd3 = dict(evd); del evd3["pubkey"]
        out.append("nostrdecfail %s %s" % (b.hex(), reqj(evd3).encode().hex()))                   # nobody named
        if mode == 44:
            t = bytearray(_b64.b64decode(payload)); t[40] ^= 4
            out.append("nostrdecfail %s %s" % (b.hex(), reqj(dict(evd, content=_b64.b64encode(bytes(t)).decode())).encode().hex()))     # a changed message


for i in range(12):
    enc_case(i)
# an encrypt request without a recipient, with a bad one, and a mode that does not exist
_a = nrb(32)
for extra in ({"tags": [["t", "x"]]}, {"tags": [], "recipient": "npub1abc"}, {"tags": [["p", "zz" * 32]]}, {"tags": [["p", xonly(nrb(32)).hex()]], "encrypt": "nip17"}):
    d = {"kind": 4, "created_at": 1700000000, "tags": [], "content": "hi", "encrypt": "nip44"}
    d.update(extra)
    out.append("nostrfail %s %s" % (_a.hex(), reqj(d).encode().hex()))

# long messages: the whole text on pages of its own, up to the limit of 4096 bytes, and past it
_a, _b = nrb(32), nrb(32)
for n_pt, mode in ((639, 44), (639, 4), (4096, 44), (4096, 4), (2049, 44), (1, 44)):
    _long = ("word%03d " * 700) % tuple(range(700))
    _long = (_long * 2)[:n_pt]
    _pt = _long.encode()
    created = 1700000001
    tags = [["p", xonly(_b).hex()]]
    req = {"kind": 4, "created_at": created, "tags": tags, "content": _long, "encrypt": "nip44" if mode == 44 else "nip04"}
    key = n44_conv(_a, xonly(_b)) if mode == 44 else ecdh_x(_a, xonly(_b))
    nonce = hmac256(key, created.to_bytes(8, "big") + _pt)
    payload = n44_encrypt(key, nonce, _pt) if mode == 44 else n04_encrypt(key, nonce[:16], _pt)
    _ev = event_json(_a, created, 4, tags, payload)
    out.append("nostr %s %s %s" % (_a.hex(), reqj(req).encode().hex(), _ev.encode().hex()))
    notes = [count_note(tags, created, _long), "Encrypted with NIP-%02d for %s" % (mode, npub_of(xonly(_b)))] + (["Long text: read every page before you sign"] if n_pt > 111 else [])
    out.append("nostrtext %s %s %s" % (reqj(req).encode().hex(), "|".join(tl(x) for x in (notes + ["", "", ""])[:3]), tl(_long) if n_pt > 111 else "-"))
    out.append("nostrdec %s %s %s" % (_b.hex(), _ev.encode().hex(), _pt.hex()))
    out.append("nostrdecview %s %s %s" % (_b.hex(), _ev.encode().hex(), "|".join(tl(x) for x in ["Decrypted Nostr message (NIP-%02d)" % mode, "With: " + npub_of(xonly(_a)), "Message: %d bytes" % n_pt, "", _long])))
# one byte more than the limit: neither encrypted nor decrypted
_pt = (("word%03d " * 700) % tuple(range(700)) * 2)[:4097].encode()
_req = {"kind": 4, "created_at": 1700000001, "tags": [["p", xonly(_b).hex()]], "content": _pt.decode(), "encrypt": "nip44"}
out.append("nostrfail %s %s" % (_a.hex(), reqj(_req).encode().hex()))
_ck = n44_conv(_a, xonly(_b))
_ev = event_json(_a, 1700000001, 4, [["p", xonly(_b).hex()]], n44_encrypt(_ck, nrb(32), _pt))
out.append("nostrdecfail %s %s" % (_b.hex(), _ev.encode().hex()))

# a long note (not encrypted): all of it on pages of its own
for i, n_pt in enumerate((112, 400, 4000)):
    created = 1700000002 + i
    text = (("lorem %03d ipsum " * 300) % tuple(range(300)))[:n_pt]
    req = {"kind": 1, "created_at": created, "tags": [], "content": text}
    notes = [count_note([], created, text), "Long text: read every page before you sign"]
    out.append("nostrtext %s %s %s" % (reqj(req).encode().hex(), "|".join(tl(x) for x in (notes + ["", "", ""])[:3]), tl(text)))

# the NIP-19 notes of an unencrypted event: the first "p" and "e" tags as npub / note1..., and the "nostr:" references of the content
for i in range(6):
    a = nrb(32)
    pk, ek = nrb(32), nrb(32)
    created = 1700000000 + nrnd.randrange(10**7)
    kind = [1, 7, 4, 6, 1, 1][i]
    tags = ([["p", pk.hex(), "wss://r.example"]] if i % 2 == 0 else []) + ([["e", ek.hex()]] if i % 3 != 2 else [])
    ref_ok = npub_of(nrb(32))
    ref_bad = ref_ok[:-1] + ("q" if ref_ok[-1] != "q" else "p")
    content = ["hi nostr:%s and nostr:%s." % (ref_ok, ref_bad), "+", "nostr:%s" % ref_ok, "see nostr: now", "nostr:%s nostr:%s nostr:%s" % (ref_ok, ref_bad, ref_bad), "no refs here"][i]
    req = {"kind": kind, "created_at": created, "tags": tags, "content": content}
    notes = [count_note(tags, created, content)]
    if kind == 4: notes.append("The content is encrypted: only the metadata can be checked")
    ptag = next((t for t in tags if t[0] == "p"), None)
    etag = next((t for t in tags if t[0] == "e"), None)
    if ptag: notes.append("To: " + npub_of(bytes.fromhex(ptag[1])))
    if etag: notes.append("Event: " + b32enc("note", bytes.fromhex(etag[1])))
    import re as _re
    toks = _re.findall(r"nostr:([0-9A-Za-z]+)", content)
    if toks: notes.append("%d nostr: references, %d not valid" % (len(toks), sum(1 for t in toks if n19_decode(t) is None)))
    if len(notes) <= 3:
        out.append("nostrview %s %s" % (reqj(req).encode().hex(), "|".join(tl(x) for x in [KINDS.get(kind, "Nostr event (kind %d)" % kind), json.dumps(content, ensure_ascii=False)[1:-1][:111]] + (notes + ["", "", ""])[:3])))
