#!/usr/bin/env python3
"""Generate known-answer vectors from independent reference implementations.

Output: tests/vectors.txt, one vector per line: <kind> <hex args...>
Deterministic (fixed seed) so the file can be regenerated and diffed.
Requires: pycryptodome (keccak), coincurve (secp256k1), pynacl (ed25519), base58.
"""
import hashlib, hmac, os, random, sys, zlib
from Crypto.Hash import keccak
import base58

rnd = random.Random(0x5058582D)          # "PSX-"
out = []

def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))
def h(b): return b.hex() if b else "-"
def emit(kind, *args): out.append(kind + " " + " ".join(h(a) if isinstance(a, bytes) else str(a) for a in args))

LENS = [0, 1, 3, 31, 32, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 135, 136, 137, 200, 271, 272, 300, 1000]

# --- hashes --------------------------------------------------------------
for n in LENS:
    m = rb(n)
    emit("sha256", m, hashlib.sha256(m).digest())
    emit("sha512", m, hashlib.sha512(m).digest())
    emit("keccak256", m, keccak.new(digest_bits=256, data=m).digest())
    emit("ripemd160", m, hashlib.new("ripemd160", m).digest())
    emit("hash160", m, hashlib.new("ripemd160", hashlib.sha256(m).digest()).digest())
    emit("crc32", m, zlib.crc32(m).to_bytes(4, "big"))
for kl in [0, 1, 32, 64, 65, 128, 129, 200]:
    for ml in [0, 5, 64, 129]:
        k, m = rb(kl), rb(ml)
        emit("hmac256", k, m, hmac.new(k, m, hashlib.sha256).digest())
        emit("hmac512", k, m, hmac.new(k, m, hashlib.sha512).digest())
for pl, sl, it, ol in [(0, 0, 1, 64), (5, 8, 1, 64), (8, 8, 2, 64), (20, 13, 100, 64), (130, 40, 7, 100), (11, 16, 2048, 64)]:
    pw, salt = rb(pl), rb(sl)
    emit("pbkdf2_512", pw, salt, it, hashlib.pbkdf2_hmac("sha512", pw, salt, it, ol))

# --- encodings -----------------------------------------------------------
for n in [0, 1, 2, 20, 21, 25, 32, 33, 37, 60]:
    d = rb(n)
    emit("base58", d, base58.b58encode(d).decode())
for n in [1, 21, 25, 33]:
    d = rb(n)
    emit("base58check", d, base58.b58encode_check(d).decode())
emit("base58", bytes(3) + rb(5), base58.b58encode(bytes(3) + rb(5)).decode())  # leading zeros (re-rolled data is fine: output recomputed below)
out.pop()
z = bytes(3) + rb(5); emit("base58", z, base58.b58encode(z).decode())

# Monero base58 reference (spec: 8 byte blocks -> 11 chars, tail table)
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SZ = [0, 2, 3, 5, 6, 7, 9, 10, 11]
def xmr58(d):
    s = ""
    for i in range(0, len(d), 8):
        b = d[i:i+8]; v = int.from_bytes(b, "big"); c = ""
        for _ in range(SZ[len(b)]): c = A[v % 58] + c; v //= 58
        s += c
    return s
for n in [1, 7, 8, 9, 16, 69, 71]:
    d = rb(n); emit("base58xmr", d, xmr58(d))

# bech32 / segwit reference (BIP173/350)
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(vals):
    G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; c = 1
    for v in vals:
        b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1: c ^= G[i]
    return c
def bech(hrp, d5, m):
    exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    p = polymod(exp + d5 + [0]*6) ^ (0x2bc830a3 if m else 1)
    return hrp + "1" + "".join(CH[x] for x in d5 + [(p >> 5*(5-i)) & 31 for i in range(6)])
def conv(data, f, t, pad=True):
    acc = bits = 0; r = []; mx = (1 << t) - 1
    for v in data:
        acc = (acc << f) | v; bits += f
        while bits >= t: bits -= t; r.append((acc >> bits) & mx)
    if pad and bits: r.append((acc << (t - bits)) & mx)
    return r
for hrp, ver, n in [("bc", 0, 20), ("bc", 0, 32), ("tb", 0, 20), ("bc", 1, 32), ("bc", 16, 40), ("bc", 2, 2)]:
    prog = rb(n)
    emit("segwit", hrp, ver, prog, bech(hrp, [ver] + conv(prog, 8, 5), ver != 0))
for n in [32]:
    d = rb(n); emit("bech32", "npub", d, bech("npub", conv(d, 8, 5), False))
emit("segwit", "bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

# --- secp256k1 (coincurve / libsecp256k1) --------------------------------
import coincurve
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def be(v): return v.to_bytes(32, "big")
keys = [1, 2, 3, 7, 0xFFFF, 2**128, 2**255, N - 1, N - 2, N // 2] + [rnd.randrange(1, N) for _ in range(14)]
for k in keys:
    pk = coincurve.PublicKey.from_secret(be(k))
    emit("secp_pub", be(k), pk.format(compressed=True), pk.format(compressed=False))
for k, t in [(1, 1), (N - 1, 1), (N - 1, 2), (5, N - 5), (5, N - 6), (N - 2, N - 1)] + [(rnd.randrange(1, N), rnd.randrange(0, N)) for _ in range(12)]:
    try: r = coincurve.PrivateKey(be(k)).add(be(t)).secret
    except Exception: r = None
    emit("secp_tweak", be(k), be(t), r if r else "-")

# --- ed25519 / Monero (PyNaCl / libsodium + big-int reference) ----------
import nacl.bindings as nb, nacl.signing
L = 2**252 + 27742317777372353535851937790883648493
def le(v, n=32): return v.to_bytes(n, "little")
def toint(b): return int.from_bytes(b, "little")
for _ in range(10):
    seed = rb(32)
    emit("ed_pub", seed, bytes(nacl.signing.SigningKey(seed).verify_key))
emit("ed_pub", bytes(32), bytes(nacl.signing.SigningKey(bytes(32)).verify_key))
sc = [1, 2, 8, L - 1, L - 2, 2**200, 2**252] + [rnd.randrange(1, L) for _ in range(12)]
for v in sc:
    emit("ed_base", le(v), nb.crypto_scalarmult_ed25519_base_noclamp(le(v)))
for _ in range(12):
    x = rb(64); emit("ed_reduce64", x, le(toint(x) % L))
for x in [bytes(32), bytes([255]) * 32, le(L), le(L - 1), le(L + 1), rb(32), rb(32)]:
    emit("ed_reduce32", x, le(toint(x) % L))
for _ in range(10):
    a, b = rnd.randrange(L), rnd.randrange(L)
    emit("ed_scadd", le(a), le(b), le((a + b) % L))
    emit("ed_scmul", le(a), le(b), le((a * b) % L))
emit("ed_scadd", le(L - 1), le(L - 1), le((2 * L - 2) % L))
emit("ed_scmul", le(L - 1), le(L - 1), le(((L - 1) ** 2) % L))
for _ in range(6):
    seed = rb(32)
    sp = le(toint(seed) % L)
    vp = le(toint(keccak.new(digest_bits=256, data=sp).digest()) % L)
    PS, PV = nb.crypto_scalarmult_ed25519_base_noclamp(sp), nb.crypto_scalarmult_ed25519_base_noclamp(vp)
    raw = bytes([0x12]) + PS + PV
    raw += keccak.new(digest_bits=256, data=raw).digest()[:4]
    emit("xmr_keys", seed, sp, vp, PS, PV, xmr58(raw))

# Monero legacy subaddresses (wallet2: m = Hs("SubAddr\0" || a || major || minor), D = B + mG, C = aD)
for _ in range(4):
    seed = rb(32)
    sp = le(toint(seed) % L)
    vp = le(toint(keccak.new(digest_bits=256, data=sp).digest()) % L)
    PS = nb.crypto_scalarmult_ed25519_base_noclamp(sp)
    for mj, mn in [(0, 1), (0, 2), (1, 0), (0, 10), (3, 77)]:
        m = le(toint(keccak.new(digest_bits=256, data=b"SubAddr\0" + vp + mj.to_bytes(4, "little") + mn.to_bytes(4, "little")).digest()) % L)
        Dp = nb.crypto_core_ed25519_add(PS, nb.crypto_scalarmult_ed25519_base_noclamp(m))
        Cp = nb.crypto_scalarmult_ed25519_noclamp(vp, Dp)
        raw = bytes([0x2a]) + Dp + Cp
        raw += keccak.new(digest_bits=256, data=raw).digest()[:4]
        emit("xmr_sub", vp, PS, "%d" % mj, "%d" % mn, xmr58(raw))

# --- BIP32 + coin addresses (own big-int/coincurve reference) -------------
def i32(n): return n.to_bytes(4, "big")
def b32_master(seed):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); return int.from_bytes(i[:32], "big"), i[32:]
def pub33(k): return coincurve.PublicKey.from_secret(be(k)).format(compressed=True)
def h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
def b32_child(k, c, idx):
    data = (bytes([0]) + be(k) if idx >= 0x80000000 else pub33(k)) + i32(idx)
    i = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(i[:32], "big") + k) % N, i[32:]
def parse_path(p):
    r = []
    for part in p.split("/")[1:]:
        h = part.endswith("'") or part.endswith("h")
        r.append(int(part.rstrip("'h")) | (0x80000000 if h else 0))
    return r
def ser(ver, depth, fp, idx, c, keydata): return base58.b58encode_check(i32(ver) + bytes([depth]) + fp + i32(idx) + c + keydata).decode()
def b32_vector(seed, path):
    k, c = b32_master(seed); fp = bytes(4); idx = 0; depth = 0
    for ix in parse_path(path):
        fp = h160(pub33(k))[:4]; k, c = b32_child(k, c, ix); idx = ix; depth += 1
    return ser(0x0488ADE4, depth, fp, idx, c, bytes([0]) + be(k)), ser(0x0488B21E, depth, fp, idx, c, pub33(k))
# anchor the reference on the published BIP32 test vector 1
_x = b32_vector(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), "m")
assert _x[1] == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", _x
_x = b32_vector(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), "m/0'/1/2'/2/1000000000")
assert _x[1] == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", _x
paths = ["m", "m/0", "m/0'", "m/0'/1", "m/44'/0'/0'/0/0", "m/44'/60'/0'/0/0", "m/84'/0'/0'/0/7", "m/44'/3'/0'/0/0", "m/1'/2'/3'/4/5/6"]
for sd in [bytes.fromhex("000102030405060708090a0b0c0d0e0f"), rb(16), rb(32), rb(64)]:
    for pth in paths:
        xprv, xpub = b32_vector(sd, pth); emit("bip32", sd, pth, xprv, xpub)

def wif(v, k): return base58.b58encode_check(bytes([v]) + be(k) + bytes([1])).decode()
def p2pkh(v, k): return base58.b58encode_check(bytes([v]) + h160(pub33(k))).decode()
def eth(k):
    pub = coincurve.PublicKey.from_secret(be(k)).format(compressed=False)[1:]
    a = keccak.new(digest_bits=256, data=pub).digest()[12:].hex()
    hh = keccak.new(digest_bits=256, data=a.encode()).hexdigest()
    return "0x" + "".join(c.upper() if c.isalpha() and int(hh[i], 16) >= 8 else c for i, c in enumerate(a))
for k in [1, 2, N - 1] + [rnd.randrange(1, N) for _ in range(10)]:
    pk = pub33(k)
    emit("addr", be(k), p2pkh(0x00, k), p2pkh(0x1e, k), wif(0x80, k), wif(0x9e, k),
         bech("bc", [0] + conv(h160(pk), 8, 5), False), eth(k), bech("npub", conv(pk[1:], 8, 5), False), bech("nsec", conv(be(k), 8, 5), False))

# --- BIP39 (reference from the packed-in-tree wordlist + published Trezor vectors) ---
WL = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist_dl", "english.txt")).read().split()
def e2m(ent):
    bits = bin(int.from_bytes(ent, "big"))[2:].zfill(len(ent) * 8) + bin(hashlib.sha256(ent).digest()[0])[2:].zfill(8)[:len(ent) * 8 // 32]
    return " ".join(WL[int(bits[i:i+11], 2)] for i in range(0, len(bits), 11))
def m2seed(m, pw): return hashlib.pbkdf2_hmac("sha512", m.encode(), ("mnemonic" + pw).encode(), 2048, 64)
_m = e2m(bytes(16))
assert _m == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
assert m2seed(_m, "TREZOR").hex().startswith("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
assert e2m(bytes([0x7f]) * 16) == "legal winner thank year wave sausage worth useful legal winner thank yellow"
def pw_hex(pw): return pw.encode() if pw else b""
cases = [bytes(16), bytes([255]) * 16, bytes([0x7f]) * 16, bytes(32), bytes([255]) * 32] + [rb(n) for n in (16, 20, 24, 28, 32) for _ in range(3)]
for ent in cases:
    m = e2m(ent)
    for pw in ["", "TREZOR", "p@ss w0rd!"] if len(ent) in (16, 32) and ent in cases[:5] else [rnd.choice(["", "TREZOR", "x"])]:
        emit("bip39", ent, m.replace(" ", "_"), pw_hex(pw), m2seed(m, pw))
# invalid mnemonics must be rejected
good = e2m(rb(16)).split()
bad = [good[:-1] + [WL[(WL.index(good[-1]) + 1) % 2048]], good[:11], good + ["abandon"], good[:5] + ["notaword"] + good[6:],
       [w[:4] for w in good], good[:-1] + [WL[(WL.index(good[-1]) + 2) % 2048]]]
def m_valid(ws):
    if len(ws) not in (12, 15, 18, 21, 24) or any(w not in WL for w in ws): return False
    bits = "".join(bin(WL.index(w))[2:].zfill(11) for w in ws); n = len(bits) * 32 // 33
    ent = int(bits[:n], 2).to_bytes(n // 8, "big")
    return bits[n:] == bin(hashlib.sha256(ent).digest()[0])[2:].zfill(8)[:len(bits) - n]
assert m_valid(good) and not any(m_valid(b) for b in bad)
for b in bad: emit("bip39_bad", "_".join(b))

# --- entropy pool (manual sources; timing sources are covered by unit tests) ---
import math
L2 = [0, 0] + [math.floor(math.log2(n) * 256) for n in range(2, 17)]
assert L2[2:] == [256, 405, 512, 594, 661, 718, 768, 811, 850, 885, 917, 947, 974, 1000, 1024], L2
def pool_ref(events):
    h = hashlib.sha256(b"psx-entropy-pool-v1"); credit = 0
    for nsym, sym in events:
        h.update(bytes([1, nsym]) + sym.to_bytes(4, "little")); credit += L2[nsym]
    bits = credit >> 8
    if bits < 256: return bits, None
    x = hashlib.sha256(b"psx-entropy-extract-v1" + h.digest() + bits.to_bytes(4, "big")).digest()
    return bits, x
def ev_str(events):
    return ",".join(("d%d" % (s + 1) if n == 6 else "c%d" % s if n == 2 else "s%d_%d" % (n, s)) for n, s in events)
def rand_events(kind, count):
    if kind == "dice": return [(6, rnd.randrange(6)) for _ in range(count)]
    if kind == "coin": return [(2, rnd.randrange(2)) for _ in range(count)]
    return [(n := rnd.choice([2, 3, 4, 6, 8, 16]), rnd.randrange(n)) for _ in range(count)]
for kind, count in [("dice", 99), ("dice", 100), ("dice", 120), ("coin", 255), ("coin", 256), ("mix", 80), ("mix", 140), ("mix", 160), ("dice", 3)]:
    ev = rand_events(kind, count); bits, x = pool_ref(ev)
    emit("entropy", ev_str(ev), bits, x if x else "-")

# --- wallet: first addresses of the standard accounts from a BIP39 seed ---
def leaf_key(seed, purpose, coin):
    k, c = b32_master(seed)
    for ix in [purpose | 0x80000000, coin | 0x80000000, 0x80000000, 0, 0]: k, c = b32_child(k, c, ix)
    return k
def wallet_ref(seed):
    k44, k84 = leaf_key(seed, 44, 0), leaf_key(seed, 84, 0)
    return (p2pkh(0x00, k44), bech("bc", [0] + conv(h160(pub33(k84)), 8, 5), False), eth(leaf_key(seed, 44, 60)),
            p2pkh(0x1e, leaf_key(seed, 44, 3)), bech("npub", conv(pub33(leaf_key(seed, 44, 1237))[1:], 8, 5), False))
_abandon = m2seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "")
_w = wallet_ref(_abandon)
# published values for this mnemonic (BIP44 / BIP84 test data)
assert _w[0] == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", _w[0]
assert _w[1] == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", _w[1]
assert _w[2] == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", _w[2]
emit("wallet", _abandon, *_w)
for _ in range(3):
    sd = rb(64); emit("wallet", sd, *wallet_ref(sd))

# --- Monero 25 word seed (reference from the downloaded wordlist, algorithm of monero electrum-words.cpp) ---
import re as _re
_src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist_dl_xmr", "english.h"), encoding="utf-8").read()
_b = _src[_src.index("words[NWORDS]"):]; _b = _b[_b.index("{"):_b.index("};")]
XW = _re.findall(r'"([a-z]+)"', _b); NX = len(XW); assert NX == 1626
def xmr_seed(key):
    ws = []
    for i in range(8):
        val = int.from_bytes(key[4*i:4*i+4], "little")
        w1 = val % NX; w2 = (val // NX + w1) % NX; w3 = ((val // NX) // NX + w2) % NX
        ws += [w1, w2, w3]
    crc = zlib.crc32("".join(XW[w][:3] for w in ws).encode()) % 24
    return [XW[w] for w in ws] + [XW[ws[crc]]]
for key in [bytes(32), bytes([255]) * 32, bytes(range(32))] + [rb(32) for _ in range(12)]:
    emit("xmr_seed", key, "_".join(xmr_seed(key)))
# prefix-only input must decode to the same key
for _ in range(3):
    key = rb(32); emit("xmr_seed_prefix", key, "_".join(w[:3] for w in xmr_seed(key)))
# invalid: wrong checksum word, wrong length, unknown word, a changed middle word
_g = xmr_seed(rb(32))
_bad = [_g[:24] + [XW[(XW.index(_g[24]) + 1) % NX]], _g[:24], _g + [_g[0]], _g[:5] + ["zzzzz"] + _g[6:], _g[:10] + [XW[(XW.index(_g[10]) + 1) % NX]] + _g[11:]]
for b in _bad:
    ok = len(b) == 25 and all(w in XW for w in b) and b[24] == b[zlib.crc32("".join(w[:3] for w in b[:24]).encode()) % 24]
    assert not ok, b
    emit("xmr_seed_bad", "_".join(b))

# --- LZ4 block format (own compressor in tools/lz4.py; the C decoders must read exactly what it writes) ---
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lz4 as _lz4
def lz4_samples():
    yield b""
    yield b"a"
    yield bytes(11)
    yield bytes(13)
    yield b"abc" * 40
    yield bytes(1000)                                   # long run: match length extension bytes, offset 1 overlap
    yield bytes(range(256)) * 3
    yield rb(300)                                       # incompressible: literal length extension
    yield (b"hello wallet " * 30) + rb(40) + (b"hello wallet " * 30)
    yield bytes([i % 7 for i in range(900)])
    yield (rb(16) * 20) + rb(5) + (rb(16) * 20)
    for _ in range(4):
        w = [rb(rnd.randrange(3, 9)) for _ in range(12)]
        yield b"".join(rnd.choice(w) for _ in range(rnd.randrange(50, 150)))
for _d in lz4_samples():
    _c = _lz4.compress(_d); assert _lz4.decompress(_c) == _d
    emit("lz4", _d, _c)
    if len(_d) > 40:                                    # in-place variant with the minimal margin
        emit("lz4ip", _d, _c, _lz4.inplace_margin(_c, len(_d)))
# malformed streams must be rejected by the checked decoder
for _b in [bytes.fromhex(h) for h in ("10", "406162", "f0", "11610000", "11610500", "000000", "")]:
    emit("lz4bad", _b)

# --- AES, HKDF, blob (core/aes.c, core/blob.c) ---
from Crypto.Cipher import AES as _AES
from Crypto.Protocol.KDF import HKDF as _HKDF
from Crypto.Hash import SHA256 as _SHA256
for kl in (16, 24, 32):
    for _ in range(3):
        k, m = rb(kl), rb(16)
        emit("aes_ecb", k, m, _AES.new(k, _AES.MODE_ECB).encrypt(m))
for kl in (16, 32):
    for n in (16, 32, 48, 160):
        k, iv, m = rb(kl), rb(16), rb(n)
        emit("aes_cbc", k, iv, m, _AES.new(k, _AES.MODE_CBC, iv=iv).encrypt(m))
for kl in (16, 32):
    for al in (0, 5, 16, 20, 33):
        for pl in (0, 1, 15, 16, 17, 64, 100):
            k, nc, a, m = rb(kl), rb(12), rb(al), rb(pl)
            g = _AES.new(k, _AES.MODE_GCM, nonce=nc); g.update(a); ct, tag = g.encrypt_and_digest(m)
            emit("aes_gcm", k, nc, a, m, ct, tag)
for sl, il, nl, ol in [(0, 22, 0, 42), (13, 22, 5, 32), (32, 64, 11, 64), (16, 96, 11, 32), (5, 1, 0, 100)]:
    sa, ik, inf = rb(sl), rb(il), rb(nl)
    emit("hkdf", sa, ik, inf, ol, _HKDF(ik, ol, sa if sa else None, _SHA256, 1, inf))
def blob_ref(pw, extra, it, rn, m):
    salt, nonce = rn[:16], rn[16:]
    kd = hashlib.pbkdf2_hmac("sha512", pw, salt, it, 64)
    key = _HKDF(extra + kd, 32, salt, _SHA256, 1, b"psx-blob-v1")
    hdr = b"PSXT" + bytes([1, 1, 1 if extra else 0, 0]) + it.to_bytes(4, "big") + rn + len(m).to_bytes(2, "big")
    g = _AES.new(key, _AES.MODE_GCM, nonce=nonce); g.update(hdr); ct, tag = g.encrypt_and_digest(m)
    return hdr + ct + tag
for pl, ex, it, ml in [(0, 0, 1, 0), (6, 0, 3, 1), (20, 0, 50, 48), (11, 32, 7, 33), (30, 32, 2, 96), (4, 0, 1, 100)]:
    pw, extra, rn, m = rb(pl), rb(ex), rb(28), rb(ml)
    emit("blob", pw, extra, it, rn, m, blob_ref(pw, extra, it, rn, m))

import base64 as _b64
for n in (0, 1, 2, 3, 4, 5, 47, 48, 106, 200):
    d = rb(n)
    emit("b64", d, _b64.b64encode(d).decode() or "-")
with open(os.path.join(os.path.dirname(__file__), "..", "tests", "vectors.txt"), "w") as f:
    f.write("\n".join(out) + "\n")
print(len(out), "vectors")
