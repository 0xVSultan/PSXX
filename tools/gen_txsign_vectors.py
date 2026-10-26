#!/usr/bin/env python3
"""Known-answer vectors for the transaction signers of core/sign (EVM, Tron, XRP, Cosmos, Nostr, ...).

References: python-ecdsa (deterministic ECDSA, every signature is verified here), bip_utils (Keccak-256, addresses), and the
serialisation formats written out below (RLP, protobuf, the XRP binary codec, NIP-01) from their specifications. The lines:
    evmtx    <priv> <unsigned tx> <signed tx> <sig65>
    evmview  <unsigned tx> <title>|<to>|<amount>|<fee>|<total>|<warn>|<note1>|<note2>|<note3>      ("~" for spaces, "-" empty)
    btcmsg   <chain id> <priv> <message hex|-> <sig65> <address> <view fields>      (sign message of the Bitcoin family, tools/txsign_btcmsg.py)
    kassh    <request> <input index> <signature hash>    (Kaspa: the request format of core/sign/kaspa.h; the first line is the official vector of rusty-kaspa)
    kas      <request> <keys c:i:priv,..|-> <KSIG|-> <view fields> <output>..       (tools/txsign_kaspa.py)
    evmauths <unsigned type 4 tx> <to>|<amount> ...      (the listed authorizations, from the second output on)
    evmauth  <priv> <rlp([chain_id, address, nonce])> <sig65 with y_parity> <to>|<amount>
    evmmsg   <priv> <message hex | -> <sig65>
    evmtyped <priv> <domain> <struct hash> <sig65>
Run with  python -I tools/gen_txsign_vectors.py   ->  tests/txsign_vectors.txt
"""
import hashlib, os, random, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import Kekkak256
from ecdsa import SigningKey, SECP256k1, util

N = SECP256k1.order
G = SECP256k1.generator
rnd = random.Random(0x7478534E)
out = []


def rb(n): return bytes(rnd.getrandbits(8) for _ in range(n))
def sha256(b): return hashlib.sha256(b).digest()
def keccak(b): return Kekkak256.QuickDigest(b)
def hx(b): return b.hex() if len(b) else "-"
def tl(s): return (s.replace(" ", "~") or "-")


def sign_rec(priv, digest):
    """deterministic ECDSA (RFC 6979 / SHA-256), low S; returns r, s, recovery id; verified against the key"""
    sk = SigningKey.from_string(priv, curve=SECP256k1, hashfunc=hashlib.sha256)
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=util.sigencode_string)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if s > N // 2:
        s = N - s
    pub = G * int.from_bytes(priv, "big")
    assert sk.get_verifying_key().verify_digest(r.to_bytes(32, "big") + s.to_bytes(32, "big"), digest, sigdecode=util.sigdecode_string)
    z = int.from_bytes(digest, "big")
    P = SECP256k1.curve.p()
    for rec in range(2):
        y = pow((pow(r, 3, P) + 7) % P, (P + 1) // 4, P)
        if (y & 1) != rec:
            y = P - y
        from ecdsa.ellipticcurve import Point
        R = Point(SECP256k1.curve, r, y)
        if (R * s + G * ((-z) % N)) * pow(r, -1, N) == pub:
            return r, s, rec
    raise SystemExit("no recovery id")


def fmt(v, dec, sym):
    s = str(v).rjust(dec + 1, "0")
    ip, fp = s[:len(s) - dec], s[len(s) - dec:].rstrip("0")
    return ip + ("." + fp if fp else "") + (" " + sym if sym else "")


# ================= EVM =================
def i2b(n): return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_hdr(n, base):
    if n < 56: return bytes([base + n])
    l = i2b(n)
    return bytes([base + 55 + len(l)]) + l


def rlp(x):
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80: return x
        return rlp_hdr(len(x), 0x80) + x
    if isinstance(x, int): return rlp(i2b(x))
    b = b"".join(rlp(i) for i in x)
    return rlp_hdr(len(b), 0xc0) + b


def eip55(a):
    h = a.hex()
    k = keccak(h.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(k[i], 16) >= 8 else c for i, c in enumerate(h))


CHN = {1: ("Ethereum", "ETH"), 10: ("Optimism", "ETH"), 56: ("BNB Chain", "BNB"), 61: ("Ethereum Classic", "ETC"), 137: ("Polygon", "POL"),
       8453: ("Base", "ETH"), 42161: ("Arbitrum One", "ETH"), 43114: ("Avalanche C", "AVAX"), 11155111: ("Sepolia", "ETH")}


def evm_case(priv, kind, chain, nonce, price, gas, to, value, data, prio=None, access=None, view=True, auths=None):
    """kind: legacy155 legacy0 t1 t2 t4 (EIP-7702: auths is the list of signed authorization tuples)"""
    access = access if access is not None else []
    if kind == "legacy155":
        unsigned = rlp([nonce, price, gas, to, value, data, chain, 0, 0])
        h = keccak(unsigned)
        r, s, rec = sign_rec(priv, h)
        signed = rlp([nonce, price, gas, to, value, data, chain * 2 + 35 + rec, r, s])
    elif kind == "legacy0":
        unsigned = rlp([nonce, price, gas, to, value, data])
        h = keccak(unsigned)
        r, s, rec = sign_rec(priv, h)
        signed = rlp([nonce, price, gas, to, value, data, 27 + rec, r, s])
    elif kind == "t1":
        body = [chain, nonce, price, gas, to, value, data, access]
        unsigned = b"\x01" + rlp(body)
        h = keccak(unsigned)
        r, s, rec = sign_rec(priv, h)
        signed = b"\x01" + rlp(body + [rec, r, s])
    elif kind == "t4":
        body = [chain, nonce, prio, price, gas, to, value, data, access, auths]
        unsigned = b"\x04" + rlp(body)
        h = keccak(unsigned)
        r, s, rec = sign_rec(priv, h)
        signed = b"\x04" + rlp(body + [rec, r, s])
    else:
        body = [chain, nonce, prio, price, gas, to, value, data, access]
        unsigned = b"\x02" + rlp(body)
        h = keccak(unsigned)
        r, s, rec = sign_rec(priv, h)
        signed = b"\x02" + rlp(body + [rec, r, s])
    sig65 = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([rec])
    out.append("evmtx %s %s %s %s" % (priv.hex(), unsigned.hex(), signed.hex(), sig65.hex()))
    if not view:
        return
    has_chain = kind != "legacy0"
    name, sym = CHN.get(chain, ("Chain %d" % chain, "native")) if has_chain else ("EVM", "native")
    title = "%s transaction" % name + (" (EIP-7702)" if kind == "t4" else "")
    notes = []
    warn = 512 if kind == "t4" else 0
    if to == b"":
        toaddr = "Contract creation"; warn |= 32
    else:
        toaddr = eip55(to)
    amount = fmt(value, 18, sym)
    total = amount
    if data:
        warn |= 32
        sel = int.from_bytes(data[:4], "big") if len(data) >= 4 else 0
        kd = None
        if sel == 0xa9059cbb and len(data) == 68: kd = 0
        elif sel == 0x095ea7b3 and len(data) == 68: kd = 1
        elif sel == 0x23b872dd and len(data) == 100: kd = 2
        if kd is not None:
            d = data[4:]
            who = d[32:64] if kd == 2 else d[0:32]
            amt = int.from_bytes(d[64:96] if kd == 2 else d[32:64], "big")
            toaddr = ("spender " if kd == 1 else "to ") + eip55(who[12:])
            amount = "UNLIMITED token units" if amt == 2**256 - 1 else "%d token units" % amt
            notes.append("%s, token contract %s" % (["ERC-20 transfer", "ERC-20 approve", "ERC-20 transferFrom"][kd], eip55(to)))
            if kd == 2:
                notes.append("from " + eip55(d[12:32]))
            total = ""
        else:
            notes.append("Contract call %08x, %d bytes of data" % (sel, len(data)))
    notes.append("Nonce %d, gas limit %d%s" % (nonce, gas, ", fee = max fee" if kind in ("t2", "t4") else ""))
    notes.append(("Chain id %d" % chain) if has_chain else "No chain id: the signature works on every EVM chain")
    notes = (notes + ["", "", ""])[:3] if len(notes) < 3 else notes[:3]
    fee = fmt(price * gas, 18, sym)
    out.append("evmview %s %s" % (unsigned.hex(), "|".join(tl(x) for x in [title, toaddr, amount, fee, total, str(warn)] + notes)))


# the EIP-155 example
k = bytes.fromhex("46" * 32)
evm_case(k, "legacy155", 1, 9, 20 * 10**9, 21000, bytes.fromhex("35" * 20), 10**18, b"")
assert out[-2].split()[3] == ("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e"
                              "1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"), "EIP-155 vector"
chains = [1, 10, 56, 61, 137, 8453, 42161, 43114, 11155111, 31337, 1337]
for i in range(60):
    priv = rb(32)
    kind = ["legacy155", "legacy0", "t1", "t2"][i % 4]
    chain = rnd.choice(chains)
    to = rb(20)
    value = rnd.choice([0, 1, 10**18, rnd.randrange(10**21), rnd.randrange(2**64)])
    data = b""
    mode = i % 7
    if mode == 1:
        data = bytes.fromhex("a9059cbb") + bytes(12) + rb(20) + rnd.choice([1, 10**6, rnd.randrange(2**200)]).to_bytes(32, "big")
    elif mode == 2:
        data = bytes.fromhex("095ea7b3") + bytes(12) + rb(20) + rnd.choice([2**256 - 1, 5 * 10**6]).to_bytes(32, "big")
    elif mode == 3:
        data = bytes.fromhex("23b872dd") + bytes(12) + rb(20) + bytes(12) + rb(20) + (rnd.randrange(2**120)).to_bytes(32, "big")
    elif mode == 4:
        data = rb(rnd.choice([4, 5, 36, 100, 300]))
    elif mode == 5:
        to = b""
        data = rb(rnd.choice([10, 80, 250]))
    access = [[rb(20), [rb(32), rb(32)]]] if kind in ("t1", "t2") and i % 3 == 0 else []
    evm_case(priv, kind, chain, rnd.choice([0, 1, 7, 255, 256, 70000]), rnd.choice([1, 10**9, rnd.randrange(10**12)]),
             rnd.choice([21000, 100000, 3000000]), to, value, data, prio=rnd.randrange(10**9), access=access)

# EIP-7702: set-code transactions and authorizations (the structure of the EIP: magic 0x05, rlp([chain_id, address, nonce]), tuples + y_parity, r, s)
r7 = random.Random(0x37373032)
def rb7(n): return bytes(r7.getrandbits(8) for _ in range(n))
def auth_tuple(authority, chain, addr, nonce):
    r, s, rec = sign_rec(authority, keccak(b"\x05" + rlp([chain, addr, nonce])))
    return [chain, addr, nonce, rec, r, s]
def auth_text(chain, addr, nonce):
    to = "CLEARS the delegation (address 0)" if addr == bytes(20) else "Delegate to " + eip55(addr)
    if chain == 0: am = "EVERY CHAIN (id 0), nonce %d" % nonce
    elif chain >= 2**64: am = "chain id above 2^64, nonce %d" % nonce
    else: am = "chain id %d, nonce %d" % (chain, nonce)
    return to, am
for case in range(8):
    priv = rb7(32)
    chain = [1, 10, 8453, 11155111, 1, 42161, 137, 1][case]
    auths, texts = [], []
    for j in range(1 + case % 4):
        ac = [chain, 0, chain, 2**70 + 5][(case + j) % 4]
        aa = bytes(20) if (case + j) % 5 == 4 else rb7(20)
        an = [0, 1, 5, 2**40][(case + j) % 4]
        auths.append(auth_tuple(rb7(32), ac, aa, an))
        texts.append(auth_text(ac, aa, an))
    evm_case(priv, "t4", chain, [0, 3, 255][case % 3], [10**9, 5 * 10**10][case % 2], [60000, 100000][case % 2], rb7(20), [0, 10**17][case % 2],
             rb7(36) if case == 3 else b"", prio=10**8, access=[], auths=auths)
    out.append("evmauths %s %s" % (out[-2].split()[2], " ".join("%s|%s" % (tl(t), tl(a)) for t, a in texts)))
for case in range(8):
    priv = rb7(32)
    ac = [1, 0, 10, 2**65, 8453, 1, 137, 0][case]
    aa = bytes(20) if case == 5 else rb7(20)
    an = [0, 1, 2, 7, 2**33, 99, 3, 4][case]
    payload = rlp([ac, aa, an])
    r, s, rec = sign_rec(priv, keccak(b"\x05" + payload))
    to, am = auth_text(ac, aa, an)
    out.append("evmauth %s %s %s %s" % (priv.hex(), payload.hex(), (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([rec])).hex(), "|".join(tl(x) for x in (to, am))))

# EIP-191 personal_sign and EIP-712 hashes
for L in (0, 1, 5, 31, 32, 33, 100, 255, 300):
    priv = rb(32)
    msg = bytes(rnd.choice(b"abcdefg hijk\n") for _ in range(L)) if L % 2 else rb(L)
    h = keccak(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)
    r, s, rec = sign_rec(priv, h)
    out.append("evmmsg %s %s %s" % (priv.hex(), hx(msg), (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])).hex()))
for _ in range(6):
    priv, ds, sh = rb(32), rb(32), rb(32)
    r, s, rec = sign_rec(priv, keccak(b"\x19\x01" + ds + sh))
    out.append("evmtyped %s %s %s %s" % (priv.hex(), ds.hex(), sh.hex(), (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + rec])).hex()))

exec(open(os.path.join(HERE, "txsign_more.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_nip.py"), encoding="utf-8").read())
import subprocess
exec(open(os.path.join(HERE, "txsign_ed.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_ton_ada.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_zec.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_kaspa.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_btcmsg.py"), encoding="utf-8").read())
exec(open(os.path.join(HERE, "txsign_bip322.py"), encoding="utf-8").read())

open(os.path.join(HERE, "..", "tests", "txsign_vectors.txt"), "w", newline="\n", encoding="utf-8").write("\n".join(out) + "\n")
print("wrote tests/txsign_vectors.txt (%d vectors)" % len(out))
