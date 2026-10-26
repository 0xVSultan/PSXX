# The Kaspa vectors of tools/gen_txsign_vectors.py (exec'd inside its namespace: out, hx, tl, fmt, sha256, SECP256k1, G, N are defined).
#   kassh <tx> <input index> <signature hash>              the signature hash of the request format of core/sign/kaspa.h, the first one is the official vector of rusty-kaspa
#   kas   <tx> <keys c:i:priv,... | -> <KSIG hex | -> <title>|<fee>|<total>|<warn>|<note1>|<note2>|<note3>  <to>|<amount>|<mine> ...
# The signature hash: BLAKE2b-256 keyed with "TransactionSigningHash" over the fields of rusty-kaspa consensus/core/src/hashing/sighash.rs (version 0); the schnorr signature is BIP340
# written out here from the specification and checked by its own verification.
import hashlib as _hl
import random as _random
import struct as _struct

_q = _random.Random(0x4B415350)               # "KASP": its own stream, the other vectors stay as they were
def _rb(n): return bytes(_q.getrandbits(8) for _ in range(n))
def _kh(data=b""): return _hl.blake2b(data, digest_size=32, key=b"TransactionSigningHash").digest()
def _u(v, n): return v.to_bytes(n, "little")
def _vb(b): return _u(len(b), 8) + b


def _tagged(tag, m):
    t = sha256(tag.encode())
    return sha256(t + t + m)


def _xonly(sk):
    P = G * sk
    return P.x().to_bytes(32, "big"), P.y() & 1


def bip340_sign(sk_bytes, msg, aux=bytes(32)):
    d0 = int.from_bytes(sk_bytes, "big")
    px, odd = _xonly(d0)
    d = N - d0 if odd else d0
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + px + msg), "big") % N
    R = G * k0
    k = N - k0 if R.y() & 1 else k0
    rx = R.x().to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + msg), "big") % N
    sig = rx + ((k + e * d) % N).to_bytes(32, "big")
    assert bip340_verify(px, msg, sig)
    return sig


def bip340_verify(px, msg, sig):
    from ecdsa.ellipticcurve import Point
    P_ = SECP256k1.curve.p()
    x = int.from_bytes(px, "big")
    y = pow((pow(x, 3, P_) + 7) % P_, (P_ + 1) // 4, P_)
    if y & 1: y = P_ - y
    P = Point(SECP256k1.curve, x, y)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + px + msg), "big") % N
    R = G * s + P * ((N - e) % N)
    return R.x() == r and not (R.y() & 1)


def _kas_addr(version, data):
    def pm(vals):
        c = 1
        for d in vals:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            for i, g in enumerate((0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)):
                if (c0 >> i) & 1: c ^= g
        return c ^ 1
    bits = "".join(format(b, "08b") for b in bytes([version]) + data)
    bits += "0" * (-len(bits) % 5)
    d5 = [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    cs = pm([ord(c) & 31 for c in "kaspa"] + [0] + d5 + [0] * 8)
    cs5 = [(cs >> (5 * (7 - i))) & 31 for i in range(8)]
    return "kaspa:" + "".join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[v] for v in d5 + cs5)


def _spk_schnorr(sk): return b"\x20" + _xonly(int.from_bytes(sk, "big"))[0] + b"\xac"


def _script_text(spk):
    if len(spk) == 34 and spk[0] == 0x20 and spk[33] == 0xac: return _kas_addr(0, spk[1:33]), 0
    if len(spk) == 35 and spk[0] == 0x21 and spk[34] == 0xab: return _kas_addr(1, spk[1:34]), 0
    if len(spk) == 35 and spk[0] == 0xaa and spk[1] == 0x20 and spk[34] == 0x87: return _kas_addr(8, spk[2:34]), 0
    return "script v0 " + spk[:20].hex(), 1


def _encode(version, lock, ins, outs):
    """ins: dict(txid, index, seq, sigops, amount, spk, key=(change, idx) | None); outs: dict(value, spk, chg=(change, idx) | None)"""
    b = _u(version, 2) + bytes([len(ins), len(outs)]) + _u(lock, 8)
    for i in ins:
        b += i["txid"] + _u(i["index"], 4) + _u(i["seq"], 8) + bytes([i["sigops"]]) + _u(i["amount"], 8) + _u(0, 2) + bytes([len(i["spk"])]) + i["spk"]
        b += bytes([1]) + _u(i["key"][0], 4) + _u(i["key"][1], 4) if i["key"] else bytes([0])
    for o in outs:
        b += _u(o["value"], 8) + _u(0, 2) + bytes([len(o["spk"])]) + o["spk"]
        b += bytes([1]) + _u(o["chg"][0], 4) + _u(o["chg"][1], 4) if o["chg"] else bytes([0])
    return b


def _sighash(lock, ins, outs, i):
    prev = _kh(b"".join(x["txid"] + _u(x["index"], 4) for x in ins))
    seqs = _kh(b"".join(_u(x["seq"], 8) for x in ins))
    sigs = _kh(bytes(x["sigops"] for x in ins))
    outh = _kh(b"".join(_u(o["value"], 8) + _u(0, 2) + _vb(o["spk"]) for o in outs))
    x = ins[i]
    d = _u(0, 2) + prev + seqs + sigs + x["txid"] + _u(x["index"], 4) + _u(0, 2) + _vb(x["spk"]) + _u(x["amount"], 8) + _u(x["seq"], 8) + bytes([x["sigops"]])
    d += outh + _u(lock, 8) + bytes(20) + _u(0, 8) + bytes(32) + bytes([1])
    return _kh(d)


# the official vector (rusty-kaspa sighash.rs, native-all-0 .. input 0), written in the request format
_t = bytes.fromhex("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3")
_s1 = bytes.fromhex("208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac")
_s2 = bytes.fromhex("20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac")
_oi = [dict(txid=_t, index=k, seq=k, sigops=0, amount=a, spk=s, key=None) for k, (a, s) in enumerate([(100, _s1), (200, _s2), (300, _s2)])]
_oo = [dict(value=300, spk=_s2, chg=None), dict(value=300, spk=_s1, chg=None)]
_h0 = _sighash(1615462089000, _oi, _oo, 0)
assert _h0.hex() == "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5", "the official Kaspa vector"
out.append("kassh %s 0 %s" % (_encode(0, 1615462089000, _oi, _oo).hex(), _h0.hex()))


def _case(nin, nout, lock, ours, chg_out, tamper=None):
    keys = {}
    ins, outs = [], []
    for k in range(nin):
        sk = _rb(32)
        while not (0 < int.from_bytes(sk, "big") < N): sk = _rb(32)
        ci = (_q.choice([0, 1]), _q.randrange(0, 50))
        if ours[k]:
            keys[ci] = sk
            spk = _spk_schnorr(sk)
        else:
            spk = _spk_schnorr(_rb(32) if False else (lambda x: x)(bytes(31) + bytes([k + 2])))
        if tamper == "spk" and k == 0 and ours[k]:
            spk = _spk_schnorr(bytes(31) + bytes([9]))
        ins.append(dict(txid=_rb(32), index=_q.randrange(0, 5), seq=_q.choice([0, 2**64 - 1, 5]), sigops=_q.choice([0, 1]), amount=_q.choice([10**8, 5 * 10**8, 12345678901]), spk=spk,
                        key=ci if ours[k] else None))
    total_in = sum(i["amount"] for i in ins)
    for j in range(nout):
        kind = (j + nin) % 4
        v = total_in // (nout + 1)
        if chg_out and j == nout - 1:
            sk = _rb(32)
            while not (0 < int.from_bytes(sk, "big") < N): sk = _rb(32)
            ci = (1, _q.randrange(0, 50))
            keys[ci] = sk
            outs.append(dict(value=v, spk=_spk_schnorr(sk), chg=ci))
        elif kind == 0:
            outs.append(dict(value=v, spk=_spk_schnorr(_rb(31) + b"\x03"), chg=None))
        elif kind == 1:
            outs.append(dict(value=v, spk=b"\x21" + b"\x02" + _rb(32) + b"\xab", chg=None))
        elif kind == 2:
            outs.append(dict(value=v, spk=b"\xaa\x20" + _rb(32) + b"\x87", chg=None))
        else:
            outs.append(dict(value=v, spk=b"\x51\x52", chg=None))
    tx = _encode(0, lock, ins, outs)
    return tx, ins, outs, keys


def _emit(tx, ins, outs, keys, lock, expect_sign=True):
    sigs = []
    for i, x in enumerate(ins):
        if not x["key"] or x["key"] not in keys: continue
        if x["spk"] != _spk_schnorr(keys[x["key"]]):
            expect_sign = False
            continue
        h = _sighash(lock, ins, outs, i)
        sigs.append(bytes([i, 66, 0x41]) + bip340_sign(keys[x["key"]], h) + b"\x01")
    ksig = b"KSIG" + bytes([1, len(sigs)]) + b"".join(sigs) if expect_sign and sigs else None
    keystr = ",".join("%d:%d:%s" % (c, i, sk.hex()) for (c, i), sk in keys.items()) or "-"
    # the view
    nsign = sum(1 for x in ins if x["key"] and x["spk"] == _spk_schnorr(keys[x["key"]]))
    in_sum = sum(x["amount"] for x in ins)
    out_sum = sum(o["value"] for o in outs)
    warn, sent, rows = 0, 0, []
    for o in outs:
        text, unk = _script_text(o["spk"])
        warn |= unk
        mine = 1 if o["chg"] and o["spk"] == _spk_schnorr(keys[o["chg"]]) else 0
        if not mine: sent += o["value"]
        rows.append("%s|%s|%d" % (tl(text), tl(fmt(o["value"], 8, "KAS")), mine))
    if not nsign: warn |= 64
    fee = ""
    if in_sum >= out_sum:
        fee = fmt(in_sum - out_sum, 8, "KAS")
        if sent and (in_sum - out_sum) * 10 > sent: warn |= 4
    else:
        warn |= 2
    notes = ["%d input%s (%d ours), %d output%s" % (len(ins), "" if len(ins) == 1 else "s", nsign, len(outs), "" if len(outs) == 1 else "s")]
    if lock: notes.append("Lock time %d" % lock)
    notes = (notes + ["", "", ""])[:3]
    out.append("kas %s %s %s %s %s" % (tx.hex(), keystr, ksig.hex() if ksig else "-", "|".join(tl(x) for x in ["Kaspa transaction", fee, fmt(sent, 8, "KAS"), str(warn)] + notes), " ".join(rows)))


for _n, (_nin, _nout, _lock, _ours, _chg) in enumerate([
        (1, 1, 0, [True], False), (1, 2, 0, [True], True), (2, 2, 1615462089000, [True, True], True), (3, 3, 0, [True, False, True], True),
        (2, 1, 7, [False, False], False), (1, 3, 0, [True], True), (4, 2, 0, [True, True, False, True], False), (2, 4, 0, [True, True], True)]):
    _tx, _ins, _outs, _keys = _case(_nin, _nout, _lock, _ours, _chg)
    _emit(_tx, _ins, _outs, _keys, _lock)
    for _i in range(_nin):
        if _n % 3 == 0 and _i < 2:
            out.append("kassh %s %d %s" % (_tx.hex(), _i, _sighash(_lock, _ins, _outs, _i).hex()))
# an input that claims to be ours but whose script is not the one of its key: shown as not ours, and not signed
_tx, _ins, _outs, _keys = _case(2, 2, 0, [True, True], True, tamper="spk")
_emit(_tx, _ins, _outs, _keys, 0)
