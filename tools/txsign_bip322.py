# BIP322 "simple" message signatures of P2WPKH and P2TR (key path) addresses (core/sign/btcmsg.c); exec'd inside tools/gen_txsign_vectors.py after txsign_btcmsg.py
# (out, hx, sha256, G, N, sign_rec, _vi, _dsha, _tagged, bip340_sign, bip340_verify, _mrb are defined).
#   bip322 <p2wpkh|p2tr> <priv> <message hex | -> <message hash> <to_spend txid> <witness of the signature, hex>
# Written from the BIP (to_spend / to_sign, BIP143 and BIP341 signature hashes). Checked against the official basic test vectors of the BIP (message hash, to_spend txid, and the
# signatures that are valid for the key), which are fetched by the check below when a copy of bip-0322/basic-test-vectors.json is in build/refpkgs (optional).
import json as _json
from bip_utils import Hash160 as _H160
from ecdsa.ellipticcurve import Point as _P322


def _b322_hash(msg):
    t = sha256(b"BIP0322-signed-message")
    return sha256(t + t + msg)


def _b322_spend(spk, mh):
    raw = bytes(4) + b"\x01" + bytes(32) + b"\xff\xff\xff\xff" + bytes([34]) + b"\x00\x20" + mh + bytes(4) + b"\x01" + bytes(8) + _vi(len(spk)) + spk + bytes(4)
    return _dsha(raw)


def _der(r, s):
    def i(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return (b"\x00" + b) if b[0] & 0x80 else b
    ri, si = i(r), i(s)
    body = b"\x02" + bytes([len(ri)]) + ri + b"\x02" + bytes([len(si)]) + si
    return b"\x30" + bytes([len(body)]) + body


def _pub(k):
    P = G * k
    return bytes([2 + (P.y() & 1)]) + P.x().to_bytes(32, "big")


def _tweaked(priv):
    d0 = int.from_bytes(priv, "big")
    P = G * d0
    d = N - d0 if P.y() & 1 else d0
    px = P.x().to_bytes(32, "big")
    t = int.from_bytes(_tagged("TapTweak", px), "big")
    dq = (d + t) % N
    Q = G * dq
    if Q.y() & 1: dq = N - dq
    return dq.to_bytes(32, "big"), Q.x().to_bytes(32, "big")


def _b322_sighash_wpkh(txid, h160):
    prev = txid + bytes(4)
    pre = bytes(4) + _dsha(prev) + _dsha(bytes(4)) + prev + b"\x19\x76\xa9\x14" + h160 + b"\x88\xac" + bytes(8) + bytes(4) + _dsha(bytes(8) + b"\x01\x6a") + bytes(4) + (1).to_bytes(4, "little")
    return _dsha(pre)


def _b322_sighash_tr(txid, spk):
    m = (b"\x00" + b"\x00" + bytes(4) + bytes(4) + sha256(txid + bytes(4)) + sha256(bytes(8)) + sha256(_vi(len(spk)) + spk)
         + sha256(bytes(4)) + sha256(bytes(8) + b"\x01\x6a") + b"\x00" + bytes(4))
    return _tagged("TapSighash", m)


def _b322(kind, priv, msg):
    mh = _b322_hash(msg)
    if kind == "p2wpkh":
        pub = _pub(int.from_bytes(priv, "big"))
        h160 = _H160.QuickDigest(pub)
        spk = b"\x00\x14" + h160
        txid = _b322_spend(spk, mh)
        r, s, _ = sign_rec(priv, _b322_sighash_wpkh(txid, h160))
        der = _der(r, s) + b"\x01"
        wit = b"\x02" + _vi(len(der)) + der + b"\x21" + pub
    else:
        tk, qx = _tweaked(priv)
        spk = b"\x51\x20" + qx
        txid = _b322_spend(spk, mh)
        sig = bip340_sign(tk, _b322_sighash_tr(txid, spk))
        wit = b"\x01\x40" + sig
    return mh, txid, wit


_m322 = _random.Random(0x42495033)
for _i in range(20):
    _kind = "p2wpkh" if _i % 2 == 0 else "p2tr"
    _priv = bytes(_m322.getrandbits(8) for _ in range(32))
    _L = _m322.choice([0, 1, 11, 31, 32, 33, 63, 64, 65, 100, 252, 253, 300])
    _msg = bytes(_m322.getrandbits(8) for _ in range(_L)) if _i % 3 == 2 else bytes(_m322.choice(b"abc defgh.") for _ in range(_L))
    _mh, _txid, _wit = _b322(_kind, _priv, _msg)
    out.append("bip322 %s %s %s %s %s %s" % (_kind, _priv.hex(), hx(_msg), _mh.hex(), _txid.hex(), _wit.hex()))

# the official vectors of the BIP: the message hash and the to_spend txid (displayed reversed), the P2WPKH signatures (our deterministic one must be one of them), the P2TR one verifies
import base64 as _b64
_f = os.path.join(HERE, "..", "build", "refpkgs", "bip322_basic.json")
if os.path.exists(_f):
    _d = _json.load(open(_f, encoding="utf-8"))
    from bip_utils import WifDecoder as _Wd
    _k0 = _Wd.Decode("L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k")[0]          # the key of the address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l
    _spk0 = b"\x00\x14" + _H160.QuickDigest(_pub(int.from_bytes(_k0, "big")))
    for _e in _d["tx_hashes"]:
        _hv = _b322_hash(_e["message"].encode("utf-8"))
        assert _hv.hex() == _e["message_hash"], "BIP322 message hash"
        assert _b322_spend(_spk0, _hv)[::-1].hex() == _e["to_spend_tx_hash"], "BIP322 to_spend txid"
    for _e in _d["simple"]:
        if _e["type"] == "p2wpkh":
            _pr = _Wd.Decode(_e["private_keys"][0])[0]
            _mh, _txid, _wit = _b322("p2wpkh", _pr, _e["message"].encode("utf-8"))
            _sigs = [_b64.b64decode(x[3:]) for x in _e["bip322_signatures"]]
            assert _wit in _sigs, "BIP322 p2wpkh signature is not one of the official ones"
            out.append("bip322 p2wpkh %s %s %s %s %s" % (_pr.hex(), hx(_e["message"].encode("utf-8")), _mh.hex(), _txid.hex(), _wit.hex()))
        elif _e["type"] == "p2tr":
            _pr = _Wd.Decode(_e["private_keys"][0])[0]
            _tk, _qx = _tweaked(_pr)
            _mh = _b322_hash(_e["message"].encode("utf-8"))
            _spk = b"\x51\x20" + _qx
            _tx = _b322_spend(_spk, _mh)
            _w = _b64.b64decode(_e["bip322_signatures"][0])
            assert _w[:2] == b"\x01\x40" and bip340_verify(_qx, _b322_sighash_tr(_tx, _spk), _w[2:]), "official BIP322 p2tr signature does not verify"
            out.append("bip322 p2tr %s %s %s %s %s" % (_pr.hex(), hx(_e["message"].encode("utf-8")), _mh.hex(), _tx.hex(), _b322("p2tr", _pr, _e["message"].encode("utf-8"))[2].hex()))
