# The "sign message" vectors of the Bitcoin family (core/sign/btcmsg.c); exec'd inside tools/gen_txsign_vectors.py (out, hx, tl, sign_rec, sha256, keccak, G, N are defined).
#   btcmsg <chain id> <priv> <message hex | -> <sig65 = header r s> <address> <title>|<to>|<warn>|<note1>|<note2>|<note3>
# Bitcoin Core's signmessage with the headers of BIP137. Every signature is verified here by recovering the public key from it and encoding that as the address of its kind with
# bip_utils, which must be the address of the private key.
import random as _random
from bip_utils import Secp256k1PublicKey, P2PKHAddrEncoder, P2SHAddrEncoder, P2WPKHAddrEncoder, BchP2PKHAddrEncoder
from ecdsa.ellipticcurve import Point as _Pt

_m = _random.Random(0x4D534721)
def _mrb(n): return bytes(_m.getrandbits(8) for _ in range(n))
def _vi(n): return bytes([n]) if n < 0xfd else b"\xfd" + n.to_bytes(2, "little")
def _dsha(b): return sha256(sha256(b))

# id, magic, kind (p2pkh, p2sh, p2wpkh), address encoder
_COINS = [
    ("btc44", "Bitcoin Signed Message:\n", "p2pkh", lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x00"), "Bitcoin"),
    ("btc49", "Bitcoin Signed Message:\n", "p2sh", lambda k: P2SHAddrEncoder.EncodeKey(k, net_ver=b"\x05"), "Bitcoin"),
    ("btc84", "Bitcoin Signed Message:\n", "p2wpkh", lambda k: P2WPKHAddrEncoder.EncodeKey(k, hrp="bc"), "Bitcoin"),
    ("ltc84", "Litecoin Signed Message:\n", "p2wpkh", lambda k: P2WPKHAddrEncoder.EncodeKey(k, hrp="ltc"), "Litecoin"),
    ("ltc44", "Litecoin Signed Message:\n", "p2pkh", lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x30"), "Litecoin"),
    ("doge", "Dogecoin Signed Message:\n", "p2pkh", lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x1e"), "Dogecoin"),
    ("dash", "DarkCoin Signed Message:\n", "p2pkh", lambda k: P2PKHAddrEncoder.EncodeKey(k, net_ver=b"\x4c"), "Dash"),
    ("bch", "Bitcoin Signed Message:\n", "p2pkh", lambda k: BchP2PKHAddrEncoder.EncodeKey(k, hrp="bitcoincash", net_ver=b"\x00"), "Bitcoin Cash"),
]
_BASE = {"p2pkh": 31, "p2sh": 35, "p2wpkh": 39}


def _recover(h, rec, r, s):
    Pm = SECP256k1.curve.p()
    y = pow((pow(r, 3, Pm) + 7) % Pm, (Pm + 1) // 4, Pm)
    if (y & 1) != rec: y = Pm - y
    R = _Pt(SECP256k1.curve, r, y)
    z = int.from_bytes(h, "big")
    return (R * s + G * ((-z) % N)) * pow(r, -1, N)


for _i in range(24):
    _id, _magic, _kind, _enc, _name = _COINS[_i % len(_COINS)]
    _priv = _mrb(32)
    _L = _m.choice([0, 1, 11, 24, 100, 252, 253, 300, 500])
    _msg = bytes(_m.choice(b"abcdefg hijklmnopqrstuvwxyz.,") for _ in range(_L)) if _i % 3 != 2 else _mrb(_L)
    _h = _dsha(_vi(len(_magic)) + _magic.encode() + _vi(len(_msg)) + _msg)
    _r, _s, _rec = sign_rec(_priv, _h)
    _hdr = _BASE[_kind] + _rec
    _sig = bytes([_hdr]) + _r.to_bytes(32, "big") + _s.to_bytes(32, "big")
    _P = _recover(_h, _hdr - _BASE[_kind], _r, _s)
    assert _P == G * int.from_bytes(_priv, "big")
    _addr = _enc(Secp256k1PublicKey.FromBytes(b"\x02" + _P.x().to_bytes(32, "big") if not (_P.y() & 1) else b"\x03" + _P.x().to_bytes(32, "big")))
    _text = all((0x20 <= c < 0x7f) or c == 10 for c in _msg)
    _to = _msg.decode() if _text else _msg[:40].hex()
    _to = _to[:111]
    _notes = ["%d bytes%s" % (len(_msg), "" if _text else " (binary, shown in hex)"), "Signs as " + _addr[:80], "It proves you hold this address; it moves no funds"]
    out.append("btcmsg %s %s %s %s %s %s" % (_id, _priv.hex(), hx(_msg), _sig.hex(), _addr, "|".join(tl(x) for x in ["Sign message (%s)" % _name, _to, "0" if _text else "32"] + _notes)))
