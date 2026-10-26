#!/usr/bin/env python3
"""Known-answer vectors for the Bitcoin family signer (core/sign/btc.c): PSBT in, signatures and finished transaction out.

References: bip_utils (BIP32 keys, addresses of every coin), python-ecdsa (deterministic ECDSA, signature check), the signature hash
algorithms and the PSBT / transaction serialisation of BIP143, BIP341, BIP174 written out below from the specifications. Every
signature is verified here against the digest the reference computed. Run with
    python -I tools/gen_btc_vectors.py
Output: tests/btc_vectors.txt, lines (hex; "-" is empty)
    psbt <net> <seed> <psbt> <signed psbt> <final tx | -> <signatures>
    view <net> <seed> <psbt> <fee | -> <total> <warn> <nout> { <address> <amount> <mine> }*       ("~" for spaces)
    perr <net> <seed> <psbt> <error code>
"""
import hashlib, os, random, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]
from bip_utils import (Bip32Slip10Secp256k1, Base58Encoder, SegwitBech32Encoder, BchBech32Encoder, Bip39SeedGenerator, Bip39Languages)
from ecdsa import SigningKey, VerifyingKey, SECP256k1, util
from ecdsa.ellipticcurve import Point

G = SECP256k1.generator
CURVE = SECP256k1.curve
P = CURVE.p()
N = SECP256k1.order
rnd = random.Random(0xB17C01)
out = []


def rb(n):
    return bytes(rnd.getrandbits(8) for _ in range(n))


def sha256(b): return hashlib.sha256(b).digest()
def dsha(b): return sha256(sha256(b))
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()


def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)


def cs(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def push(b): return bytes([len(b)]) + b          # only short pushes are needed here


# ---- networks ----
NETS = {
    "btc": dict(sym="BTC", name="Bitcoin", p2pkh=0x00, p2sh=0x05, hrp="bc", cash=None, forkid=False),
    "ltc": dict(sym="LTC", name="Litecoin", p2pkh=0x30, p2sh=0x32, hrp="ltc", cash=None, forkid=False),
    "doge": dict(sym="DOGE", name="Dogecoin", p2pkh=0x1e, p2sh=0x16, hrp=None, cash=None, forkid=False),
    "dash": dict(sym="DASH", name="Dash", p2pkh=0x4c, p2sh=0x10, hrp=None, cash=None, forkid=False),
    "bch": dict(sym="BCH", name="Bitcoin Cash", p2pkh=0x00, p2sh=0x05, hrp=None, cash="bitcoincash", forkid=True),
}


def amount_text(v, net):
    s = "%d.%08d" % (v // 10**8, v % 10**8)
    s = s.rstrip("0").rstrip(".")
    return s + " " + NETS[net]["sym"]


def addr_of_script(net, spk):
    n = NETS[net]
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        if n["cash"]:
            return str(BchBech32Encoder.Encode(n["cash"], b"\x00", spk[3:23]))
        return Base58Encoder.CheckEncode(bytes([n["p2pkh"]]) + spk[3:23])
    if len(spk) == 23 and spk[0] == 0xa9 and spk[22] == 0x87:
        if n["cash"]:
            return str(BchBech32Encoder.Encode(n["cash"], b"", spk[2:22]))
        return Base58Encoder.CheckEncode(bytes([n["p2sh"]]) + spk[2:22])
    if len(spk) in (22, 34) and spk[0] == 0 and spk[1] in (0x14, 0x20) and n["hrp"]:
        return SegwitBech32Encoder.Encode(n["hrp"], 0, spk[2:])
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20 and n["hrp"]:
        return SegwitBech32Encoder.Encode(n["hrp"], 1, spk[2:])
    if spk[:1] == b"\x6a":
        return "OP_RETURN data"
    return spk[:24].hex() + (".." if len(spk) > 24 else "")


# ---- keys ----
def key_at(seed, path):
    k = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(path)
    return k.PrivateKey().Raw().ToBytes(), k.PublicKey().RawCompressed().ToBytes()


def master_fp(seed):
    return hash160(Bip32Slip10Secp256k1.FromSeed(seed).PublicKey().RawCompressed().ToBytes())[:4]


def path_bytes(path):
    r = b""
    for part in path.split("/")[1:]:
        h = part.endswith("'")
        r += struct.pack("<I", int(part.rstrip("'")) | (0x80000000 if h else 0))
    return r


NUMS_X = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")      # the BIP341 point without a known private key


def lift_x(x):
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    return Point(CURVE, x, y if y % 2 == 0 else P - y)


def tweak_xonly(xonly, merkle=b""):
    t = int.from_bytes(tagged("TapTweak", xonly + merkle), "big")
    Q = lift_x(int.from_bytes(xonly, "big")) + G * t
    return Q.x().to_bytes(32, "big")


def schnorr_sign(priv, msg):
    d0 = int.from_bytes(priv, "big")
    Pt = G * d0
    d = d0 if Pt.y() % 2 == 0 else N - d0
    aux = tagged("BIP0340/aux", bytes(32))
    t = (d ^ int.from_bytes(aux, "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + Pt.x().to_bytes(32, "big") + msg), "big") % N
    R = G * k0
    k = k0 if R.y() % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", R.x().to_bytes(32, "big") + Pt.x().to_bytes(32, "big") + msg), "big") % N
    return R.x().to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def ecdsa_sign_der(priv, digest):
    sk = SigningKey.from_string(priv, curve=SECP256k1, hashfunc=hashlib.sha256)
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=util.sigencode_string)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if s > N // 2:
        s = N - s
    vk = sk.get_verifying_key()
    assert vk.verify_digest(r.to_bytes(32, "big") + s.to_bytes(32, "big"), digest, sigdecode=util.sigdecode_string)

    def enc(v):
        b = v.to_bytes(32, "big").lstrip(b"\x00")
        if b[0] & 0x80: b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


# ---- transactions ----
def ser_tx(version, ins, outs, locktime, wit=None):
    """ins: list of (txid, vout, scriptsig, seq); outs: list of (value, spk); wit: list of witness item lists or None"""
    b = struct.pack("<I", version)
    if wit is not None:
        b += b"\x00\x01"
    b += cs(len(ins))
    for txid, vout, ss, seq in ins:
        b += txid + struct.pack("<I", vout) + cs(len(ss)) + ss + struct.pack("<I", seq)
    b += cs(len(outs))
    for v, spk in outs:
        b += struct.pack("<Q", v) + cs(len(spk)) + spk
    if wit is not None:
        for items in wit:
            b += cs(len(items)) + b"".join(cs(len(i)) + i for i in items)
    return b + struct.pack("<I", locktime)


def txid_of(version, ins, outs, locktime):
    return dsha(ser_tx(version, ins, outs, locktime))


def outs_blob(outs): return b"".join(struct.pack("<Q", v) + cs(len(s)) + s for v, s in outs)


def sighash_legacy(version, ins, outs, locktime, idx, script_code, ht):
    b = struct.pack("<I", version) + cs(len(ins))
    for j, (txid, vout, ss, seq) in enumerate(ins):
        b += txid + struct.pack("<I", vout)
        sc = script_code if j == idx else b""
        b += cs(len(sc)) + sc + struct.pack("<I", seq)
    b += cs(len(outs)) + outs_blob(outs) + struct.pack("<II", locktime, ht)
    return dsha(b)


def sighash_bip143(version, ins, outs, locktime, idx, script_code, amount, ht):
    hp = dsha(b"".join(t + struct.pack("<I", v) for t, v, _, _ in ins))
    hs = dsha(b"".join(struct.pack("<I", s) for _, _, _, s in ins))
    ho = dsha(outs_blob(outs))
    t, v, _, seq = ins[idx]
    b = struct.pack("<I", version) + hp + hs + t + struct.pack("<I", v) + cs(len(script_code)) + script_code
    b += struct.pack("<Q", amount) + struct.pack("<I", seq) + ho + struct.pack("<II", locktime, ht)
    return dsha(b)


def sighash_taproot(version, ins, outs, locktime, idx, prevs, ht, leaf=None):
    sp = sha256(b"".join(t + struct.pack("<I", v) for t, v, _, _ in ins))
    sa = sha256(b"".join(struct.pack("<Q", a) for a, _ in prevs))
    ss = sha256(b"".join(cs(len(s)) + s for _, s in prevs))
    sq = sha256(b"".join(struct.pack("<I", s) for _, _, _, s in ins))
    so = sha256(outs_blob(outs))
    m = b"\x00" + bytes([ht]) + struct.pack("<II", version, locktime) + sp + sa + ss + sq + so + (b"\x02" if leaf else b"\x00") + struct.pack("<I", idx)
    if leaf: m += leaf + b"\x00" + b"\xff\xff\xff\xff"                  # BIP342: the leaf hash, key version 0, no code separator
    return tagged("TapSighash", m)


# ---- PSBT ----
def kv(key, val): return cs(len(key)) + key + cs(len(val)) + val


def p2pkh(h): return b"\x76\xa9\x14" + h + b"\x88\xac"
def p2wpkh(h): return b"\x00\x14" + h
def p2sh(h): return b"\xa9\x14" + h + b"\x87"


def make_case(net, seed, kinds, other_seed=None, tamper=None, explicit_sighash=False, extra_outputs=True, locktime_o=None, seq_o=None, version_o=None, ms_change=None):
    """kinds: list of input kinds: p2pkh p2wpkh p2sh_wpkh p2tr p2tr_tree p2wsh p2sh_ms foreign.
    Returns (psbt bytes, expected signed psbt, final tx or None, nsig, summary info)"""
    n = NETS[net]
    coin = COINS[net]
    fp = master_fp(seed)
    ins, prev_infos = [], []
    in_maps = []
    wit_final = []
    for idx, kind in enumerate(kinds):
        sd = other_seed if kind == "foreign" else seed
        k = "p2wpkh" if kind == "foreign" else kind
        acct = rnd.randrange(3)
        purpose = {"p2pkh": 44, "p2sh_wpkh": 49, "p2wpkh": 84, "p2tr": 86, "p2tr_tree": 86, "p2tr_script": 86, "p2wsh": 48, "p2sh_ms": 45, "ms_wsh": 48, "ms_shwsh": 48, "ms_sh": 45}[k]
        path = "m/%d'/%d'/%d'/%d/%d" % (purpose, coin, acct, rnd.randrange(2), rnd.randrange(50))
        priv, pub = key_at(sd, path)
        fpr = master_fp(sd)
        redeem = wscript = tint = merkle = None
        ders = mskeys = mn = tleaf = None
        if k == "p2pkh":
            spk = p2pkh(hash160(pub))
        elif k == "p2wpkh":
            spk = p2wpkh(hash160(pub))
        elif k == "p2sh_wpkh":
            redeem = p2wpkh(hash160(pub))
            spk = p2sh(hash160(redeem))
        elif k in ("p2tr", "p2tr_tree"):
            tint = pub[1:]
            merkle = rb(32) if k == "p2tr_tree" else None
            spk = b"\x51\x20" + tweak_xonly(tint, merkle or b"")
        elif k == "p2tr_script":                                          # tr(NUMS, multi_a(2, ours, a cosigner)): one leaf, spent by its script path
            _, cpub2 = key_at(COSEEDS[0], path)
            tscript = bytes([0x20]) + pub[1:] + b"\xac" + bytes([0x20]) + cpub2[1:] + b"\xba\x52\x9c"       # <A> CHECKSIG <B> CHECKSIGADD 2 NUMEQUAL
            leafhash = tagged("TapLeaf", b"\xc0" + cs(len(tscript)) + tscript)
            tint = NUMS_X
            tt = int.from_bytes(tagged("TapTweak", tint + leafhash), "big")
            QQ = lift_x(int.from_bytes(tint, "big")) + G * tt
            spk = b"\x51\x20" + QQ.x().to_bytes(32, "big")
            tleaf = dict(script=tscript, leafhash=leafhash, ctrl=bytes([0xc0 | (QQ.y() & 1)]) + tint)
        elif k == "p2wsh":
            _, pub2 = key_at(sd, "m/48'/0'/0'/2'/0/1")
            _, pub3 = key_at(seed if kind != "foreign" else other_seed, "m/48'/0'/1'/2'/0/2")
            wscript = b"\x52" + push(pub) + push(pub2) + push(pub3) + b"\x53\xae"
            spk = b"\x00\x20" + sha256(wscript)
            mskeys, mn = [pub, pub2, pub3], (2, 3)
        elif k == "p2sh_ms":
            _, pub2 = key_at(sd, "m/45'/0'/0'/0/1")
            redeem = b"\x52" + push(pub) + push(pub2) + b"\x52\xae"
            spk = p2sh(hash160(redeem))
            mskeys, mn = [pub, pub2], (2, 2)
        elif k in ("ms_wsh", "ms_shwsh", "ms_sh"):                    # a wallet of three: our key and two cosigners, sorted keys at the same chain / index
            chain, widx = rnd.randrange(2), rnd.randrange(60)
            apath = acct_path(k, coin)
            path = "%s/%d/%d" % (apath, chain, widx)
            priv, pub = key_at(sd, path)
            recs = sorted([(key_at(sdx, path)[1], master_fp(sdx), path) for sdx in [sd] + COSEEDS], key=lambda r: r[0])
            ders = recs
            keys = [r[0] for r in recs]
            msc = ms_script(2, keys)
            if k == "ms_sh":
                redeem = msc; spk = p2sh(hash160(redeem))
            elif k == "ms_wsh":
                wscript = msc; spk = b"\x00\x20" + sha256(wscript)
            else:
                wscript = msc; redeem = b"\x00\x20" + sha256(wscript); spk = p2sh(hash160(redeem))
            mskeys, mn = keys, (2, 3)
        amount = rnd.randrange(20000, 5 * 10**8)
        # previous transaction: random inputs, our output among others
        pouts = [(rnd.randrange(1000, 10**8), p2wpkh(rb(20)))]
        pouts.insert(rnd.randrange(2), (amount, spk))
        vout = [o[1] for o in pouts].index(spk)
        pins = [(rb(32), rnd.randrange(4), rb(rnd.randrange(0, 30)), 0xfffffffd)]
        use_wit = rnd.random() < 0.5
        ptx = ser_tx(2, pins, pouts, rnd.randrange(100), [[rb(72), rb(33)]] if use_wit else None)
        pl = rnd.randrange(100)
        ptx = ser_tx(2, pins, pouts, pl, [[rb(72), rb(33)]] if use_wit else None)
        ptxid = dsha(ser_tx(2, pins, pouts, pl))
        ins.append((ptxid, vout, b"", 0xfffffffd if seq_o is None else seq_o[idx % len(seq_o)]))
        prev_infos.append(dict(kind=k, foreign=(kind == "foreign"), amount=amount, spk=spk, priv=priv, pub=pub, path=path, fp=fpr,
                               redeem=redeem, wscript=wscript, tint=tint, merkle=merkle, tleaf=tleaf, ptx=ptx, pub_all=None, ders=ders, mskeys=mskeys, mn=mn))
    # outputs: some external, one change of ours, optional OP_RETURN
    outs = []
    out_meta = []
    ext_kinds = [rnd.choice(["p2pkh", "p2wpkh", "p2sh", "p2tr"]) for _ in range(rnd.randrange(1, 3))]
    for ek in ext_kinds:
        pub = key_at(rb(32), "m/44'/0'/0'/0/0")[1]
        if ek == "p2pkh": spk = p2pkh(hash160(pub))
        elif ek == "p2sh": spk = p2sh(hash160(rb(22)))
        elif ek == "p2wpkh": spk = p2wpkh(hash160(pub))
        else: spk = b"\x51\x20" + pub[1:]
        if n["hrp"] is None and ek in ("p2wpkh", "p2tr"):
            spk = p2pkh(hash160(pub))
        outs.append((rnd.randrange(1000, 10**7), spk))
        out_meta.append(None)
    change_kind = rnd.choice(["p2wpkh", "p2pkh", "p2sh_wpkh", "p2tr"]) if n["hrp"] else "p2pkh"
    cpath = "m/%d'/%d'/0'/1/%d" % ({"p2pkh": 44, "p2wpkh": 84, "p2sh_wpkh": 49, "p2tr": 86}[change_kind], coin, rnd.randrange(30))
    cpriv, cpub = key_at(seed, cpath)
    cmap = b""
    if change_kind == "p2pkh":
        cspk = p2pkh(hash160(cpub)); cmap = kv(b"\x02" + cpub, fp + path_bytes(cpath))
    elif change_kind == "p2wpkh":
        cspk = p2wpkh(hash160(cpub)); cmap = kv(b"\x02" + cpub, fp + path_bytes(cpath))
    elif change_kind == "p2sh_wpkh":
        rs = p2wpkh(hash160(cpub)); cspk = p2sh(hash160(rs)); cmap = kv(b"\x00", rs) + kv(b"\x02" + cpub, fp + path_bytes(cpath))
    else:
        cspk = b"\x51\x20" + tweak_xonly(cpub[1:]); cmap = kv(b"\x05", cpub[1:]) + kv(b"\x07" + cpub[1:], b"\x00" + fp + path_bytes(cpath))
    outs.insert(rnd.randrange(len(outs) + 1), (rnd.randrange(1000, 10**7), cspk))
    mspk = mmap = None
    if ms_change:
        chain, widx = 1, rnd.randrange(60)
        apath = acct_path(ms_change, coin)
        path = "%s/%d/%d" % (apath, chain, widx)
        recs = sorted([(key_at(sdx, path)[1], master_fp(sdx), path) for sdx in [seed] + COSEEDS], key=lambda r: r[0])
        msc = ms_script(2, [r[0] for r in recs])
        if ms_change == "ms_wsh": mspk = b"\x00\x20" + sha256(msc); mmap = kv(b"\x01", msc)
        elif ms_change == "ms_shwsh": rs = b"\x00\x20" + sha256(msc); mspk = p2sh(hash160(rs)); mmap = kv(b"\x00", rs) + kv(b"\x01", msc)
        else: mspk = p2sh(hash160(msc)); mmap = kv(b"\x00", msc)
        mmap += b"".join(kv(b"\x02" + pb, fpx + path_bytes(pth)) for pb, fpx, pth in recs)
        outs.insert(rnd.randrange(len(outs) + 1), (rnd.randrange(1000, 10**7), mspk))
    out_meta = [None] * len(outs)
    out_maps = [b"\x00"] * len(outs)
    for j, (v, spk) in enumerate(outs):
        if spk == cspk:
            out_maps[j] = cmap + b"\x00"
        elif mspk is not None and spk == mspk:
            out_maps[j] = mmap + b"\x00"
    if extra_outputs and rnd.random() < 0.5:
        outs.append((0, b"\x6a\x04" + rb(4)))
        out_maps.append(b"\x00")
    version, locktime = 2, rnd.randrange(0, 900000)
    if version_o is not None: version = version_o
    if locktime_o is not None: locktime = locktime_o
    # PSBT inputs
    prevs = [(pi["amount"], pi["spk"]) for pi in prev_infos]
    sigs = []                                   # per input: list of (key bytes, value bytes) of the expected signature records
    finals = []                                 # per input: (scriptsig, witness items) or None
    nsig = 0
    for idx, pi in enumerate(prev_infos):
        k = pi["kind"]
        m = b""
        if k == "p2pkh" and False:
            pass
        tap = k in ("p2tr", "p2tr_tree")
        tscr = k == "p2tr_script"
        if not tap or True:
            m += kv(b"\x00", pi["ptx"])
        if k in ("p2wpkh", "p2sh_wpkh", "p2tr", "p2tr_tree", "p2tr_script", "p2wsh", "ms_wsh", "ms_shwsh"):
            m += kv(b"\x01", struct.pack("<Q", pi["amount"]) + cs(len(pi["spk"])) + pi["spk"])
        if explicit_sighash:
            m += kv(b"\x03", struct.pack("<I", (0 if tap else (0x41 if n["forkid"] else 1))) if not (tap or tscr) else struct.pack("<I", 1))
        if pi["redeem"]:
            m += kv(b"\x04", pi["redeem"])
        if pi["wscript"]:
            m += kv(b"\x05", pi["wscript"])
        if tscr:
            tl = pi["tleaf"]
            m += kv(b"\x15" + tl["ctrl"], tl["script"] + b"\xc0") + kv(b"\x16" + pi["pub"][1:], b"\x01" + tl["leafhash"] + pi["fp"] + path_bytes(pi["path"])) + kv(b"\x17", pi["tint"])
        elif tap:
            m += kv(b"\x16" + pi["tint"], b"\x00" + pi["fp"] + path_bytes(pi["path"])) + kv(b"\x17", pi["tint"])
            if pi["merkle"]:
                m += kv(b"\x18", pi["merkle"])
        elif pi["ders"]:
            for dpub, dfp, dpath in pi["ders"]:
                m += kv(b"\x06" + dpub, dfp + path_bytes(dpath))
        else:
            m += kv(b"\x06" + pi["pub"], pi["fp"] + path_bytes(pi["path"]))
        in_maps.append(m + b"\x00")
        # expected result
        sig_recs, fin = [], None
        if pi["foreign"]:
            sigs.append([]); finals.append(None)
            continue
        ht = 0x41 if n["forkid"] else 1
        if explicit_sighash and (tap or tscr):
            ht = 1
        if tscr:
            tht = 1 if explicit_sighash else 0
            dig = sighash_taproot(version, ins, outs, locktime, idx, prevs, tht, pi["tleaf"]["leafhash"])
            sg = schnorr_sign(pi["priv"], dig)
            sig_recs.append((b"\x14" + pi["pub"][1:] + pi["tleaf"]["leafhash"], sg + (bytes([tht]) if tht else b"")))
            fin = None
        elif tap:
            tweaked = None
            d0 = int.from_bytes(pi["priv"], "big")
            Pt = G * d0
            d = d0 if Pt.y() % 2 == 0 else N - d0
            t = int.from_bytes(tagged("TapTweak", pi["tint"] + (pi["merkle"] or b"")), "big")
            tweaked = ((d + t) % N).to_bytes(32, "big")
            tht = 1 if explicit_sighash else 0
            dig = sighash_taproot(version, ins, outs, locktime, idx, prevs, tht)
            sg = schnorr_sign(tweaked, dig)
            val = sg + (bytes([tht]) if tht else b"")
            sig_recs.append((b"\x13", val))
            fin = (b"", [val])
        else:
            if k == "p2pkh":
                sc = pi["spk"]; algo = "bip143" if n["forkid"] else "legacy"
            elif k == "p2wpkh":
                sc = p2pkh(pi["spk"][2:22]); algo = "bip143"
            elif k == "p2sh_wpkh":
                sc = p2pkh(pi["redeem"][2:22]); algo = "bip143"
            elif k in ("p2wsh", "ms_wsh", "ms_shwsh"):
                sc = pi["wscript"]; algo = "bip143"
            else:
                sc = pi["redeem"]; algo = "bip143" if n["forkid"] else "legacy"
            if algo == "bip143":
                dig = sighash_bip143(version, ins, outs, locktime, idx, sc, pi["amount"], ht)
            else:
                dig = sighash_legacy(version, ins, outs, locktime, idx, sc, ht)
            der = ecdsa_sign_der(pi["priv"], dig) + bytes([ht])
            sig_recs.append((b"\x02" + pi["pub"], der))
            if k == "p2pkh": fin = (push(der) + push(pi["pub"]), [])
            elif k == "p2wpkh": fin = (b"", [der, pi["pub"]])
            elif k == "p2sh_wpkh": fin = (push(pi["redeem"]), [der, pi["pub"]])
            else: fin = None
        sigs.append(sig_recs)
        finals.append(fin)
        nsig += len(sig_recs)
    unsigned = ser_tx(version, ins, outs, locktime)
    glob = kv(b"\x00", unsigned) + b"\x00"
    psbt = b"psbt\xff" + glob + b"".join(in_maps) + b"".join(out_maps)
    signed = b"psbt\xff" + glob
    for recs in sigs:
        signed += b"".join(kv(a, b) for a, b in recs) + b"\x00"
    signed += b"\x00" * len(outs)
    final = None
    if all(f is not None for f in finals):
        any_wit = any(f[1] for f in finals)
        wit = [f[1] for f in finals] if any_wit else None
        final = ser_tx(version, [(t, v, finals[i][0], s) for i, (t, v, _, s) in enumerate(ins)], outs, locktime, wit)
    # the summary the screen shows
    in_sum = sum(pi["amount"] for pi in prev_infos)
    out_sum = sum(v for v, _ in outs)
    spend = sum(v for v, spk in outs if spk != cspk)
    view = dict(fee=amount_text(in_sum - out_sum, net) if in_sum >= out_sum else None, total=amount_text(spend, net),
                outs=[(addr_of_script(net, spk), amount_text(v, net), 1 if spk == cspk else 0) for v, spk in outs],
                warn=0, in_sum=in_sum, out_sum=out_sum)
    view["info"] = dict(prevs=prev_infos, outs=outs, change=cspk, version=version, locktime=locktime, seqs=[i[3] for i in ins], seed=seed, msc=mspk, msc_kind=ms_change)
    return psbt, signed, final, nsig, view, ins


COSEEDS = [bytes([7]) * 64, bytes([9]) * 64]
COINS = {"btc": 0, "ltc": 2, "doge": 3, "dash": 5, "bch": 145}


def acct_path(k, coin):
    return {"ms_wsh": "m/48'/%d'/0'/2'" % coin, "ms_shwsh": "m/48'/%d'/0'/1'" % coin, "ms_sh": "m/45'"}[k]


def ms_script(m, keys):
    return bytes([0x50 + m]) + b"".join(bytes([33]) + k for k in keys) + bytes([0x50 + len(keys), 0xae])


WTYPE = {"ms_wsh": 1, "ms_shwsh": 2, "ms_sh": 3}


def wallet_policy(net, seed, k):
    """(descriptor with checksum, identifier hex (8 digits), [fingerprints in the order of the descriptor]) of the 2 of 3 wallet of the kind: our account first, then the cosigners'"""
    apath = acct_path(k, COINS[net])
    keys, body = [], b"PSXXMS01" + bytes([WTYPE[k], 1, 2, 3])
    for sd in [seed] + COSEEDS:
        acc = Bip32Slip10Secp256k1.FromSeed(sd).DerivePath(apath)
        fpx = master_fp(sd)
        comps = [int(c.rstrip("'")) | (0x80000000 if c.endswith("'") else 0) for c in apath.split("/")[1:]]
        keys.append(("[%s%s]%s/<0;1>/*" % (fpx.hex(), apath[1:].replace("'", "h"), acc.PublicKey().ToExtended()), fpx))
        body += fpx + bytes([len(comps)]) + b"".join(struct.pack(">I", c) for c in comps + [0] * (8 - len(comps)))
        body += acc.PublicKey().RawCompressed().ToBytes() + acc.ChainCode().ToBytes()
    fmt = {"ms_wsh": "wsh(%s)", "ms_shwsh": "sh(wsh(%s))", "ms_sh": "sh(%s)"}[k]
    text = fmt % ("sortedmulti(2," + ",".join(x[0] for x in keys) + ")")
    return text + "#" + desc_checksum(text), sha256(body)[:4].hex(), [x[1] for x in keys]


def vi(n): return 1 if n < 0xfd else 3 if n <= 0xffff else 5


def desc_checksum(desc):
    INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#" + chr(34) + chr(92) + " "
    CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GEN = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

    def pm(symbols):
        chk = 1
        for v in symbols:
            top = chk >> 35
            chk = (chk & 0x7ffffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if (top >> i) & 1 else 0
        return chk
    symbols, groups = [], []
    for ch in desc:
        v = INPUT.find(ch)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2]); groups = []
    if len(groups) == 1: symbols.append(groups[0])
    elif len(groups) == 2: symbols.append(groups[0] * 3 + groups[1])
    c = pm(symbols + [0] * 8) ^ 1
    return "".join(CS[(c >> (5 * (7 - i))) & 31] for i in range(8))


def input_cost(pi):
    """(bytes outside the witness, witness bytes) of a signed input, with 72 byte signatures (the same estimate the summary of btc.c makes)"""
    k = pi["kind"]
    if k == "p2pkh": return 41 + 107, 0
    if k == "p2wpkh": return 41, 108
    if k == "p2sh_wpkh": return 41 + 23, 108
    if k in ("p2tr", "p2tr_tree", "p2tr_script"): return 41, 66            # the key path estimate, as btc.c makes it
    m = pi["mn"][0]
    if k in ("p2wsh", "ms_wsh"): return 41, 2 + m * 73 + vi(len(pi["wscript"])) + len(pi["wscript"])
    if k == "ms_shwsh": return 41 + 35, 2 + m * 73 + vi(len(pi["wscript"])) + len(pi["wscript"])
    rl = len(pi["redeem"])                                   # p2sh_ms, ms_sh: a script hash with the redeem script in the scriptSig
    ss = 1 + m * 73 + (1 if rl < 76 else 2 if rl < 256 else 3) + rl
    return 41 + ss + (2 if ss >= 253 else 0), 0


def expected_notes(net, info, registered=()):
    """The extra lines of the summary, from the structure of the transaction (written out from the description, not from btc.c)"""
    import datetime
    notes, prevs, outs, n = [], info["prevs"], info["outs"], NETS[net]
    in_sum, out_sum = sum(p["amount"] for p in prevs), sum(v for v, _ in outs)
    nonwit, witsum, anywit = 4 + vi(len(prevs)) + 4, 0, False
    for p in prevs:
        b, w = input_cost(p)
        nonwit += b
        witsum += w if w else 1
        anywit = anywit or bool(w)
    nonwit += vi(len(outs)) + sum(8 + vi(len(sp)) + len(sp) for _, sp in outs)
    weight = 4 * nonwit + ((2 + witsum) if anywit else 0)
    vsize = (weight + 3) // 4
    if in_sum >= out_sum:
        r10 = (in_sum - out_sum) * 10 // vsize
        notes.append("Fee rate %d.%d sat/vB (about %d vB)" % (r10 // 10, r10 % 10, vsize))
    mss = [p for p in prevs if p["mn"]]
    unreg = any(p["kind"] not in registered for p in mss)
    if mss:
        if len({p["mn"] for p in mss}) > 1:
            notes.append("Several multisig scripts of different sizes")
        elif not unreg and len({p["kind"] for p in mss}) == 1:
            k = mss[0]["kind"]
            _, wid, fps = wallet_policy(net, info["seed"], k)
            notes.append("Wallet %s, 2 of 3:" % wid + "".join(" you" if i == 0 else " " + fps[i].hex() for i in range(3)))
        else:
            p0 = mss[0]
            line = "Multisig %d of %d:" % p0["mn"]
            recs = {d[0]: d for d in (p0["ders"] or [(p0["pub"], p0["fp"], p0["path"])])}
            for key in p0["mskeys"]:
                d = recs.get(key)
                line += " ?" if d is None else (" you" if d[1] == master_fp(info["seed"]) else " " + d[1].hex())
            notes.append(line)
    seqs = info["seqs"]
    if any(sq < 0xfffffffe for sq in seqs) and not n["forkid"]:
        notes.append("Replaceable (RBF): a higher fee can be set later")
    lt = info["locktime"]
    if lt:
        if all(sq == 0xffffffff for sq in seqs): notes.append("Lock time %d is not enforced: all inputs are final" % lt)
        elif lt < 500000000: notes.append("Cannot be mined before block %d" % lt)
        else:
            t = datetime.datetime.fromtimestamp(lt, datetime.timezone.utc)
            notes.append("Cannot be mined before %04d-%02d-%02d %02d:%02d UTC" % (t.year, t.month, t.day, t.hour, t.minute))
    ext = [1 for _, sp in outs if sp != info["change"] and sp[0] != 0x6a and not (info["msc"] is not None and sp == info["msc"] and info["msc_kind"] in registered)]
    if len(ext) > 1: notes.append("Pays %d addresses" % len(ext))
    nf = sum(1 for p in prevs if p["foreign"])
    if 0 < nf < len(prevs): notes.append("%d of %d inputs are not yours (payjoin?)" % (nf, len(prevs)))
    if any(p["kind"] == "p2tr_script" and not p["foreign"] for p in prevs): notes.append("Signs a Taproot script path; its other keys are not checked")
    if info["version"] not in (1, 2): notes.append("Transaction version %d (usual: 1 or 2)" % info["version"])
    return notes


def hx(b): return b.hex() if b else "-"


def emit(net, seed, kinds, **kw):
    psbt, signed, final, nsig, view, ins = make_case(net, seed, kinds, **kw)
    out.append("psbt %s %s %s %s %s %d" % (net, seed.hex(), psbt.hex(), signed.hex(), hx(final), nsig))
    warn = 0
    if view["fee"] is None:
        view["fee"] = "?"
        warn |= 2
    if view["fee"] != "?" and (view["in_sum"] - view["out_sum"]) * 10 > view["in_sum"]:
        warn |= 4
    # TXW_DATA (32) for OP_RETURN, TXW_UNKNOWN_SCRIPT never here, TXW_UNVERIFIED (8) when an amount came from a witness UTXO only
    if any(o[0] == "OP_RETURN data" for o in view["outs"]):
        warn |= 32
    if any(k == "foreign" for k in kinds) and not any(k != "foreign" for k in kinds):
        warn |= 64
    MSK = ("p2wsh", "p2sh_ms", "ms_wsh", "ms_shwsh", "ms_sh", "p2tr_script")
    if any(k in MSK for k in kinds):
        warn |= 1024                                  # a multisig input of a wallet that is not registered
    line = "view %s %s %s %s %s %d %d" % (net, seed.hex(), psbt.hex(), view["fee"].replace(" ", "~"), view["total"].replace(" ", "~"), warn, len(view["outs"]))
    for a, v, mine in view["outs"]:
        line += " %s %s %d" % (a.replace(" ", "~"), v.replace(" ", "~"), mine)
    out.append(line)
    notes = expected_notes(net, view["info"])
    out.append("note %s %s %s %d%s" % (net, seed.hex(), psbt.hex(), len(notes), "".join(" " + t.replace(" ", "~") for t in notes)))
    # the same with registered wallets: pview / pnote <net> <seed> <psbt> <number of descriptors> <descriptors> then the fields of view / note
    wkinds = [k for k in ("ms_wsh", "ms_shwsh", "ms_sh") if k in kinds]
    if view["info"]["msc_kind"] and view["info"]["msc_kind"] not in wkinds:
        wkinds.append(view["info"]["msc_kind"])
    if wkinds:
        regs = [tuple(wkinds)]
        if len(wkinds) > 1:
            regs.append((wkinds[0],))
        for reg in regs:
            descs = [wallet_policy(net, seed, k)[0] for k in reg]
            unreg = any(k in MSK and k not in reg for k in kinds)
            w2 = (warn & ~1024) | (1024 if unreg else 0)
            msc, mk = view["info"]["msc"], view["info"]["msc_kind"]
            mine_ms = msc is not None and mk in reg
            outs_v = [(a, v, 1 if (m or (mine_ms and addr_of_script(net, msc) == a)) else 0) for a, v, m in view["outs"]]
            total = sum(v for v, spk in view["info"]["outs"] if spk != view["info"]["change"] and not (mine_ms and spk == msc))
            line2 = "pview %s %s %s %d %s %s %s %d %d" % (net, seed.hex(), psbt.hex(), len(descs), " ".join(descs), view["fee"].replace(" ", "~"), amount_text(total, net).replace(" ", "~"), w2, len(outs_v))
            for a, v, mine in outs_v:
                line2 += " %s %s %d" % (a.replace(" ", "~"), v.replace(" ", "~"), mine)
            out.append(line2)
            notes2 = expected_notes(net, view["info"], reg)
            out.append("pnote %s %s %s %d %s %d%s" % (net, seed.hex(), psbt.hex(), len(descs), " ".join(descs), len(notes2), "".join(" " + t.replace(" ", "~") for t in notes2)))
    return psbt


seeds = [rb(64) for _ in range(6)]
oth = rb(64)
# a mixed Bitcoin transaction with every input kind
emit("btc", seeds[0], ["p2wpkh", "p2pkh", "p2sh_wpkh", "p2tr"])
emit("btc", seeds[1], ["p2tr", "p2tr_tree"])
emit("btc", seeds[2], ["p2wpkh"], explicit_sighash=True)
emit("btc", seeds[2], ["p2pkh", "p2tr"], explicit_sighash=True)
for i in range(24):
    kinds = [rnd.choice(["p2pkh", "p2wpkh", "p2sh_wpkh", "p2tr", "p2tr_tree"]) for _ in range(rnd.randrange(1, 6))]
    emit("btc", seeds[i % 6], kinds)
for net in ("ltc", "ltc", "ltc"):
    emit(net, seeds[3], [rnd.choice(["p2pkh", "p2wpkh", "p2sh_wpkh"]) for _ in range(rnd.randrange(1, 4))])
for net in ("doge", "doge", "dash", "dash"):
    emit(net, seeds[4], ["p2pkh"] * rnd.randrange(1, 4))
for _ in range(4):
    emit("bch", seeds[5], ["p2pkh"] * rnd.randrange(1, 4))
emit("bch", seeds[5], ["p2pkh"], explicit_sighash=True)
# foreign inputs: ours are signed, theirs are left alone (no finished transaction then)
emit("btc", seeds[0], ["p2wpkh", "foreign", "p2pkh"], other_seed=oth)
emit("btc", seeds[0], ["foreign", "p2tr"], other_seed=oth)
# multi signature scripts: only our signature is added
emit("btc", seeds[1], ["p2wsh"])
emit("btc", seeds[1], ["p2sh_ms", "p2wpkh"])
# nothing of ours
emit("btc", seeds[0], ["foreign", "foreign"], other_seed=oth)

# a previous transaction that is not the one spent: the signer must refuse
for kinds in (["p2wpkh"], ["p2pkh"], ["p2tr", "p2wpkh"]):
    psbt, signed, final, nsig, view, ins = make_case("btc", seeds[0], kinds)
    # damage one byte of the first non-witness UTXO (type 0 record: key 0x00): flip a byte inside the previous transaction
    marker = b"\x01\x00"                          # key length 1, key type 0
    pos = psbt.index(marker, psbt.index(b"\x00", 5 + 5) if False else 0)
    # find the first input map: it starts after the global map; locate by walking the structure
    off = 5
    while psbt[off] != 0:
        kl = psbt[off]; off += 1 + kl
        vl, c = psbt[off], 1
        if vl == 0xfd: vl = struct.unpack("<H", psbt[off + 1:off + 3])[0]; c = 3
        off += c + vl
    off += 1                                      # now at the first input map
    assert psbt[off] == 1 and psbt[off + 1] == 0
    off += 2
    vl, c = psbt[off], 1
    if vl == 0xfd: vl = struct.unpack("<H", psbt[off + 1:off + 3])[0]; c = 3
    # flip a byte in the output value area of the previous tx (a copy that still parses, hashes differently)
    bad = bytearray(psbt)
    bad[off + c + vl - 1] ^= 0x01
    out.append("perr btc %s %s -3" % (seeds[0].hex(), bytes(bad).hex()))

# the summary lines: multisig (script hash kinds with cosigners), time based and final lock times, the version
emit("btc", seeds[1], ["ms_wsh"])
emit("btc", seeds[2], ["ms_shwsh", "p2wpkh"])
emit("btc", seeds[3], ["ms_sh"])
emit("btc", seeds[3], ["ms_wsh", "ms_wsh", "ms_shwsh"])
emit("btc", seeds[4], ["ms_wsh", "p2sh_ms"])
emit("ltc", seeds[3], ["ms_wsh"])
emit("btc", seeds[0], ["p2wpkh"], locktime_o=1900000000)
emit("btc", seeds[0], ["p2wpkh", "p2tr"], seq_o=[0xffffffff], locktime_o=700000)
emit("btc", seeds[0], ["p2pkh"], seq_o=[0xfffffffe], locktime_o=800000)
emit("btc", seeds[0], ["p2wpkh"], version_o=1, locktime_o=0)
emit("btc", seeds[0], ["p2wpkh"], version_o=3)
emit("bch", seeds[5], ["p2pkh", "p2pkh"], seq_o=[0xfffffffd])
# registered multisig wallets: the inputs are named, a change output of the wallet is recognised
emit("btc", seeds[1], ["ms_wsh"], ms_change="ms_wsh")
emit("btc", seeds[1], ["ms_wsh", "ms_wsh"], ms_change="ms_wsh")
emit("btc", seeds[2], ["ms_shwsh"], ms_change="ms_shwsh")
emit("btc", seeds[3], ["ms_sh", "p2wpkh"], ms_change="ms_sh")
emit("btc", seeds[4], ["ms_wsh", "ms_shwsh"])
emit("btc", seeds[0], ["p2wpkh"], ms_change="ms_wsh")                  # a wallet that spends from a single key key to its multisig wallet
emit("ltc", seeds[3], ["ms_wsh"], ms_change="ms_wsh")
emit("btc", seeds[5], ["ms_wsh", "p2wsh"], ms_change="ms_wsh")

# the demo of the emulator: a 2 of 3 wallet whose first key is that of the test mnemonic ("abandon ... about"), its descriptor and a PSBT that spends from it and sends
# change back to it (tools/psxx_tx.py ms-demo puts them on the card of the signer)
_seed = Bip39SeedGenerator("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Bip39Languages.ENGLISH).Generate("")
_psbt = emit("btc", _seed, ["ms_wsh"], ms_change="ms_wsh")
open(os.path.join(HERE, "..", "tests", "ms_demo.txt"), "w", newline="\n").write("descriptor %s\npsbt %s\n" % (wallet_policy("btc", _seed, "ms_wsh")[0], _psbt.hex()))

# Taproot script path (BIP342): a 2 of 2 multi_a leaf, signed with our key
emit("btc", seeds[0], ["p2tr_script"])
emit("btc", seeds[1], ["p2tr_script", "p2wpkh"])
emit("btc", seeds[2], ["p2tr_script"], explicit_sighash=True)
emit("btc", seeds[3], ["p2tr", "p2tr_script", "foreign"], other_seed=oth)

open(os.path.join(HERE, "..", "tests", "btc_vectors.txt"), "w", newline="\n").write("\n".join(out) + "\n")
print("wrote tests/btc_vectors.txt (%d vectors)" % len(out))
