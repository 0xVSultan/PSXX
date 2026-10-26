# The Zcash transparent vectors of tools/gen_txsign_vectors.py (exec'd inside its namespace).
# The signature hashes come from the reference implementation of the Zcash foundation (build/refzcash: zip_0243.py, zip_0244.py).
#   zecsign <seed> <request> <signed tx>       zecview <request> <title>|<fee>|<total>|<warn>|<n1>|<n2>|<n3>|<nout>|(to|amount)*
#   zecerr  <seed> <request> <code>
sys.path.insert(0, os.path.join(HERE, "..", "build", "refzcash"))
from zcash_test_vectors import zip_0243, zip_0244
from bip_utils import Bip32Slip10Secp256k1


def zcs(n):
    if n < 0xFD: return bytes([n])
    return b"\xfd" + struct.pack("<H", n)


class ZPrev:
    def __init__(s, txid, n): s.txid, s.n = txid, n
    def __bytes__(s): return s.txid + struct.pack("<I", s.n)


class ZScript:
    def __init__(s, b): s.b = b
    def __bytes__(s): return zcs(len(s.b)) + s.b


class ZIn:
    def __init__(s, txid, n, seq): s.prevout, s.nSequence, s.scriptSig = ZPrev(txid, n), seq, b""


class ZOut:
    def __init__(s, v, spk): s.v, s.spk = v, spk
    def __bytes__(s): return struct.pack("<Q", s.v) + zcs(len(s.spk)) + s.spk


class ZTx:
    pass


class ZTIn:
    def __init__(s, n, amount, spk): s.nIn, s.amount, s.scriptPubKey = n, amount, ZScript(spk)


def zec_addr(prefix, h): return Base58Encoder.CheckEncode(prefix + h)


def zec_case(seed, ver, ninputs, ours=None, shielded=False, optype=None):
    branch = 0x76B809BB if ver == 4 else rnd.choice([0xC2D6D0B4, 0xC8E71055])
    vin, tin, infos = [], [], []
    for i in range(ninputs):
        acct, idx = rnd.randrange(3), rnd.randrange(30)
        sd = seed if (ours is None or ours[i]) else rb(64)
        path = "m/44'/133'/%d'/0/%d" % (acct, idx)
        k = Bip32Slip10Secp256k1.FromSeed(sd).DerivePath(path)
        pub = k.PublicKey().RawCompressed().ToBytes()
        spk = b"\x76\xa9\x14" + hash160(pub) + b"\x88\xac"
        amount = rnd.randrange(50000, 10**10)
        txid = rb(32)
        vin.append(ZIn(txid, rnd.randrange(3), 0xfffffffe))
        tin.append(ZTIn(i, amount, spk))
        pb = b"".join(struct.pack("<I", int(p.rstrip("'")) | (0x80000000 if p.endswith("'") else 0)) for p in path.split("/")[1:])
        infos.append((amount, spk, len(path.split("/")) - 1, pb, k.PrivateKey().Raw().ToBytes(), pub))
    outs, texts = [], []
    for j in range(rnd.randrange(1, 4)):
        kind = rnd.choice(["t1", "t3", "ret"] if optype is None else [optype])
        if kind == "t1":
            h = rb(20); spk = b"\x76\xa9\x14" + h + b"\x88\xac"; text = zec_addr(b"\x1c\xb8", h)
        elif kind == "t3":
            h = rb(20); spk = b"\xa9\x14" + h + b"\x87"; text = zec_addr(b"\x1c\xbd", h)
        else:
            spk = b"\x6a\x04" + rb(4); text = "OP_RETURN data"
        v = 0 if kind == "ret" else rnd.randrange(1000, 10**8)
        outs.append(ZOut(v, spk))
        texts.append((text, fmt(v, 8, "ZEC")))
    locktime, expiry = rnd.randrange(0, 500000), rnd.randrange(2000000, 3000000)
    vins = b"".join(bytes(x.prevout) + b"\x00" + struct.pack("<I", x.nSequence) for x in vin)
    vouts = b"".join(bytes(o) for o in outs)
    if ver == 5:
        tx = struct.pack("<II", 0x80000005, 0x26A7270A) + struct.pack("<III", branch, locktime, expiry) + zcs(len(vin)) + vins + zcs(len(outs)) + vouts + (b"\x00\x00\x00" if not shielded else b"\x01\x00\x00")
    else:
        tx = struct.pack("<II", 0x80000004, 0x892F2085) + zcs(len(vin)) + vins + zcs(len(outs)) + vouts + struct.pack("<II", locktime, expiry) + bytes(8) + (b"\x00\x00\x00" if not shielded else b"\x00\x01\x00")
    req = b"ZTXR" + struct.pack("<II", branch, len(tx)) + tx
    for amount, spk, depth, pb, _, _ in infos:
        req += struct.pack("<Q", amount) + zcs(len(spk)) + spk + bytes([depth]) + pb
    # the reference signature hashes and the signatures
    t = ZTx()
    t.vin, t.vout = vin, outs
    t.nVersionGroupId = 0x26A7270A if ver == 5 else 0x892F2085
    t.nConsensusBranchId = branch
    t.nLockTime, t.nExpiryHeight = locktime, expiry
    t.vSpendsSapling, t.vOutputsSapling, t.vActionsOrchard = [], [], []
    t.vJoinSplit, t.vShieldedSpends, t.vShieldedOutputs, t.valueBalance = [], [], [], 0
    t.version_bytes = (lambda: 0x80000005) if ver == 5 else (lambda: 0x80000004)
    t.is_coinbase = lambda: False
    scripts = []
    if all(ours) if ours is not None else True:
        for i, (amount, spk, depth, pb, priv, pub) in enumerate(infos):
            if ver == 5:
                dig = zip_0244.signature_digest(t, tin, 1, tin[i])
            else:
                dig = zip_0243.signature_hash(ZScript(spk), t, i, 1, amount, branch)
            r_, s_, _ = sign_rec(priv, dig)

            def enc(v):
                b = v.to_bytes(32, "big").lstrip(b"\x00")
                if b[0] & 0x80: b = b"\x00" + b
                return b"\x02" + bytes([len(b)]) + b
            body = enc(r_) + enc(s_)
            der = b"\x30" + bytes([len(body)]) + body + b"\x01"
            scripts.append(bytes([len(der)]) + der + bytes([33]) + pub)
    status = None
    if shielded: status = -2
    elif ours is not None and not all(ours): status = -3
    if status is not None:
        out.append("zecerr %s %s %d" % (seed.hex(), req.hex(), status))
        return
    vins_signed = b"".join(bytes(x.prevout) + zcs(len(scripts[i])) + scripts[i] + struct.pack("<I", x.nSequence) for i, x in enumerate(vin))
    if ver == 5:
        signed = struct.pack("<II", 0x80000005, 0x26A7270A) + struct.pack("<III", branch, locktime, expiry) + zcs(len(vin)) + vins_signed + zcs(len(outs)) + vouts + b"\x00\x00\x00"
    else:
        signed = struct.pack("<II", 0x80000004, 0x892F2085) + zcs(len(vin)) + vins_signed + zcs(len(outs)) + vouts + struct.pack("<II", locktime, expiry) + bytes(8) + b"\x00\x00\x00"
    out.append("zecsign %s %s %s" % (seed.hex(), req.hex(), signed.hex()))
    in_sum = sum(a for a, *_ in infos)
    out_sum = sum(o.v for o in outs)
    warn = 0
    if (in_sum - out_sum) * 10 > in_sum: warn |= 4
    if any(tx_[0] == "OP_RETURN data" for tx_ in texts): warn |= 32
    note = "%d input%s, branch id %08x, expiry height %d" % (ninputs, "" if ninputs == 1 else "s", branch, expiry)
    fee = fmt(in_sum - out_sum, 8, "ZEC") if in_sum >= out_sum else "?"
    if in_sum < out_sum: warn |= 2
    fields = ["Zcash transaction (v%d)" % ver, fee, fmt(out_sum, 8, "ZEC"), str(warn), note, "", "", str(len(texts))] + [x for o in texts for x in o]
    out.append("zecview %s %s" % (req.hex(), bsplit(*fields)))


for i in range(16):
    zec_case(rb(64), 5 if i % 2 == 0 else 4, rnd.randrange(1, 4))
zec_case(rb(64), 5, 2, ours=[True, False])
zec_case(rb(64), 4, 2, ours=[False, True])
zec_case(rb(64), 5, 1, shielded=True)
zec_case(rb(64), 4, 1, shielded=True)
