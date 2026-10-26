# The TON and Cardano vectors of tools/gen_txsign_vectors.py (exec'd inside its namespace).
#   tonsign <seed> <boc> <root hash> <sig>      tonview <boc> <title>|<fee>|<total>|<warn>|<n1>|<n2>|<n3>|<nout>|(to|amount)*
#   adasign <node 96 B> <body> <tx hash> <vkey> <sig>     adaview <body> <same fields>
from pytoniq_core import begin_cell, Address, Cell

# ===================== TON =====================
def ton_internal(dest, value, bounce, kind):
    b = begin_cell().store_uint(0, 1).store_bit(1).store_bit(bounce).store_bit(0).store_uint(0, 2)
    b.store_address(Address(dest)).store_coins(value).store_bit(0).store_coins(0).store_coins(0).store_uint(0, 64).store_uint(0, 32).store_bit(0)
    notes, amt_text, to_text, jet = [], fmt(value, 9, "TON"), Address(dest).to_str(is_user_friendly=True, is_bounceable=bool(bounce), is_url_safe=True), False
    if kind == "comment":
        text = "thanks for lunch"
        b.store_bit(0).store_uint(0, 32).store_bytes(text.encode())
        notes.append("Comment: " + text)
    elif kind == "jetton":
        recipient = Address((0, rb(32)))
        units = rnd.randrange(1, 10**15)
        body = begin_cell().store_uint(0x0f8a7ea5, 32).store_uint(rnd.randrange(2**32), 64).store_coins(units).store_address(recipient) \
            .store_address(Address((0, rb(32)))).store_bit(0).store_coins(1).store_bit(0).end_cell()
        b.store_bit(1).store_ref(body)
        to_text = recipient.to_str(is_user_friendly=True, is_bounceable=True, is_url_safe=True)
        amt_text = "%d jetton units" % units
        notes.append("Jetton transfer: the TON of the message pay for the fees")
        jet = True
    elif kind == "otherop":
        b.store_bit(0).store_uint(0x12345678, 32).store_uint(7, 16)
        notes.append("Message body, operation 12345678")
    else:
        b.store_bit(0)
    return b.end_cell(), to_text, amt_text, notes, jet


def ton_case(seed, ver, kinds):
    msgs, outs, notes, warn, total = [], [], [], 0, 0
    for k in kinds:
        value = rnd.choice([10**9, 123456789, rnd.randrange(10**12)])
        bounce = rnd.randrange(2)
        cellm, to_text, amt_text, nn, jet = ton_internal((0, rb(32)), value, bounce, k)
        msgs.append((rnd.choice([3, 3, 1, 128]), cellm))
        outs.append((to_text, amt_text))
        notes += nn
        if k == "otherop" or jet: warn |= 32
        if not jet: total += value
    until, seq = 1700000000 + rnd.randrange(10**6), rnd.randrange(1000)
    if ver == 4:
        sm = begin_cell().store_uint(698983191, 32).store_uint(until, 32).store_uint(seq, 32).store_uint(0, 8)
        for mode, c in msgs:
            sm.store_uint(mode, 8).store_ref(c)
        root = sm.end_cell()
        head = "Wallet v4R2, seqno %d, valid until %d" % (seq, until)
    else:
        prev = begin_cell().end_cell()
        for mode, c in msgs:
            prev = begin_cell().store_ref(prev).store_uint(0x0ec3c86d, 32).store_uint(mode, 8).store_ref(c).end_cell()
        root = begin_cell().store_uint(0x7369676e, 32).store_uint(0x7fffff11, 32).store_uint(until, 32).store_uint(seq, 32).store_bit(1).store_ref(prev).store_bit(0).end_cell()
        head = "Wallet v5R1, seqno %d, valid until %d" % (seq, until)
    boc = root.to_boc(has_idx=bool(rnd.randrange(2)), hash_crc32=bool(rnd.randrange(2)))
    A, sig = ed_pub_sign(seed, root.hash)
    out.append("tonsign %s %s %s %s" % (seed.hex(), boc.hex(), root.hash.hex(), sig.hex()))
    notes = ([head] + notes + ["", "", ""])[:3]
    fields = ["TON wallet message", "", fmt(total, 9, "TON") if total else "", str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("tonview %s %s" % (boc.hex(), bsplit(*fields)))


for i in range(24):
    kinds = [rnd.choice(["plain", "comment", "jetton", "otherop"]) for _ in range(rnd.randrange(1, 4))]
    ton_case(rb(32), 4 if i % 2 == 0 else 5, kinds)
# a cell that is no wallet message: signed blind
for _ in range(2):
    root = begin_cell().store_uint(rnd.randrange(2**32), 32).store_uint(5, 8).end_cell()
    out.append("tonsign %s %s %s %s" % ((s := rb(32)).hex(), root.to_boc().hex(), root.hash.hex(), ed_pub_sign(s, root.hash)[1].hex()))
    out.append("tonview %s %s" % (root.to_boc().hex(), bsplit("TON wallet message", "", "", 16, "Only the hash of the message is signed", "", "", 1, "unknown message format", "")))

# ===================== Cardano =====================
def cbor_head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2**32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)


class Tag:
    def __init__(self, n, x): self.n, self.x = n, x


class CMap(list):
    pass


def cbor(x):
    if isinstance(x, bool): raise ValueError
    if isinstance(x, int): return cbor_head(0, x)
    if isinstance(x, (bytes, bytearray)): return cbor_head(2, len(x)) + bytes(x)
    if isinstance(x, str): return cbor_head(3, len(x.encode())) + x.encode()
    if isinstance(x, CMap): return cbor_head(5, len(x)) + b"".join(cbor(k) + cbor(v) for k, v in x)
    if isinstance(x, list): return cbor_head(4, len(x)) + b"".join(cbor(i) for i in x)
    if isinstance(x, Tag): return cbor_head(6, x.n) + cbor(x.x)
    raise TypeError(x)


def bech32_long(hrp, data):
    CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(v):
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        c = 1
        for x in v:
            b = c >> 25
            c = (c & 0x1ffffff) << 5 ^ x
            for i in range(5):
                c ^= gen[i] if (b >> i) & 1 else 0
        return c
    acc, bitsn, d5 = 0, 0, []
    for byte in data:
        acc = acc << 8 | byte
        bitsn += 8
        while bitsn >= 5:
            bitsn -= 5
            d5.append((acc >> bitsn) & 31)
    if bitsn: d5.append((acc << (5 - bitsn)) & 31)
    hrpx = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(hrpx + d5 + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CH[x] for x in d5 + chk)


def ada_addr_text(a):
    h = a[0] >> 4
    net = a[0] & 15
    want = 57 if h <= 3 else 29 if h in (6, 7, 14, 15) else 0
    if not want or len(a) != want or net > 1:
        return Base58Encoder.Encode(a)
    hrp = ("stake" if net else "stake_test") if h >= 14 else ("addr" if net else "addr_test")
    return bech32_long(hrp, a)


def ada_case(i):
    n_in = rnd.randrange(1, 4)
    inputs = [[rb(32), rnd.randrange(5)] for _ in range(n_in)]
    outs_cbor, outs, total, warn = [], [], 0, 0
    for k in range(rnd.randrange(1, 4)):
        style = rnd.choice(["base", "ent", "testbase", "byron", "base"])
        if style == "base": a = bytes([0x01]) + rb(56)
        elif style == "ent": a = bytes([0x61]) + rb(28)
        elif style == "testbase": a = bytes([0x00]) + rb(56)
        else: a = bytes([0x82, 0xd8, 0x18, 0x58, 0x21, 0x83, 0x58, 0x1c]) + rb(28) + bytes([0xa0, 0x00])
        coin = rnd.choice([1000000, 2500000, rnd.randrange(10**11)])
        ntok = 0
        if rnd.random() < 0.3:
            ma = CMap([(rb(28), CMap([(b"tok1", rnd.randrange(1, 100)), (b"tok2", 5)]))])
            ntok = 2
            val = [coin, ma]
        else:
            val = coin
        o = [a, val] if rnd.random() < 0.6 else CMap([(0, a), (1, val)])
        outs_cbor.append(o)
        amt = fmt(coin, 6, "ADA") + (" + %d tokens" % ntok if ntok else "")
        if ntok: warn |= 32
        outs.append((ada_addr_text(a), amt))
        total += coin
    fee = rnd.choice([170000, 200000, 345678])
    pairs = [(0, Tag(258, inputs) if rnd.random() < 0.3 else inputs), (1, outs_cbor), (2, fee)]
    notes = ["%d input%s, %d output%s" % (n_in, "" if n_in == 1 else "s", len(outs), "" if len(outs) == 1 else "s")]
    if rnd.random() < 0.7:
        ttl = rnd.randrange(10**8, 2 * 10**8)
        pairs.append((3, ttl))
        notes.append("Valid until slot %d" % ttl)
    if i % 5 == 1:
        pairs.append((4, [[0, [0, rb(28)]], [2, [0, rb(28)], rb(28)]]))
        pairs.append((5, CMap([(bytes([0xe1]) + rb(28), 3000000)])))
        notes.append("Withdraws %s of staking rewards" % fmt(3000000, 6, "ADA"))
        notes.append("2 certificates (staking or delegation changes)"); warn |= 32
    if i % 7 == 3:
        pairs.append((9, CMap([(rb(28), CMap([(b"x", 1)]))])))
        notes.append("Mints or burns tokens"); warn |= 48
    pairs.sort(key=lambda kv: kv[0])
    body = cbor(CMap(pairs))
    txh = hashlib.blake2b(body, digest_size=32).digest()
    kl = bytearray(rb(32)); kl[0] &= 248; kl[31] &= 31; kl[31] |= 64
    kr, cc = rb(32), rb(32)
    A, sig = ed_sign_scalar(int.from_bytes(kl, "little"), kr, txh)
    out.append("adasign %s %s %s %s %s" % ((bytes(kl) + kr + cc).hex(), body.hex(), txh.hex(), A.hex(), sig.hex()))
    notes = (notes + ["", "", ""])[:3]
    fields = ["Cardano transaction", fmt(fee, 6, "ADA"), fmt(total, 6, "ADA"), str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("adaview %s %s" % (body.hex(), bsplit(*fields)))


def ed_sign_scalar(a, prefix, msg):
    A = (EG * a).to_bytes()
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % EL
    R = (EG * r).to_bytes()
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % EL
    sig = R + ((r + k * a) % EL).to_bytes(32, "little")
    assert VerifyingKey.from_string(A, curve=Ed25519).verify(sig, msg)
    return A, sig


for i in range(26):
    ada_case(i)
