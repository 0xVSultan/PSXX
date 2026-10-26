# The Solana, Stellar, NEAR and Polkadot vectors of tools/gen_txsign_vectors.py (exec'd inside its namespace).
#   solsign  <seed> <message> <sig> <tx>          solview  <message> <title>|<fee>|<total>|<warn>|<n1>|<n2>|<n3>|<nout>|(to|amount)*
#   xlmsign  <seed> <passphrase hex> <tx> <sig> <hint>   xlmview  <tx> <same fields>
#   nearsign <seed> <tx> <sig> <signed tx>        nearview <tx> <same fields>
#   dotsign  <scheme 0|1> <key> <payload> <sig65>  dotview <chain 0|1> <payload> <title>|<to>|<amount>|<total>|<warn>|<n1>|<n2>|<n3>
import base64
from ecdsa import Ed25519, VerifyingKey
from bip_utils import Base58Decoder

EG = Ed25519.generator
EL = EG.order()


def ed_pub_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248; a[31] &= 127; a[31] |= 64
    ai = int.from_bytes(a, "little")
    A = (EG * ai).to_bytes()
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % EL
    R = (EG * r).to_bytes()
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % EL
    sig = R + ((r + k * ai) % EL).to_bytes(32, "little")
    assert VerifyingKey.from_string(A, curve=Ed25519).verify(sig, msg)
    return A, sig


def B58(b): return __import__("bip_utils").Base58Encoder.Encode(b)


def bsplit(*fields): return "|".join(tl(str(x)) for x in fields)


# ===================== Solana =====================
SYS = bytes(32)
TOKEN = Base58Decoder.Decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
BUDGET = Base58Decoder.Decode("ComputeBudget111111111111111111111111111111")
MEMO = Base58Decoder.Decode("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
ATA = Base58Decoder.Decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")


def cu16(n):
    o = b""
    while True:
        b = n & 0x7f
        n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])


def sol_case(seed, kind):
    pub, _ = ed_pub_sign(seed, b"")
    dest, mint, other = rb(32), rb(32), rb(32)
    instrs, notes, outs, warn = [], [], [], 0
    sent = 0
    accounts = [pub, dest, mint, SYS, TOKEN, BUDGET, MEMO, ATA, other]
    ix = {k: i for i, k in enumerate(["pub", "dest", "mint", "sys", "token", "budget", "memo", "ata", "other"])}
    units, price = None, None
    lamports = rnd.choice([1, 5000, 10**9, rnd.randrange(10**12)])
    if kind in ("transfer", "priority", "v0"):
        instrs.append((ix["sys"], [0, 1], (2).to_bytes(4, "little") + lamports.to_bytes(8, "little")))
        outs.append((B58(dest), fmt(lamports, 9, "SOL"))); sent += lamports
    if kind == "priority":
        units, price = rnd.choice([50000, 200000]), rnd.choice([1, 1000, 123456])
        instrs.insert(0, (ix["budget"], [], b"\x02" + units.to_bytes(4, "little")))
        instrs.insert(0, (ix["budget"], [], b"\x03" + price.to_bytes(8, "little")))
    if kind == "spl":
        amt = rnd.randrange(1, 10**9)
        instrs.append((ix["token"], [2, 1, 0], b"\x03" + amt.to_bytes(8, "little")))
        outs.append((B58(dest), "%d token units" % amt)); warn |= 32
    if kind == "splc":
        amt, dec = rnd.randrange(1, 10**9), rnd.choice([0, 6, 9])
        instrs.append((ix["token"], [2, 8, 1, 0], b"\x0c" + amt.to_bytes(8, "little") + bytes([dec])))
        outs.append((B58(dest), fmt(amt, dec, "") + " token")); warn |= 32
        notes.append("Token mint " + B58(accounts[8]))
    if kind == "memo":
        memo = b"hello memo"
        instrs.append((ix["sys"], [0, 1], (2).to_bytes(4, "little") + lamports.to_bytes(8, "little")))
        outs.append((B58(dest), fmt(lamports, 9, "SOL"))); sent += lamports
        instrs.append((ix["memo"], [], memo))
        notes.append("Memo: " + memo.decode())
    if kind == "unknown":
        data = rb(rnd.choice([4, 40]))
        instrs.append((ix["other"], [0, 1], data))
        outs.append(("program " + B58(other)[:30], "instruction, %d bytes of data" % len(data))); warn |= 48
    if kind == "ata":
        instrs.append((ix["ata"], [0, 1], b""))
        notes.append("Creates a token account")
    if kind == "twosigners":
        accounts = [other, pub, dest, SYS]
        instrs.append((3, [1, 2], (2).to_bytes(4, "little") + lamports.to_bytes(8, "little")))
        outs.append((B58(dest), fmt(lamports, 9, "SOL"))); sent += lamports
    nsig = 2 if kind == "twosigners" else 1
    v0 = kind == "v0"
    msg = (b"\x80" if v0 else b"") + bytes([nsig, 0, 5]) + cu16(len(accounts)) + b"".join(accounts) + rb(32) + cu16(len(instrs))
    for p, a, d in instrs:
        msg += bytes([p]) + cu16(len(a)) + bytes(a) + cu16(len(d)) + d
    if v0:
        msg += cu16(1) + rb(32) + cu16(1) + b"\x00" + cu16(1) + b"\x01"
    A, sig = ed_pub_sign(seed, msg)
    slot = [i for i, k in enumerate(accounts) if k == pub][0]
    sigs = [bytes(64)] * nsig
    sigs[slot] = sig
    tx = bytes([nsig]) + b"".join(sigs) + msg
    out.append("solsign %s %s %s %s" % (seed.hex(), msg.hex(), sig.hex(), tx.hex()))
    fee = 5000 * nsig
    if price:
        fee += (units * price + 999999) // 1000000
        notes.append("Priority fee: %d micro-lamports per unit, %d units" % (price, units))
    if v0: notes.append("Version 0 message: some accounts come from lookup tables")
    if not outs: outs.append(("no transfer", ""))
    notes = (notes + ["", "", ""])[:3]
    fields = ["Solana transaction", fmt(fee, 9, "SOL"), fmt(sent, 9, "SOL") if sent else "", str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("solview %s %s" % (msg.hex(), bsplit(*fields)))


for i in range(22):
    sol_case(rb(32), ["transfer", "priority", "spl", "splc", "memo", "unknown", "ata", "twosigners", "v0", "transfer", "priority"][i % 11])

# ===================== Stellar =====================
def x32(n): return struct.pack(">I", n)
def x64(n): return struct.pack(">Q", n)
def xop(b): return b + bytes((4 - len(b) % 4) % 4)


def crc16x(b):
    crc = 0
    for x in b:
        crc ^= x << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def strkey(pub):
    p = bytes([6 << 3]) + pub
    p += struct.pack("<H", crc16x(p))
    return base64.b32encode(p).decode().rstrip("=")


def x_acct(pub, muxed=False): return x32(0) + pub


def x_asset(code=None, issuer=None):
    if code is None: return x32(0)
    c = code.encode()
    if len(c) <= 4: return x32(1) + c.ljust(4, b"\x00") + x32(0) + issuer
    return x32(2) + c.ljust(12, b"\x00") + x32(0) + issuer


def xlm_amount(stroops): return fmt(stroops, 7, "")


def xlm_case(seed, kind):
    pub, _ = ed_pub_sign(seed, b"")
    src = rb(32) if kind == "other_src" else pub
    dest, issuer = rb(32), rb(32)
    fee = rnd.choice([100, 200, 10000])
    seq = rnd.randrange(10**12)
    cond = rnd.choice([0, 1])
    memo = rnd.choice([0, 1, 2, 3])
    tx = x32(0) + src + x32(fee) + x64(seq)
    tx += x32(0) if cond == 0 else x32(1) + x64(0) + x64(1900000000)
    notes = []
    if memo == 0: tx += x32(0)
    elif memo == 1: tx += x32(1) + x32(5) + xop(b"hello"); notes.append("Memo: hello")
    elif memo == 2: tx += x32(2) + x64(123456789); notes.append("Memo id: 123456789")
    else: tx += x32(3) + rb(32); notes.append("Memo: a 32 byte hash")
    ops, outs, warn, total, only = [], [], 0, 0, True
    amt = rnd.choice([1, 10000000, rnd.randrange(10**12)])
    if kind in ("payment", "other_src"):
        ops.append(x32(0) + x32(1) + x_acct(dest) + x_asset() + x64(amt))
        outs.append((strkey(dest), xlm_amount(amt) + " XLM")); total += amt
    elif kind == "payment_asset":
        ops.append(x32(0) + x32(1) + x_acct(dest) + x_asset("USDC", issuer) + x64(amt))
        outs.append((strkey(dest), xlm_amount(amt) + " USDC (issuer %s)" % strkey(issuer))); only = False
    elif kind == "create":
        ops.append(x32(0) + x32(0) + x_acct(dest) + x64(amt))
        outs.append(("create account " + strkey(dest), xlm_amount(amt) + " XLM")); total += amt
    elif kind == "trust":
        ops.append(x32(0) + x32(6) + x_asset("USDC", issuer) + x64(2**63 - 1))
        outs.append(("trust USDC", "issuer " + strkey(issuer)))
    elif kind == "merge":
        ops.append(x32(0) + x32(8) + x_acct(dest))
        outs.append(("merge ALL funds into " + strkey(dest), "everything"))
    elif kind == "multi":
        ops.append(x32(0) + x32(1) + x_acct(dest) + x_asset() + x64(amt))
        outs.append((strkey(dest), xlm_amount(amt) + " XLM")); total += amt
        ops.append(x32(1) + x_acct(rb(32)) + x32(1) + x_acct(dest) + x_asset() + x64(7))
        outs.append((strkey(dest), xlm_amount(7) + " XLM")); total += 7
    elif kind == "unsupported":
        ops.append(x32(0) + x32(5) + bytes(36))
        outs.append(("Operation type 5", "cannot be shown")); warn |= 48
    # the multi-op test with an op source: rebuild to know the key
    if kind == "multi":
        osrc = rb(32)
        ops[1] = x32(1) + x_acct(osrc) + x32(1) + x_acct(dest) + x_asset() + x64(7)
        notes.append("Op 2 source account " + strkey(osrc))
    tx += x32(len(ops)) + b"".join(ops) + x32(0)
    passphrase = rnd.choice(["Public Global Stellar Network ; September 2015", "Test SDF Network ; September 2015"])
    h = sha256(sha256(passphrase.encode()) + x32(2) + tx)
    A, sig = ed_pub_sign(seed, h)
    out.append("xlmsign %s %s %s %s %s" % (seed.hex(), passphrase.encode().hex(), tx.hex(), sig.hex(), A[28:].hex()))
    notes.append("Source %s, sequence %d" % (strkey(src), seq))
    notes = (notes + ["", "", ""])[:3]
    fields = ["Stellar transaction", fmt(fee, 7, "XLM"), (fmt(total, 7, "XLM") if total and only else ""), str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("xlmview %s %s" % (tx.hex(), bsplit(*fields)))


for i in range(24):
    xlm_case(rb(32), ["payment", "payment_asset", "create", "trust", "merge", "multi", "unsupported", "other_src"][i % 8])

# ===================== NEAR =====================
def bs(b): return struct.pack("<I", len(b)) + b
def bstr(s): return bs(s.encode())


def near_case(seed, kind):
    pub, _ = ed_pub_sign(seed, b"")
    signer = pub.hex()
    recv = rnd.choice(["alice.near", "bob.testnet", rb(32).hex()])
    nonce = rnd.randrange(10**12)
    tx = bstr(signer) + b"\x00" + (pub if kind != "wrongkey" else rb(32)) + struct.pack("<Q", nonce) + bstr(recv) + rb(32)
    dep = rnd.choice([0, 10**24, rnd.randrange(10**27)])
    notes, warn, outs, total = [], 0, [], ""
    if kind == "transfer" or kind == "wrongkey":
        tx += struct.pack("<I", 1) + b"\x03" + dep.to_bytes(16, "little")
        outs.append((recv, fmt(dep, 24, "NEAR"))); total = fmt(dep, 24, "NEAR")
    elif kind == "call":
        args = rb(rnd.choice([0, 30, 200]))
        gas = rnd.choice([30 * 10**12, 300 * 10**12])
        tx += struct.pack("<I", 1) + b"\x02" + bstr("ft_transfer") + bs(args) + struct.pack("<Q", gas) + dep.to_bytes(16, "little")
        outs.append((recv, fmt(dep, 24, "NEAR")))
        notes.append("Call ft_transfer(), %d bytes of arguments, %d gas" % (len(args), gas)); warn |= 32
    elif kind == "fullkey":
        tx += struct.pack("<I", 1) + b"\x05" + b"\x00" + rb(32) + struct.pack("<Q", 0) + b"\x01"
        outs.append(("ADD A KEY WITH FULL ACCESS", "gives complete control of the account")); warn |= 48
    elif kind == "fckey":
        tx += struct.pack("<I", 1) + b"\x05" + b"\x00" + rb(32) + struct.pack("<Q", 0) + b"\x00" + b"\x01" + (10**24).to_bytes(16, "little") + bstr("c.near") + struct.pack("<I", 2) + bstr("a") + bstr("bb")
        outs.append(("add a function call key", "limited access")); warn |= 32
    elif kind == "delacct":
        tx += struct.pack("<I", 1) + b"\x07" + bstr("heir.near")
        outs.append(("DELETE ACCOUNT, funds go to heir.near", "everything")); warn |= 32
    elif kind == "multi":
        tx += struct.pack("<I", 2) + b"\x00" + b"\x03" + dep.to_bytes(16, "little")
        outs.append((recv, "create account")); outs.append((recv, fmt(dep, 24, "NEAR"))); total = fmt(dep, 24, "NEAR")
    h = sha256(tx)
    if kind == "wrongkey":
        out.append("nearbad %s %s" % (seed.hex(), tx.hex()))
    else:
        A, sig = ed_pub_sign(seed, h)
        out.append("nearsign %s %s %s %s" % (seed.hex(), tx.hex(), sig.hex(), (tx + b"\x00" + sig).hex()))
    notes.append("Signer %s, nonce %d" % (signer, nonce))
    notes.append("Receiver " + recv)
    notes = (notes + ["", "", ""])[:3]
    fields = ["NEAR transaction", "", total, str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("nearview %s %s" % (tx.hex(), bsplit(*fields)))


for i in range(21):
    near_case(rb(32), ["transfer", "call", "fullkey", "fckey", "delacct", "multi", "wrongkey"][i % 7])

# ===================== Polkadot / Kusama =====================
try:
    import sr25519 as _sr
except ImportError:
    _sr = None


def compact_enc(n):
    if n < 1 << 6: return bytes([n << 2])
    if n < 1 << 14: return struct.pack("<H", n << 2 | 1)
    if n < 1 << 30: return struct.pack("<I", n << 2 | 2)
    b = n.to_bytes((n.bit_length() + 7) // 8, "little")
    return bytes([((len(b) - 4) << 2) | 3]) + b


def ss58(prefix, pub):
    if prefix < 64: pre = bytes([prefix])
    body = pre + pub
    chk = hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
    return Base58Encoder.Encode(body + chk)


def dot_case(i):
    chain = i % 2
    kind = ["transfer", "transfer", "other", "long", "keepalive"][i % 5]
    pallet = 4 if chain else 5
    dest = rb(32)
    value = rnd.choice([10**10, 123456789012, rnd.randrange(10**18)])
    extra = rb(rnd.choice([10, 40]))
    if kind in ("transfer", "keepalive"):
        payload = bytes([pallet, 3 if kind == "keepalive" else 0, 0]) + dest + compact_enc(value) + extra
    elif kind == "other":
        payload = bytes([7, 2]) + rb(20)
    else:
        payload = bytes([pallet, 0, 0]) + dest + compact_enc(value) + rb(300)
    seed = rb(32)
    msg = hashlib.blake2b(payload, digest_size=32).digest() if len(payload) > 256 else payload
    A, sig = ed_pub_sign(seed, msg)
    out.append("dotsign 0 %s %s %s" % (seed.hex(), payload.hex(), (b"\x00" + sig).hex()))
    if _sr and os.path.exists(os.path.join(HERE, "..", "build", "host", "sign_tool.exe")):
        mini = rb(32)
        s2 = bytes.fromhex(subprocess.check_output([os.path.join(HERE, "..", "build", "host", "sign_tool.exe"), "sr25519", mini.hex(), msg.hex()]).decode().strip())
        assert _sr.verify(s2, msg, _sr.pair_from_seed(mini)[0])
        out.append("dotsign 1 %s %s %s" % (mini.hex(), payload.hex(), (b"\x01" + s2).hex()))
    if kind in ("transfer", "keepalive", "long"):
        dec, sym, pre = (12, "KSM", 2) if chain else (10, "DOT", 0)
        to, amt = ss58(pre, dest), fmt(value, dec, sym)
        notes = ["Balances call %d.%d, decoded from the call indices of the current runtime" % (payload[0], payload[1])]
        warn = 8
        total = amt
    else:
        to, amt, total, warn = "call %02x%02x" % (payload[0], payload[1]), "%d bytes of payload" % len(payload), "", 48
        notes = ["The call cannot be decoded without the metadata of the runtime"]
    if len(payload) > 256: notes.append("More than 256 bytes: its BLAKE2b-256 hash is signed")
    notes = (notes + ["", "", ""])[:3]
    title = "%s extrinsic" % ("Kusama" if chain else "Polkadot")
    out.append("dotview %d %s %s" % (chain, payload.hex(), bsplit(title, to, amt, total, warn, *notes)))


for i in range(20):
    dot_case(i)
