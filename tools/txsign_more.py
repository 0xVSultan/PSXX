# The Tron, XRP, Cosmos and Nostr vectors of tools/gen_txsign_vectors.py (run inside its namespace: exec'd before the file is written).

# ================= Tron =================
from bip_utils import Base58Encoder, Base58Alphabets, Bech32Encoder
import json


def pbv(n):
    o = b""
    while n >= 0x80:
        o += bytes([(n & 0x7f) | 0x80]); n >>= 7
    return o + bytes([n])


def pb_b(f, b): return pbv(f << 3 | 2) + pbv(len(b)) + b
def pb_i(f, n): return pbv(f << 3) + pbv(n)


def tron_addr(a21): return Base58Encoder.CheckEncode(a21)


def tron_case(priv, kind):
    owner = b"\x41" + rb(20)
    to = b"\x41" + rb(20)
    amount = rnd.choice([1, 1000000, rnd.randrange(10**12)])
    fee_limit = rnd.choice([0, 10**8, 150 * 10**6])
    notes = []
    warn = 0
    if kind == "trx":
        ctype, url = 1, "protocol.TransferContract"
        param = pb_b(1, owner) + pb_b(2, to) + pb_i(3, amount)
        toaddr, amt, total = tron_addr(to), fmt(amount, 6, "TRX"), fmt(amount, 6, "TRX")
    elif kind == "trc10":
        ctype, url = 2, "protocol.TransferAssetContract"
        name = b"1002000"
        param = pb_b(1, name) + pb_b(2, owner) + pb_b(3, to) + pb_i(4, amount)
        toaddr, amt, total = tron_addr(to), "%d units of TRC-10 token %s" % (amount, name.decode()), ""
    elif kind == "trc20":
        ctype, url = 31, "protocol.TriggerSmartContract"
        dest = rb(20)
        tokamt = rnd.randrange(2**100)
        contract = b"\x41" + rb(20)
        data = bytes.fromhex("a9059cbb") + bytes(12) + dest + tokamt.to_bytes(32, "big")
        param = pb_b(1, owner) + pb_b(2, contract) + pb_b(4, data)
        toaddr, amt, total = tron_addr(b"\x41" + dest), "%d token units" % tokamt, ""
        notes.append("TRC-20 transfer, token contract " + tron_addr(contract)); warn |= 32
    elif kind == "call":
        ctype, url = 31, "protocol.TriggerSmartContract"
        contract = b"\x41" + rb(20)
        data = rb(rnd.choice([4, 36, 100]))
        cv = rnd.choice([0, 5 * 10**6])
        param = pb_b(1, owner) + pb_b(2, contract) + (pb_i(3, cv) if cv else b"") + pb_b(4, data)
        toaddr, amt, total = "contract " + tron_addr(contract), fmt(cv, 6, "TRX"), ""
        notes.append("Contract call, %d bytes of data" % len(data)); warn |= 32 | 16
    else:
        ctype, url = 12, "protocol.AccountUpdateContract"
        param = pb_b(1, owner) + pb_i(2, amount)
        toaddr, amt, total = "Contract type 12", "", ""
        notes.append("Cannot be shown: only the hash is signed"); warn |= 16
    contract_msg = pb_i(1, ctype) + pb_b(2, pb_b(1, ("type.googleapis.com/" + url).encode()) + pb_b(2, param))
    raw = pb_b(1, rb(2)) + pb_i(3, rnd.randrange(10**8)) + pb_b(4, rb(8)) + pb_i(8, 1700000000000 + rnd.randrange(10**9)) \
        + pb_b(11, contract_msg) + pb_i(14, 1700000000000 + rnd.randrange(10**9)) + (pb_i(18, fee_limit) if fee_limit else b"")
    txid = sha256(raw)
    r, sv, rec = sign_rec(priv, txid)
    out.append("tronraw %s %s %s %s" % (priv.hex(), raw.hex(), (r.to_bytes(32, "big") + sv.to_bytes(32, "big") + bytes([rec])).hex(), txid.hex()))
    fee = ""
    if fee_limit:
        fee = fmt(fee_limit, 6, "TRX")
        notes.append("Fee limit " + fee)
    notes = (notes + ["", "", ""])[:3]
    out.append("tronview %s %s" % (raw.hex(), "|".join(tl(x) for x in ["Tron transaction", toaddr, amt, fee, total, str(warn)] + notes)))


for i in range(20):
    tron_case(rb(32), ["trx", "trc10", "trc20", "call", "other"][i % 5])


# Stake 2.0 and the account permissions (own random source: the other vectors stay as they were)
def tron_special_cases():
    q = random.Random(0x54524F4E)
    def rbq(n): return bytes(q.getrandbits(8) for _ in range(n))
    def finish(priv, ctype, url, param, toaddr, amt, notes, warn, extra_outs=()):
        fee_limit = q.choice([0, 10**8])
        contract_msg = pb_i(1, ctype) + pb_b(2, pb_b(1, ("type.googleapis.com/" + url).encode()) + pb_b(2, param))
        raw = pb_b(1, rbq(2)) + pb_i(3, q.randrange(10**8)) + pb_b(4, rbq(8)) + pb_i(8, 1700000000000 + q.randrange(10**9)) \
            + pb_b(11, contract_msg) + pb_i(14, 1700000000000 + q.randrange(10**9)) + (pb_i(18, fee_limit) if fee_limit else b"")
        txid = sha256(raw)
        r, sv, rec = sign_rec(priv, txid)
        out.append("tronraw %s %s %s %s" % (priv.hex(), raw.hex(), (r.to_bytes(32, "big") + sv.to_bytes(32, "big") + bytes([rec])).hex(), txid.hex()))
        fee = ""
        notes = list(notes)
        if fee_limit:
            fee = fmt(fee_limit, 6, "TRX")
            notes.append("Fee limit " + fee)
        notes = (notes + ["", "", ""])[:3]
        out.append("tronview %s %s" % (raw.hex(), "|".join(tl(x) for x in ["Tron transaction", toaddr, amt, fee, "", str(warn)] + notes)))
        if extra_outs:
            out.append("tronouts %s %s" % (raw.hex(), " ".join("%s|%s" % (tl(a), tl(b)) for a, b in extra_outs)))
    for i in range(16):
        priv, owner, rcv = rbq(32), b"\x41" + rbq(20), b"\x41" + rbq(20)
        bal = q.choice([1, 1000000, 123456789])
        res = i % 2
        name = "ENERGY" if res else "BANDWIDTH"
        kind = i % 8
        if kind in (0, 1):                                   # freeze / unfreeze V2
            ctype, url = (54, "protocol.FreezeBalanceV2Contract") if kind == 0 else (55, "protocol.UnfreezeBalanceV2Contract")
            param = pb_b(1, owner) + pb_i(2 if True else 0, bal) + (pb_i(3, res) if res else b"")
            finish(priv, ctype, url, param, ("Stake for " if kind == 0 else "Unstake from ") + name, fmt(bal, 6, "TRX"), [], 0)
        elif kind == 2:
            finish(priv, 56, "protocol.WithdrawExpireUnfreezeContract", pb_b(1, owner), "Withdraw the unstaked TRX", "", [], 0)
        elif kind in (3, 4, 5):                              # delegate (locked or not) / take back
            lock = kind == 4
            period = q.choice([28800, 864000])
            param = pb_b(1, owner) + (pb_i(2, res) if res else b"") + pb_i(3, bal) + pb_b(4, rcv) + (pb_i(5, 1) + pb_i(6, period) if lock else b"")
            if kind == 5:
                finish(priv, 58, "protocol.UnDelegateResourceContract", pb_b(1, owner) + (pb_i(2, res) if res else b"") + pb_i(3, bal) + pb_b(4, rcv),
                       "Take back %s from %s" % (name, tron_addr(rcv)), fmt(bal, 6, "TRX"), [], 0)
            else:
                finish(priv, 57, "protocol.DelegateResourceContract", param, "Delegate %s to %s" % (name, tron_addr(rcv)), fmt(bal, 6, "TRX"),
                       ["Locked for %d blocks" % period if lock else "Not locked"], 0)
        else:                                                # AccountPermissionUpdate: owner, one or two actives
            def key(addr, w): return pb_b(1, addr) + pb_i(2, w)
            def perm(ptype, pid, pname, thr, keys):
                return (pb_i(1, ptype) if ptype else b"") + (pb_i(2, pid) if pid else b"") + pb_b(3, pname) + pb_i(4, thr) + b"".join(pb_b(7, k) for k in keys)
            k1, k2, k3 = b"\x41" + rbq(20), b"\x41" + rbq(20), b"\x41" + rbq(20)
            owner_perm = perm(0, 0, b"owner", 2, [key(k1, 1), key(k2, 1)])
            act = perm(2, 2, b"active0", 1, [key(k3, 1)])
            param = pb_b(1, owner) + pb_b(2, owner_perm) + pb_b(4, act)
            outs = [("Owner key " + tron_addr(k1), "weight 1, threshold 2"), ("Owner key " + tron_addr(k2), "weight 1, threshold 2"), ("Active key " + tron_addr(k3), "weight 1, threshold 1")]
            finish(priv, 46, "protocol.AccountPermissionUpdateContract", param, "Changes who can sign for this account", "3 keys in 2 permissions",
                   ["Owner and active keys can move all the funds"], 512, outs)
tron_special_cases()

# ================= XRP =================
RIPPLE = Base58Alphabets.RIPPLE


def xrp_addr(a20): return Base58Encoder.CheckEncode(b"\x00" + a20, RIPPLE)
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()


def vl(b):
    assert len(b) <= 192
    return bytes([len(b)]) + b


def iou(mant, exp, cur, issuer, neg=False):
    w = 0x8000000000000000 | ((0 if neg else 1) << 62) | ((exp + 97) << 54) | mant
    return w.to_bytes(8, "big") + bytes(12) + cur.encode() + bytes(5) + issuer


def iou_text(mant, exp, cur, issuer, neg=False):
    digits = str(mant)
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]; exp += 1
    if exp >= 0: val = digits + "0" * exp
    elif -exp >= len(digits): val = "0." + "0" * (-exp - len(digits)) + digits
    else: val = digits[:len(digits) + exp] + "." + digits[len(digits) + exp:]
    return "%s%s %s (issuer %s)" % ("-" if neg else "", val, cur, xrp_addr(issuer))


def xrp_case(priv, kind):
    pub = G * int.from_bytes(priv, "big")
    pubc = bytes([2 + (pub.y() & 1)]) + pub.x().to_bytes(32, "big")
    acct = hash160(pubc)
    dest = rb(20)
    seq = rnd.randrange(1, 10**6)
    fee = rnd.choice([10, 12, 5000])
    flags = rnd.choice([0, 0x80000000])
    tag = rnd.choice([None, 1, 123456789])
    lls = rnd.choice([None, 82000000])
    notes = []
    amt_drops = rnd.choice([1, 1000000, rnd.randrange(10**11)])
    blob = b"\x12" + (0 if kind != "other" else 7).to_bytes(2, "big")
    blob += b"\x22" + flags.to_bytes(4, "big") + b"\x24" + seq.to_bytes(4, "big")
    if tag is not None: blob += b"\x2e" + tag.to_bytes(4, "big")
    if lls: blob += b"\x20\x1b" + lls.to_bytes(4, "big")
    warn = 0
    if kind == "iou":
        mant, exp = rnd.choice([(1000000000000000, -15), (1234567890123456, -10), (5000000000000000, 2), (1000000000000000, -20)])
        issuer = rb(20)
        blob += b"\x61" + iou(mant, exp, "USD", issuer)
        amt, total = iou_text(mant, exp, "USD", issuer), ""
    else:
        blob += b"\x61" + (0x4000000000000000 | amt_drops).to_bytes(8, "big")
        amt, total = fmt(amt_drops, 6, "XRP"), fmt(amt_drops, 6, "XRP")
    blob += b"\x68" + (0x4000000000000000 | fee).to_bytes(8, "big") + b"\x73" + vl(pubc) + b"\x81" + vl(acct) + b"\x83" + vl(dest)
    if kind == "memo":
        blob += b"\xf9" + b"\xea" + b"\x7d" + vl(b"hello") + b"\xe1" + b"\xf1"
    toaddr = xrp_addr(dest)
    if kind == "other":
        toaddr, amt, total = "Transaction type 7", "", ""; warn |= 16
        notes.append("Only a payment can be shown: the rest is signed blind")
    notes.append("Sequence %d%s" % (seq, ", flags set" if flags else ""))
    if tag is not None: notes.append("Destination tag %d" % tag)
    digest = hashlib.sha512(b"STX\x00" + blob).digest()[:32]
    r, sv, rec = sign_rec(priv, digest)

    def enc(v):
        b = v.to_bytes(32, "big").lstrip(b"\x00")
        if b[0] & 0x80: b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(sv)
    der = b"\x30" + bytes([len(body)]) + body
    pos = blob.index(b"\x81" + vl(acct))
    signed = blob[:pos] + b"\x74" + vl(der) + blob[pos:]
    out.append("xrptx %s %s %s" % (priv.hex(), blob.hex(), signed.hex()))
    notes = (notes + ["", "", ""])[:3]
    out.append("xrpview %s %s" % (blob.hex(), "|".join(tl(x) for x in ["XRP transaction", toaddr, amt, fmt(fee, 6, "XRP"), total, str(warn)] + notes)))


for i in range(20):
    xrp_case(rb(32), ["xrp", "iou", "memo", "other"][i % 4])

# ================= Cosmos =================
def cosmos_addr(hrp, a20): return Bech32Encoder.Encode(hrp, a20)


def coin(denom, amount): return pb_b(1, denom.encode()) + pb_b(2, str(amount).encode())


def coin_text(denom, amount):
    if denom.startswith("u") and denom[1:].isalpha() and denom.islower():
        return fmt(amount, 6, denom[1:].upper())
    return "%d %s" % (amount, denom)


def cos_case(priv, kind):
    memo = rnd.choice(["", "memo text", "thanks"])
    chain = rnd.choice(["cosmoshub-4", "osmosis-1", "theta-testnet-001"])
    hrp = {"cosmoshub-4": "cosmos", "osmosis-1": "osmo"}.get(chain, "cosmos")
    msgs, outs, warn = [], [], 0
    for _ in range(1 if kind != "multi" else 3):
        if kind == "other":
            url = "/cosmos.staking.v1beta1.MsgDelegate"
            val = pb_b(1, b"cosmos1abc") + pb_b(2, b"cosmosvaloper1abc") + pb_b(3, coin("uatom", 1000))
            msgs.append(pb_b(1, pb_b(1, url.encode()) + pb_b(2, val)))
            outs.append((url, "")); warn |= 16 | 32
        else:
            frm, to = cosmos_addr(hrp, rb(20)), cosmos_addr(hrp, rb(20))
            coins = [(rnd.choice(["uatom", "uosmo", "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2"]), rnd.randrange(1, 10**10))]
            if kind == "multi" and rnd.random() < 0.5:
                coins.append(("uion", rnd.randrange(1, 1000)))
            val = pb_b(1, frm.encode()) + pb_b(2, to.encode()) + b"".join(pb_b(3, coin(d, a)) for d, a in coins)
            msgs.append(pb_b(1, pb_b(1, b"/cosmos.bank.v1beta1.MsgSend") + pb_b(2, val)))
            outs.append((to, " + ".join(coin_text(d, a) for d, a in coins)))
    body = b"".join(msgs) + (pb_b(2, memo.encode()) if memo else b"")
    fee_coin = ("uatom" if hrp == "cosmos" else "uosmo", rnd.randrange(1000, 100000))
    gas = rnd.choice([100000, 200000, 350000])
    signer = pb_b(1, pb_b(1, b"/cosmos.crypto.secp256k1.PubKey") + pb_b(2, pb_b(1, rb(33)))) + pb_b(2, pb_b(1, pb_b(1, b""))) + pb_i(3, rnd.randrange(100))
    auth = pb_b(1, signer) + pb_b(2, pb_b(1, coin(*fee_coin)) + pb_i(2, gas))
    acct = rnd.randrange(10**6)
    doc = pb_b(1, body) + pb_b(2, auth) + pb_b(3, chain.encode()) + pb_i(4, acct)
    r, sv, rec = sign_rec(priv, sha256(doc))
    sig = r.to_bytes(32, "big") + sv.to_bytes(32, "big")
    txraw = pb_b(1, body) + pb_b(2, auth) + pb_b(3, sig)
    out.append("cossign %s %s %s %s" % (priv.hex(), doc.hex(), sig.hex(), txraw.hex()))
    notes = ["Chain %s, account number %d" % (chain, acct)] + (["Memo: " + memo] if memo else []) + ["Gas limit %d" % gas]
    notes = (notes + ["", "", ""])[:3]
    fields = ["Cosmos transaction", coin_text(*fee_coin), str(warn)] + notes + [str(len(outs))] + [x for o in outs for x in o]
    out.append("cosview %s %s" % (doc.hex(), "|".join(tl(x) for x in fields)))


for i in range(18):
    cos_case(rb(32), ["send", "send", "multi", "other"][i % 4])

# ================= Nostr =================
def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)


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


KINDS = {0: "Nostr profile (kind 0)", 1: "Nostr note (kind 1)", 3: "Nostr contact list (kind 3)", 4: "Nostr direct message (kind 4)",
         5: "Nostr deletion (kind 5)", 6: "Nostr repost (kind 6)", 7: "Nostr reaction (kind 7)", 22242: "Nostr relay login (kind 22242)"}
TEXTS = ["hello world", "line one\nline two", 'say "hi" and \\ back', "tab\there", "café über", "emoji \U0001F600 ok", "中文 text", "", "a/b"]


def _b32e(hrp, raw):
    cs = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    d5, acc, bits = [], 0, 0
    for byte in raw:
        acc = (acc << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; d5.append((acc >> bits) & 31)
        acc &= (1 << bits) - 1
    if bits: d5.append((acc << (5 - bits)) & 31)
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + d5 + [0] * 6:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    chk ^= 1
    return hrp + "1" + "".join(cs[v] for v in d5) + "".join(cs[(chk >> (5 * (5 - i))) & 31] for i in range(6))


def nostr_case(priv, i):
    kind = rnd.choice([0, 1, 1, 3, 4, 5, 7, 22242, 30023])
    created = 1700000000 + rnd.randrange(10**7)
    content = TEXTS[i % len(TEXTS)]
    tags = [] if i % 3 == 0 else [["e", rb(32).hex()], ["p", rb(32).hex(), "wss://relay.example.com"]]
    if i % 5 == 0: tags.append(["t", "café"])
    pk = (G * int.from_bytes(priv, "big")).x().to_bytes(32, "big").hex()
    ser = json.dumps([0, pk, created, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = sha256(ser.encode("utf-8"))
    sig = schnorr_sign(priv, eid)
    tags_c = json.dumps(tags, separators=(",", ":"), ensure_ascii=False)
    content_c = json.dumps(content, ensure_ascii=False)[1:-1]
    event = '{"id":"%s","pubkey":"%s","created_at":%d,"kind":%d,"tags":%s,"content":"%s","sig":"%s"}' % (eid.hex(), pk, created, kind, tags_c, content_c, sig.hex())
    style = i % 3
    req = {"kind": kind, "created_at": created, "tags": tags, "content": content}
    if style == 1: req = dict(pubkey="00" * 32, **req)
    if style == 2: req = dict(id="ff" * 32, sig="aa" * 64, **req)
    text = json.dumps(req, ensure_ascii=(style != 0), indent=2 if style == 2 else None, separators=(", ", ": ") if style == 1 else ((",", ": ") if style == 2 else (",", ":")))
    out.append("nostr %s %s %s" % (priv.hex(), text.encode().hex(), event.encode().hex()))
    ntags = len(tags)
    title = KINDS.get(kind, "Nostr event (kind %d)" % kind)
    notes = ["%d tag%s, created_at %d, content %d bytes" % (ntags, "" if ntags == 1 else "s", created, len(content_c.encode()))]
    if kind == 4: notes.append("The content is encrypted: only the metadata can be checked")
    ptag = next((t for t in tags if t[0] == "p"), None)                      # the NIP-19 forms of the first "p" and "e" tags (tools/txsign_nip.py has the Bech32 code)
    etag = next((t for t in tags if t[0] == "e"), None)
    if ptag: notes.append("To: " + _b32e("npub", bytes.fromhex(ptag[1])))
    if etag: notes.append("Event: " + _b32e("note", bytes.fromhex(etag[1])))
    notes = (notes + ["", "", ""])[:3]
    out.append("nostrview %s %s" % (text.encode().hex(), "|".join(tl(x) for x in [title, content_c[:111]] + notes)))


for i in range(27):
    nostr_case(rb(32), i)
