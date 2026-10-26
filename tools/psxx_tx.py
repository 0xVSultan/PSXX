#!/usr/bin/env python3
"""Host side of the PSX signer (hal/psx/signer_app.c): build signing requests, put them on a memory card image, read the results.

  python tools/psxx_tx.py demo   <card.mcd> [set 1|2] [--onto]  copy the blank card to <card.mcd> and put demo requests for the BIP39 test
                                                       mnemonic ("abandon ... about", empty passphrase) on it
  python tools/psxx_tx.py make   --chain eth --kind tx --path "m/44'/60'/0'/0/0" --payload-hex <hex> [--out request.bin]
  python tools/psxx_tx.py add    <card.mcd> <request.bin>        write a request file into a free block of the card image
  python tools/psxx_tx.py results <card.mcd>                      list the result files (PSXXSG..) the signer saved
  python tools/psxx_tx.py ms-add <card.mcd> <descriptor | @file>  put the descriptor of a multisig wallet on the card (a file PSXXMD..); the signer registers it after the user
                                                       has compared the cosigners and the first address (Home, Multisig wallets)
  python tools/psxx_tx.py ms-demo <card.mcd>                      the descriptor and a PSBT of tests/ms_demo.txt (the test mnemonic is one of the three cosigners)

The container is described in core/sign/dispatch.h. Requests are files PSXXRQ01.. on the card; results PSXXSG01.. hold the length
(u32 LE) and the result bytes. The tool needs bip_utils (build/refpkgs), like the generators of the test vectors.
"""
import argparse, base64, hashlib, os, shutil, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs")]

REQ_TAG, RES_TAG, MSD_TAG = "PSXXRQ", "PSXXSG", "PSXXMD"
FRAME = 128


# ---------------------------------------------------------------- the memory card image
def load_card(path):
    d = bytearray(open(path, "rb").read())
    if len(d) != 131072 or d[0:2] != b"MC":
        raise SystemExit("%s is not a formatted 128 KB card image" % path)
    return d


def dir_entry(d, b):
    return d[b * FRAME:(b + 1) * FRAME]


def free_block(d):
    for b in range(1, 16):
        if dir_entry(d, b)[0] in (0xA0, 0xA1):
            return b
    raise SystemExit("the card image is full")


def next_number(d, tag):
    n = 0
    for b in range(1, 16):
        e = dir_entry(d, b)
        if e[0] & 0xF0 == 0x50 and e[22:28] == tag.encode():
            n = max(n, int(e[28:30]))
    return n + 1


def add_file(d, tag, data):
    """a save file with the data from frame 2 on (u32 length first), the way hal/psx/mcfile.c writes it"""
    return add_file_raw(d, tag, struct.pack("<I", len(data)) + data, "PSXX " + ("request" if tag == REQ_TAG else "signature"))


def add_file_raw(d, tag, blob, title):
    """a save file whose frames 2.. hold `blob` as it is"""
    if len(blob) > 62 * FRAME:
        raise SystemExit("too big for one block (%d bytes, 7936 at most)" % len(blob))
    b = free_block(d)
    num = next_number(d, tag)
    base = 64 * b * FRAME
    hdr = bytearray(FRAME)
    hdr[0:4] = b"SC" + bytes([0x11, 0x01])
    title = title.encode()
    hdr[4:4 + len(title)] = title
    pal = [0, 30 | 24 << 5 | 4 << 10, 24 | 24 << 5 | 26 << 10, 12 | 12 << 5 | 14 << 10, 3 | 5 << 5 | 12 << 10]
    for i, c in enumerate(pal):
        hdr[96 + 2 * i:98 + 2 * i] = struct.pack("<H", c)
    d[base:base + FRAME] = hdr
    icon = bytearray(FRAME)
    for y in range(16):                       # a small square frame icon
        for x in range(16):
            c = 1 if (x in (1, 14) or y in (1, 14)) and 1 <= x <= 14 and 1 <= y <= 14 else 0
            if x % 2 == 0: icon[y * 8 + x // 2] |= c
            else: icon[y * 8 + x // 2] |= c << 4
    d[base + FRAME:base + 2 * FRAME] = icon
    for i in range(0, len(blob), FRAME):
        chunk = blob[i:i + FRAME].ljust(FRAME, b"\x00")
        d[base + (2 + i // FRAME) * FRAME:base + (3 + i // FRAME) * FRAME] = chunk
    e = bytearray(FRAME)
    e[0] = 0x51
    e[4:8] = struct.pack("<I", 0x2000)
    e[8:10] = b"\xff\xff"
    name = ("BESCES-00000" + tag + "%02d" % num).encode()
    e[10:30] = name
    x = 0
    for v in e[:127]: x ^= v
    e[127] = x
    d[b * FRAME:(b + 1) * FRAME] = e
    return b, num


def read_files(d, tag):
    out = []
    for b in range(1, 16):
        e = dir_entry(d, b)
        if e[0] & 0xF0 == 0x50 and e[22:28] == tag.encode():
            base = 64 * b * FRAME
            raw = bytes(d[base + 2 * FRAME:base + 64 * FRAME])
            n = struct.unpack("<I", raw[:4])[0]
            out.append((bytes(e[10:30]).decode(errors="replace"), raw[4:4 + n]))
    return out


# ---------------------------------------------------------------- the request container
def make_request(chain, kind, path, payload):
    c = chain.encode()
    if len(c) > 8: raise SystemExit("chain ids have at most 8 characters")
    p = path.encode()
    return b"PSXQ\x01" + bytes([kind]) + c.ljust(8, b"\x00") + bytes([len(p)]) + p + struct.pack("<I", len(payload)) + payload


# ---------------------------------------------------------------- demo payloads for the test mnemonic
def demo_keys():
    from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32Slip10Ed25519
    seed = Bip39SeedGenerator("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").Generate("")
    return seed, Bip32Slip10Secp256k1, Bip32Slip10Ed25519


def sha256(b): return hashlib.sha256(b).digest()
def dsha(b): return sha256(sha256(b))
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()


def cs(n):
    if n < 0xFD: return bytes([n])
    return b"\xfd" + struct.pack("<H", n)


def kv(key, val): return cs(len(key)) + key + cs(len(val)) + val


def i2b(n): return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_hdr(n, base):
    if n < 56: return bytes([base + n])
    l = i2b(n)
    return bytes([base + 55 + len(l)]) + l


def rlp(x):
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        return x if len(x) == 1 and x[0] < 0x80 else rlp_hdr(len(x), 0x80) + x
    if isinstance(x, int): return rlp(i2b(x))
    b = b"".join(rlp(i) for i in x)
    return rlp_hdr(len(b), 0xc0) + b


def demo_requests(which):
    from bip_utils import Bech32Encoder
    seed, S, E = demo_keys()
    secp = lambda path: S.FromSeed(seed).DerivePath(path)
    ed = lambda path: E.FromSeed(seed).DerivePath(path)
    reqs = []

    def path_bytes(path):
        return b"".join(struct.pack("<I", int(p.rstrip("'")) | (0x80000000 if p.endswith("'") else 0)) for p in path.split("/")[1:])

    if which == 3:
        # Kaspa: 0.5 KAS sent from two inputs of the account m/44'/111111'/0', change back to (1, 0); and an EIP-7702 authorization of the Ethereum account
        le = lambda v, n: int(v).to_bytes(n, "little")
        def kpub(path): return secp(path).PublicKey().RawCompressed().ToBytes()[1:]
        spk = lambda x: b"\x20" + x + b"\xac"
        inputs = [(bytes.fromhex("a1" * 32), 0, 300000000, spk(kpub("m/44'/111111'/0'/0/0")), (0, 0)), (bytes.fromhex("b2" * 32), 1, 250000000, spk(kpub("m/44'/111111'/0'/0/1")), (0, 1))]
        outputs = [(50000000, spk(bytes.fromhex("cd" * 32)), None), (499990000, spk(kpub("m/44'/111111'/0'/1/0")), (1, 0))]
        t = le(0, 2) + bytes([len(inputs), len(outputs)]) + le(0, 8)
        for txid, idx, amount, s, (c, i) in inputs:
            t += txid + le(idx, 4) + le(0, 8) + b"\x01" + le(amount, 8) + le(0, 2) + bytes([len(s)]) + s + b"\x01" + le(c, 4) + le(i, 4)
        for value, s, ch in outputs:
            t += le(value, 8) + le(0, 2) + bytes([len(s)]) + s + (b"\x01" + le(ch[0], 4) + le(ch[1], 4) if ch else b"\x00")
        reqs.append(("kaspa transfer", make_request("kas", 0, "m/44'/111111'/0'", t)))
        reqs.append(("bitcoin signed message", make_request("btc84", 1, "m/84'/0'/0'/0/0", b"I hold this address - PSX signer")))
        reqs.append(("eth 7702 authorization", make_request("eth", 3, "m/44'/60'/0'/0/0", rlp([1, bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045"), 0]))))
    elif which == 1:
        # Ethereum: 0.25 ETH to a friend, EIP-1559
        to = bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045")
        body = [1, 5, 2 * 10**9, 30 * 10**9, 21000, to, 250000000000000000, b"", []]
        reqs.append(("eth transfer", make_request("eth", 0, "m/44'/60'/0'/0/0", b"\x02" + rlp(body))))
        reqs.append(("eth message", make_request("eth", 1, "m/44'/60'/0'/0/0", b"Sign in to example.org\nNonce: 8731265")))
        # Bitcoin: a native segwit input of 0.01 BTC from m/84'/0'/0'/0/0, 0.004 BTC sent, change back to m/84'/0'/0'/1/0
        k = secp("m/84'/0'/0'/0/0"); pub = k.PublicKey().RawCompressed().ToBytes()
        ck = secp("m/84'/0'/0'/1/0"); cpub = ck.PublicKey().RawCompressed().ToBytes()
        fp = hash160(S.FromSeed(seed).PublicKey().RawCompressed().ToBytes())[:4]
        spk = b"\x00\x14" + hash160(pub)
        pins = [(bytes.fromhex("11" * 32), 0, b"\x01\x51", 0xfffffffd)]
        pouts = [(1000000, spk), (50000, b"\x00\x14" + bytes.fromhex("22" * 20))]
        def ser(version, ins, outs, lock):
            return struct.pack("<I", version) + cs(len(ins)) + b"".join(t + struct.pack("<I", v) + cs(len(s)) + s + struct.pack("<I", q) for t, v, s, q in ins) \
                + cs(len(outs)) + b"".join(struct.pack("<Q", v) + cs(len(s)) + s for v, s in outs) + struct.pack("<I", lock)
        ptx = ser(2, pins, pouts, 0)
        ptxid = dsha(ptx)
        dest = bytes.fromhex("e8df018c7e326cc253faac7e46cdc51e68542c42")        # bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
        outs = [(400000, b"\x00\x14" + dest), (595000, b"\x00\x14" + hash160(cpub))]
        unsigned = ser(2, [(ptxid, 0, b"", 0xfffffffd)], outs, 0)
        in_map = kv(b"\x00", ptx) + kv(b"\x01", struct.pack("<Q", 1000000) + cs(len(spk)) + spk) + kv(b"\x06" + pub, fp + path_bytes("m/84'/0'/0'/0/0")) + b"\x00"
        out_maps = b"\x00" + kv(b"\x02" + cpub, fp + path_bytes("m/84'/0'/0'/1/0")) + b"\x00"
        psbt = b"psbt\xff" + kv(b"\x00", unsigned) + b"\x00" + in_map + out_maps
        reqs.append(("bitcoin psbt", make_request("btc84", 0, "", psbt)))
        # Solana: 1.5 SOL
        ek = ed("m/44'/501'/0'/0'"); epub = ek.PublicKey().RawCompressed().ToBytes()[1:]
        dst = bytes.fromhex("0a" * 32)
        msg = bytes([1, 0, 1]) + b"\x03" + epub + dst + bytes(32) + bytes.fromhex("77" * 32) + b"\x01" + bytes([2]) + b"\x02\x00\x01" + b"\x0c" + struct.pack("<IQ", 2, 1500000000)
        reqs.append(("solana transfer", make_request("sol", 0, "m/44'/501'/0'/0'", msg)))
        # Tron: 12 TRX
        tk = secp("m/44'/195'/0'/0/0")
        from bip_utils import Kekkak256
        u = tk.PublicKey().RawUncompressed().ToBytes()[1:]
        owner = b"\x41" + Kekkak256.QuickDigest(u)[12:]
        to21 = b"\x41" + bytes.fromhex("aa" * 20)
        def pbv(n):
            o = b""
            while n >= 0x80: o += bytes([(n & 0x7f) | 0x80]); n >>= 7
            return o + bytes([n])
        pbb = lambda f, b: pbv(f << 3 | 2) + pbv(len(b)) + b
        pbi = lambda f, n: pbv(f << 3) + pbv(n)
        param = pbb(1, owner) + pbb(2, to21) + pbi(3, 12000000)
        contract = pbi(1, 1) + pbb(2, pbb(1, b"type.googleapis.com/protocol.TransferContract") + pbb(2, param))
        raw = pbb(1, b"\x12\x34") + pbi(3, 1234567) + pbb(4, bytes.fromhex("0102030405060708")) + pbi(8, 1893456000000) + pbb(11, contract) + pbi(14, 1893455000000)
        reqs.append(("tron transfer", make_request("trx", 0, "m/44'/195'/0'/0/0", raw)))
        # XRP: 25 XRP with a destination tag
        xk = secp("m/44'/144'/0'/0/0"); xpub = xk.PublicKey().RawCompressed().ToBytes()
        vl = lambda b: bytes([len(b)]) + b
        blob = b"\x12\x00\x00" + b"\x22\x80\x00\x00\x00" + b"\x24" + struct.pack(">I", 7) + b"\x2e" + struct.pack(">I", 4242) + b"\x20\x1b" + struct.pack(">I", 90000000) \
            + b"\x61" + (0x4000000000000000 | 25000000).to_bytes(8, "big") + b"\x68" + (0x4000000000000000 | 12).to_bytes(8, "big") + b"\x73" + vl(xpub) \
            + b"\x81" + vl(hash160(xpub)) + b"\x83" + vl(bytes.fromhex("bb" * 20))
        reqs.append(("xrp payment", make_request("xrp", 0, "m/44'/144'/0'/0/0", blob)))
        # Nostr note
        ev = '{"kind":1,"created_at":1700000000,"tags":[["t","psx"]],"content":"hello from a PlayStation"}'
        reqs.append(("nostr note", make_request("nostr", 0, "m/44'/1237'/0'/0/0", ev.encode())))
        # Cosmos Hub: 2.5 ATOM
        coin = lambda d, a: pbb(1, d.encode()) + pbb(2, str(a).encode())
        frm = Bech32Encoder.Encode("cosmos", hash160(secp("m/44'/118'/0'/0/0").PublicKey().RawCompressed().ToBytes()))
        to = Bech32Encoder.Encode("cosmos", bytes.fromhex("cc" * 20))
        msg1 = pbb(1, pbb(1, b"/cosmos.bank.v1beta1.MsgSend") + pbb(2, pbb(1, frm.encode()) + pbb(2, to.encode()) + pbb(3, coin("uatom", 2500000))))
        body = msg1 + pbb(2, b"coffee")
        auth = pbb(1, pbb(1, pbb(1, b"/cosmos.crypto.secp256k1.PubKey") + pbb(2, pbb(1, b"\x02" + bytes(32)))) + pbb(2, pbb(1, pbb(1, b"")))) + pbb(2, pbb(1, coin("uatom", 5000)) + pbi(2, 200000))
        doc = pbb(1, body) + pbb(2, auth) + pbb(3, b"cosmoshub-4") + pbi(4, 1234)
        reqs.append(("cosmos send", make_request("atom", 0, "m/44'/118'/0'/0/0", doc)))
    else:
        # Stellar: 10 XLM
        sk = ed("m/44'/148'/0'"); spub = sk.PublicKey().RawCompressed().ToBytes()[1:]
        x32 = lambda n: struct.pack(">I", n)
        x64 = lambda n: struct.pack(">Q", n)
        tx = x32(0) + spub + x32(100) + x64(123456789) + x32(0) + x32(1) + x32(5) + b"hello\x00\x00\x00" + x32(1) + x32(0) + x32(1) + x32(0) + bytes.fromhex("dd" * 32) + x32(0) + x64(100000000) + x32(0)
        passph = b"Test SDF Network ; September 2015"
        reqs.append(("stellar payment", make_request("xlm", 0, "m/44'/148'/0'", bytes([len(passph)]) + passph + tx)))
        # NEAR: 1 NEAR
        nk = ed("m/44'/397'/0'"); npub = nk.PublicKey().RawCompressed().ToBytes()[1:]
        bs = lambda b: struct.pack("<I", len(b)) + b
        tx = bs(npub.hex().encode()) + b"\x00" + npub + struct.pack("<Q", 77) + bs(b"bob.near") + bytes.fromhex("ee" * 32) + struct.pack("<I", 1) + b"\x03" + (10**24).to_bytes(16, "little")
        reqs.append(("near transfer", make_request("near", 0, "m/44'/397'/0'", tx)))
        # Polkadot (sr25519): 3 DOT, balances.transfer_keep_alive
        dst = bytes.fromhex("ab" * 32)
        payload = bytes([5, 3, 0]) + dst + bytes([0x07, 0x00, 0x5c, 0x26, 0x05, 0x07]) + bytes(20)
        reqs.append(("polkadot transfer", make_request("dotsr", 0, "//polkadot//0", payload)))
        # Zcash transparent: spend 0.5 ZEC from m/44'/133'/0'/0/0 (version 5)
        zk = secp("m/44'/133'/0'/0/0"); zpub = zk.PublicKey().RawCompressed().ToBytes()
        spk = b"\x76\xa9\x14" + hash160(zpub) + b"\x88\xac"
        vin = bytes.fromhex("12" * 32) + struct.pack("<I", 1) + b"\x00" + struct.pack("<I", 0xfffffffe)
        h20 = bytes.fromhex("34" * 20)
        outs = struct.pack("<Q", 30000000) + cs(25) + b"\x76\xa9\x14" + h20 + b"\x88\xac" + struct.pack("<Q", 19990000) + cs(25) + spk
        branch = 0xC8E71055
        tx = struct.pack("<II", 0x80000005, 0x26A7270A) + struct.pack("<III", branch, 0, 3000000) + cs(1) + vin + cs(2) + outs + b"\x00\x00\x00"
        zreq = b"ZTXR" + struct.pack("<II", branch, len(tx)) + tx + struct.pack("<Q", 50000000) + cs(25) + spk + bytes([5]) + path_bytes("m/44'/133'/0'/0/0")
        reqs.append(("zcash transparent", make_request("zec", 0, "", zreq)))
        # TON v4R2: 0.5 TON with a comment
        try:
            from pytoniq_core import begin_cell, Address
            m = begin_cell().store_uint(0, 1).store_bit(1).store_bit(1).store_bit(0).store_uint(0, 2).store_address(Address((0, bytes.fromhex("55" * 32)))) \
                .store_coins(500000000).store_bit(0).store_coins(0).store_coins(0).store_uint(0, 64).store_uint(0, 32).store_bit(0).store_bit(0).store_uint(0, 32).store_bytes(b"thanks").end_cell()
            root = begin_cell().store_uint(698983191, 32).store_uint(1900000000, 32).store_uint(12, 32).store_uint(0, 8).store_uint(3, 8).store_ref(m).end_cell()
            reqs.append(("ton transfer", make_request("ton", 0, "m/44'/607'/0'", root.to_boc())))
        except Exception as e:
            print("note: TON demo skipped (%s)" % e)
    return reqs


# ---------------------------------------------------------------- command line
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("card"); d.add_argument("set", nargs="?", type=int, default=1)
    d.add_argument("--count", type=int, default=0, help="only the first N requests (a card has 15 blocks)")
    d.add_argument("--onto", action="store_true", help="put the requests on the card as it is (for example the B card with the signer package) instead of on a copy of the blank one")
    m = sub.add_parser("make")
    m.add_argument("--chain", required=True); m.add_argument("--kind", default="tx", choices=["tx", "msg", "typed", "auth"])
    m.add_argument("--path", default=""); m.add_argument("--payload-hex"); m.add_argument("--payload-file"); m.add_argument("--out", default="request.bin")
    a = sub.add_parser("add"); a.add_argument("card"); a.add_argument("request")
    r = sub.add_parser("results"); r.add_argument("card")
    ma = sub.add_parser("ms-add"); ma.add_argument("card"); ma.add_argument("descriptor")
    md = sub.add_parser("ms-demo"); md.add_argument("card")
    args = ap.parse_args()

    if args.cmd == "demo":
        if not args.onto:
            shutil.copyfile(os.path.join(HERE, "..", "build", "card", "blank-slot2.mcd"), args.card)
        card = load_card(args.card)
        for name, req in demo_requests(args.set)[: args.count or None]:
            b, num = add_file(card, REQ_TAG, req)
            print("block %2d  %s%02d  %s (%d bytes)" % (b, REQ_TAG, num, name, len(req)))
        open(args.card, "wb").write(card)
    elif args.cmd == "make":
        payload = bytes.fromhex(args.payload_hex) if args.payload_hex else open(args.payload_file, "rb").read()
        open(args.out, "wb").write(make_request(args.chain, {"tx": 0, "msg": 1, "typed": 2, "auth": 3}[args.kind], args.path, payload))
        print("wrote", args.out)
    elif args.cmd == "add":
        card = load_card(args.card)
        b, num = add_file(card, REQ_TAG, open(args.request, "rb").read())
        open(args.card, "wb").write(card)
        print("block %d, %s%02d" % (b, REQ_TAG, num))
    elif args.cmd in ("ms-add", "ms-demo"):
        card = load_card(args.card)
        if args.cmd == "ms-add":
            text = open(args.descriptor[1:]).read() if args.descriptor.startswith("@") else args.descriptor
            text = "".join(text.split())
        else:
            demo = dict(l.split(" ", 1) for l in open(os.path.join(HERE, "..", "tests", "ms_demo.txt")).read().splitlines() if l)
            text = demo["descriptor"]
        b, num = add_file_raw(card, MSD_TAG, struct.pack("<I", len(text)) + text.encode(), "PSXX descriptor")
        print("block %2d  %s%02d  descriptor (%d characters)" % (b, MSD_TAG, num, len(text)))
        if args.cmd == "ms-demo":
            b, num = add_file(card, REQ_TAG, make_request("btc84", 0, "", bytes.fromhex(demo["psbt"].strip())))
            print("block %2d  %s%02d  bitcoin psbt of the multisig wallet" % (b, REQ_TAG, num))
        open(args.card, "wb").write(card)
    else:
        for name, data in read_files(load_card(args.card), RES_TAG):
            print(name, len(data), "bytes")
            print("  hex   ", data.hex())
            print("  base64", base64.b64encode(data).decode())


if __name__ == "__main__":
    main()
