"""Builds tests/orchard_sign_vectors.txt for tests/test_orchard_sign.c: Zcash transactions with Orchard actions (the "ZTXR" request with
the Orchard tail of core/sign/zec.h), signed by the C code through the dispatcher (build/host/orchard_tool) and checked here with the
reference code of the Zcash foundation (build/refzcash): ZIP-244 signature hash, ZIP-32 keys, notes and their encryption, the Pallas
arithmetic; the RedPallas signatures are verified with the verification equation of the protocol spec, the transparent ones with
coincurve. The actions with notes are built with the reference note encryption, so the signer has to open them for real.

  python tools/gen_orchard_sign_vectors.py"""
import hashlib, os, random, struct, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "refshim"), os.path.join(HERE, "..", "build", "refpkgs"), os.path.join(HERE, "..", "build", "refzcash")]
from hashlib import blake2b
from zcash_test_vectors import zip_0244
from zcash_test_vectors.rand import Rand
from zcash_test_vectors.transaction import TransactionV5
from zcash_test_vectors.unified_encoding import encode_unified
from zcash_test_vectors.orchard.key_components import ExtendedSpendingKey, SpendingKey, FullViewingKey, diversify_hash, derive_nullifier
from zcash_test_vectors.orchard.generators import SPENDING_KEY_BASE
from zcash_test_vectors.orchard.pallas import Scalar, Point, Fp, q, p
from zcash_test_vectors.orchard.note import OrchardNote
from zcash_test_vectors.orchard.note_encryption import OrchardNoteEncryption
from bip_utils import Bip32Slip10Secp256k1
import coincurve

TOOL = os.path.join(HERE, "..", "build", "host", "orchard_tool.exe")
OUT = os.path.join(HERE, "..", "tests", "orchard_sign_vectors.txt")
rnd = random.Random(0x0cad)
H = 0x80000000
ZEC = 10 ** 8


def rb(n): return bytes(rnd.randrange(256) for _ in range(n))
def cs(n): return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)
def sha256(b): return hashlib.sha256(b).digest()
def hash160(b): return hashlib.new("ripemd160", sha256(b)).digest()
RAND = Rand(rb)


class Raw:
    def __init__(s, b): s.b = b
    def __bytes__(s): return s.b


class ZPrev:
    def __init__(s, txid, n): s.txid, s.n = txid, n
    def __bytes__(s): return s.txid + struct.pack("<I", s.n)


class ZScript:
    def __init__(s, b): s.b = b
    def __bytes__(s): return cs(len(s.b)) + s.b
    def raw(s): return s.b


class ZIn:
    def __init__(s, txid, n, seq): s.prevout, s.nSequence, s.scriptSig = ZPrev(txid, n), seq, Raw(b"\x00")


class ZOut:
    def __init__(s, v, spk): s.v, s.spk = v, spk
    def __bytes__(s): return struct.pack("<Q", s.v) + cs(len(s.spk)) + s.spk


class ZTIn:
    def __init__(s, n, amount, spk): s.nIn, s.amount, s.scriptPubKey = n, amount, ZScript(spk)


def hstar(*parts):
    h = blake2b(person=b"Zcash_RedPallasH", digest_size=64)
    for x in parts: h.update(x)
    return Scalar(int.from_bytes(h.digest(), "little") % q)


def redpallas_verify(sig, rk, msg):
    R, vk = Point.from_bytes(sig[:32]), Point.from_bytes(rk)
    S = int.from_bytes(sig[32:], "little")
    if S >= q: return False
    return SPENDING_KEY_BASE * Scalar(S) == R + vk * hstar(sig[:32], rk, msg)


def ua(fvk, j):
    return encode_unified([(3, fvk.diversifier(j) + bytes(fvk.pk_d(j)))], "u")


class Wallet:
    def __init__(s, seed, account):
        s.esk = ExtendedSpendingKey.master(seed).child(32 | H).child(133 | H).child(account | H)
        s.fvk = FullViewingKey.from_spending_key(s.esk)
        s.fvi = s.fvk.internal()


def note_of(fvk, j, v):
    return OrchardNote(fvk.diversifier(j), fvk.pk_d(j), v, Fp(rnd.randrange(p)), rb(32))


def encrypt_output(note, ovk, cv):
    """the action fields of an output: returns (cmx, epk, enc, out)"""
    cm = note.note_commitment()
    ne = OrchardNoteEncryption(RAND)
    t = ne.encrypt(note, b"\xf6" + bytes(511), note.pk_d, diversify_hash(note.d), cv, cm, ovk)
    return bytes(cm.extract()), bytes(t.epk), t.c_enc, t.c_out


def rnd_point_bytes(): return bytes(Point.rand(RAND))


def make_action(rk, spent, out, ovk, tamper=None):
    """spent: our OrchardNote (with fvk for the nullifier) or None (a dummy spend); out: (OrchardNote of the output) or None (padding)"""
    cv = Point.rand(RAND)
    if spent is not None:
        note, fvk = spent
        nf = derive_nullifier(fvk.nk, note.rho, note.psi, note.note_commitment())
    else:
        nf = Fp(rnd.randrange(p))
    nfb = bytes(nf)
    if out is None:
        return bytes(cv) + nfb + rk + rb(32) + rnd_point_bytes() + rb(580) + rb(80)
    n2 = OrchardNote(out.d, out.pk_d, out.v, nf, out.rseed)             # the output note gets the nullifier of the spend as rho
    if tamper == "value":                                              # the ciphertext says another value than the commitment
        cm = n2.note_commitment()
        bad = OrchardNote(out.d, out.pk_d, out.v + 12345, nf, out.rseed)
        ne = OrchardNoteEncryption(RAND)
        t = ne.encrypt(bad, b"\xf6" + bytes(511), bad.pk_d, diversify_hash(bad.d), cv, cm, ovk)
        cmx, epk, enc, outc = bytes(cm.extract()), bytes(t.epk), t.c_enc, t.c_out
    else:
        cmx, epk, enc, outc = encrypt_output(n2, ovk, cv)
    return bytes(cv) + nfb + rk + cmx + epk + enc + outc


class Case:
    pass


def build(seed, account, nsign, nact, vbal, t_in=0, t_out=0, actions=None, notedata=None):
    """a transaction with nact Orchard actions, the first nsign of them ours (rk = ak + alpha G).
    actions: optional list of (spent, out, ovk, tamper) for the readable ones; notedata[i]: (kind, note) for spend i"""
    W = Wallet(seed, account)
    ask = W.esk.ask
    acts, sigs = [], []
    for i in range(nact):
        if i < nsign:
            alpha = Scalar(int.from_bytes(rb(32), "little") % q)
            rk = bytes(SPENDING_KEY_BASE * (ask + alpha))
            sigs.append((i, alpha, rk))
        else:
            rk = rnd_point_bytes()
        if actions and i < len(actions) and actions[i] is not None:
            spent, out, ovk, tamper = actions[i]
            acts.append(make_action(rk, spent, out, ovk, tamper))
        else:
            acts.append(rb(32) + rb(32) + rk + rb(32) + rnd_point_bytes() + rb(580) + rb(80))
    vin, tin, tinfo = [], [], []
    for i in range(t_in):
        a, idx = rnd.randrange(3), rnd.randrange(30)
        path = "m/44'/133'/%d'/0/%d" % (a, idx)
        k = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath(path)
        pub = k.PublicKey().RawCompressed().ToBytes()
        spk = b"\x76\xa9\x14" + hash160(pub) + b"\x88\xac"
        amount = rnd.randrange(50000, 10 ** 9) if t_in != 1 or vbal >= 0 else -vbal + 10000
        vin.append(ZIn(rb(32), rnd.randrange(3), 0xfffffffe))
        tin.append(ZTIn(i, amount, spk))
        pb = b"".join(struct.pack("<I", int(p_.rstrip("'")) | (H if p_.endswith("'") else 0)) for p_ in path.split("/")[1:])
        tinfo.append((amount, spk, len(path.split("/")) - 1, pb, k.PrivateKey().Raw().ToBytes(), pub))
    outs = [ZOut(rnd.randrange(1000, 10 ** 8), b"\x76\xa9\x14" + rb(20) + b"\x88\xac") for _ in range(t_out)]
    branch = 0xC2D6D0B4
    locktime, expiry = rnd.randrange(0, 500000), rnd.randrange(2000000, 3000000)
    flags = 3
    anchor = rb(31) + b"\x00"
    tx = TransactionV5.__new__(TransactionV5)
    tx.nVersionGroupId, tx.nConsensusBranchId, tx.nLockTime, tx.nExpiryHeight = 0x26A7270A, branch, locktime, expiry
    tx.vin, tx.vout = vin, outs
    tx.vSpendsSapling, tx.vOutputsSapling, tx.valueBalanceSapling = [], [], 0
    class A: pass
    tx.vActionsOrchard = []
    for a in acts:
        d = A()
        d.cv, d.nullifier, d.rk, d.cmx, d.ephemeralKey = Raw(a[0:32]), Raw(a[32:64]), Raw(a[64:96]), Raw(a[96:128]), Raw(a[128:160])
        d.encCiphertext, d.outCiphertext = a[160:740], a[740:820]
        tx.vActionsOrchard.append(d)
    tx.flagsOrchard, tx.valueBalanceOrchard, tx.anchorOrchard = flags, vbal & 0xFFFFFFFFFFFFFFFF, Raw(anchor)
    tx.proofsOrchard, tx.bindingSigOrchard = b"", Raw(bytes(64))
    sighash_shielded = zip_0244.signature_digest(tx, tin, zip_0244.SIGHASH_ALL, None)
    t_sighash = [zip_0244.signature_digest(tx, tin, zip_0244.SIGHASH_ALL, tin[i]) for i in range(t_in)]
    hdr = struct.pack("<II", 0x80000005, 0x26A7270A) + struct.pack("<III", branch, locktime, expiry)
    vins = b"".join(bytes(x.prevout) + b"\x00" + struct.pack("<I", x.nSequence) for x in vin)
    vouts = b"".join(bytes(o) for o in outs)
    body = hdr + cs(len(vin)) + vins + cs(len(outs)) + vouts + b"\x00\x00" + cs(nact) + b"".join(acts) + bytes([flags]) + struct.pack("<q", vbal) + anchor
    req = b"ZTXR" + struct.pack("<II", branch, len(body)) + body
    for amount, spk, depth, pb, priv, pub in tinfo:
        req += struct.pack("<Q", amount) + cs(len(spk)) + spk + bytes([depth]) + pb
    req += bytes([nsign])
    for i, alpha, rk in sigs:
        req += bytes([i]) + alpha.s.to_bytes(32, "little")
        nd = notedata[i] if notedata and i < len(notedata) else None
        if nd is None:
            req += b"\x00"
        else:
            kind, note, v_claim = nd
            req += bytes([kind]) + note.d + struct.pack("<Q", v_claim) + note.rseed + bytes(note.rho)
    c = Case()
    c.req, c.sigs, c.sighash, c.t_sighash, c.tinfo, c.acts, c.W = req, sigs, sighash_shielded, t_sighash, tinfo, acts, W
    return c


def run(seed, path, req):
    pr = subprocess.run([TOOL, "zecu", seed.hex(), path, req.hex()], capture_output=True, text=True, check=True)
    return pr.stdout.strip().splitlines()


def check(c, res):
    assert res[:4] == b"ZORS", res[:4]
    o, nt = 5, res[4]
    assert nt == len(c.tinfo)
    for i in range(nt):
        n = res[o]; ss = res[o + 1:o + 1 + n]; o += 1 + n
        amount, spk, depth, pb, priv, pub = c.tinfo[i]
        L = ss[0]; der = ss[1:1 + L - 1]; ht = ss[L]
        assert ht == 1 and ss[1 + L] == 33 and ss[2 + L:2 + L + 33] == pub, "scriptSig layout"
        assert coincurve.PublicKey(pub).verify(der, c.t_sighash[i], hasher=None), "transparent signature"
    ns = res[o]; o += 1
    assert ns == len(c.sigs)
    for (i, alpha, rk) in c.sigs:
        assert res[o] == i
        sig = res[o + 1:o + 65]
        o += 65
        assert redpallas_verify(sig, rk, c.sighash), "RedPallas signature of action %d" % i
    assert o == len(res)
    return nt, ns


def main():
    seed = rb(64)
    out = []
    path = "m/32'/133'/0'"
    W = Wallet(seed, 0)
    alice = FullViewingKey.from_spending_key(SpendingKey(rb(32)))
    fee = 10000

    def good(name, c, want_blind, want_outs=(), p_=path):
        lines = run(seed, p_, c.req)
        assert lines[-1].startswith("result "), (name, lines)
        head = lines[0]
        warn = int(head.split("warn ")[1], 16)
        assert bool(warn & 0x10) == want_blind, (name, "blind flag", head)
        for w in want_outs:
            assert any(l.startswith("summary out " + w) for l in lines), (name, w, lines)
        res = bytes.fromhex(lines[-1][7:])
        nt, ns = check(c, res)
        print("ok  %-34s %d transparent, %d spend authorizations, %s" % (name, nt, ns, "BLIND" if want_blind else "fully read"))
        for ln in lines[:-1]: print("      ", ln)
        out.append("zorc %s %s %s %s %s %d" % (name.replace(" ", "_"), seed.hex(), p_, c.req.hex(), res.hex(), int(want_blind)))

    def bad(name, req, code, p_=path):
        lines = run(seed, p_, req)
        assert lines[-1] == "error %d" % code, (name, lines)
        print("ok  %-34s refused with %d" % (name, code))
        out.append("zorcbad %s %s %s %s %d" % (name.replace(" ", "_"), seed.hex(), p_, req.hex(), code))

    # plain actions with random ciphertexts (cannot be read): the old behaviour, blind
    good("one spend, two actions", build(seed, 0, 1, 2, fee), True)
    good("all actions ours", build(seed, 0, 3, 3, 15000), True)
    good("unshield to a t-address", build(seed, 0, 2, 2, 150010000, t_out=1), True)
    good("shield from t-addresses", build(seed, 0, 0, 2, -299000000, t_in=2), True)
    good("t-input and a spend", build(seed, 0, 1, 2, -5000, t_in=1, t_out=1), True)
    good("account 3", build(seed, 3, 1, 2, 10000), True, p_="m/32'/133'/3'")

    # real notes. A: 5 ZEC spent, 2 to Alice, the change to our internal address
    spent = note_of(W.fvk, 0, 5 * ZEC)
    to_alice = note_of(alice, 0, 2 * ZEC)
    change = note_of(W.fvi, 0, 3 * ZEC - fee)
    acts = [((spent, W.fvk), to_alice, W.fvk.ovk, None), (None, change, W.fvi.ovk, None)]
    nd = [(1, spent, 5 * ZEC)]
    c = build(seed, 0, 1, 2, fee, actions=acts, notedata=nd)
    good("payment with change, read", c, False, [ua(alice, 0)])
    # B: the change output is not readable (another key): 3 ZEC - fee goes somewhere unseen
    acts_b = [((spent, W.fvk), to_alice, W.fvk.ovk, None), (None, change, rb(32), None)]
    good("change output unreadable", build(seed, 0, 1, 2, fee, actions=acts_b, notedata=nd), True)
    # C: nothing said about the note spent
    good("no note data", build(seed, 0, 1, 2, fee, actions=acts), True)
    # D: the change goes to an external address of ours (diversifier 3), made with the external ovk
    change_x = note_of(W.fvk, 3, 3 * ZEC - fee)
    good("change to an external address", build(seed, 0, 1, 2, fee, actions=[acts[0], (None, change_x, W.fvk.ovk, None)], notedata=nd), False)
    # E: two notes spent, one payment, a padding output (random)
    sp1, sp2 = note_of(W.fvk, 0, 2 * ZEC), note_of(W.fvi, 0, 4 * ZEC)
    pay = note_of(alice, 0, 6 * ZEC - fee)
    acts_e = [((sp1, W.fvk), pay, W.fvk.ovk, None), ((sp2, W.fvk), None, None, None)]
    # sp2 was received with the internal key: its nullifier uses the same nk, the note data say kind 2
    acts_e[1] = ((sp2, W.fvk), None, None, None)
    good("two notes, padding output", build(seed, 0, 2, 2, fee, actions=acts_e, notedata=[(1, sp1, 2 * ZEC), (2, sp2, 4 * ZEC)]), False, [ua(alice, 0)])
    # F: shielding from a transparent input, the output readable with our external ovk
    shield = note_of(alice, 0, 3 * ZEC)
    good("shield, readable", build(seed, 0, 0, 1, -3 * ZEC, t_in=1, actions=[(None, shield, W.fvk.ovk, None)]), False, [ua(alice, 0)])

    # refusals
    c0 = build(seed, 0, 1, 2, fee)
    bad("other account", c0.req, -7, "m/32'/133'/1'")
    t = bytearray(c0.req); t[-6] ^= 1
    bad("wrong alpha", bytes(t), -7)
    bad("truncated", c0.req[:-1], -5)
    bad("output does not match its action", build(seed, 0, 1, 2, fee, actions=[((spent, W.fvk), to_alice, W.fvk.ovk, "value"), (None, change, W.fvi.ovk, None)], notedata=nd).req, -11)
    bad("spent value lied about", build(seed, 0, 1, 2, fee, actions=acts, notedata=[(1, spent, 5 * ZEC + 1)]).req, -11)
    open(OUT, "w").write("\n".join(out) + "\n")
    print("wrote", OUT, len(out), "vectors")


if __name__ == "__main__":
    main()
