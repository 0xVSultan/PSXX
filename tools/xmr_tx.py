"""Host side of the Monero signer: builds the "XMRQ" request of core/sign/xmr.h (what a view-only wallet sends to the cold signer) and
checks the "XMRS" result with the independent reference of tools/xmr_ref.py (CLSAG verification, the balance of the commitments).

The requests built here use random decoys and a random stand-in for the bulletproofs+ (the signer only hashes it): the signatures are
checked against the CLSAG algorithm of Monero, not against a live network."""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xmr_ref import *

NET_STD, NET_INT, NET_SUB = 0x12, 0x13, 0x2a


def keys(seed):
    b = int.from_bytes(seed, 'little') % L
    a = sc(le(b))
    return b, a, enc(mul(b, G)), enc(mul(a, G))


def subaddress(b, a, major, minor):
    """(D, C) of the subaddress (major, minor): D = B + m G, C = a D, m = Hs("SubAddr\\0" || a || major || minor)"""
    m = sc(b'SubAddr\0' + le(a) + struct.pack('<II', major, minor))
    D = add(mul(b, G), mul(m, G))
    return enc(D), enc(mul(a, D)), m


class Rng:
    def __init__(self, seed):
        self.n = 0
        self.seed = seed

    def scalar(self):
        self.n += 1
        return sc(self.seed + struct.pack('<I', self.n))

    def point(self):
        return enc(mul(self.scalar(), G))


def make_input(rng, own, n, l, amount, acct=0, idx=0, oidx=1):
    b, a, B, A = own
    r0 = rng.scalar()
    R = enc(mul(r0, G))
    der = derivation(R, a)
    s = deriv_scalar(der, oidx)
    x = (s + b) % L
    if acct or idx:
        x = (x + subaddress(b, a, acct, idx)[2]) % L
    P = enc(mul(x, G))
    sb = le(s)
    mask = mask_of(sb)
    C = enc(commit(mask, amount))
    encamt = amount_xor(sb, amount)
    ring = []
    for k in range(n):
        if k == l:
            ring.append((P, C))
        else:
            ring.append((rng.point(), enc(commit(rng.scalar(), rng.scalar() % (1 << 40)))))
    I_ = enc(mul(x, hash_to_point(P)))
    return dict(n=n, l=l, ring=ring, R=R, oidx=oidx, acct=acct, idx=idx, enc=encamt, x=x, I=I_, amount=amount, mask=mask)


def make_output(net, B, A, amount, flags=0, pid=None, own_sub=None):
    return dict(net=net, B=B, A=A, amount=amount, flags=flags, pid=pid, own_sub=own_sub)


def build(seed, inputs, outs, fee, rng, rct_type=6, additional=False, tags=True, unlock=0, proof_len=640, extra_nonce=None):
    """returns (request bytes, info)"""
    own = keys(seed)
    ins = [make_input(rng, own, **i) for i in inputs]
    r_main = rng.scalar()
    rs = [rng.scalar() for _ in outs] if additional else [r_main] * len(outs)
    okeys, vtags, outC, outenc, outmask, pubs = [], [], [], [], [], []
    nonce = extra_nonce
    for j, o in enumerate(outs):
        r = rs[j]
        der = derivation(o['A'], r)
        s = deriv_scalar(der, j)
        okeys.append(enc(add(mul(s, G), dec(o['B']))))
        vtags.append(view_tag(der, j))
        mk = mask_of(le(s))
        outmask.append(mk)
        outC.append(enc(commit(mk, o['amount'])))
        outenc.append(amount_xor(le(s), o['amount']))
        pubs.append(enc(mul(r, dec(o['B']) if o['net'] in (NET_SUB,) else G)))
        if o['pid'] is not None:
            nonce = b'\x01' + bytes(a ^ b for a, b in zip(o['pid'], kec(der + b'\x8d')[:8]))
    # prefix
    pre = varint(2) + varint(unlock) + varint(len(ins))
    for i in ins:
        pre += b'\x02' + varint(0) + varint(i['n']) + b''.join(varint(1000 + 7 * k) for k in range(i['n'])) + i['I']
    pre += varint(len(outs))
    for j in range(len(outs)):
        pre += varint(0) + (b'\x03' + okeys[j] + bytes([vtags[j]]) if tags else b'\x02' + okeys[j])
    extra = b''
    if not additional:
        extra += b'\x01' + pubs[0]
    if nonce is not None:
        extra += b'\x02' + varint(len(nonce)) + nonce
    if additional:
        extra += b'\x04' + varint(len(outs)) + b''.join(pubs)
    pre += varint(len(extra)) + extra
    proof = b''.join(enc(mul(rng.scalar(), G)) for _ in range(proof_len // 32))
    req = b'XMRQ\x01' + bytes([rct_type, len(ins), len(outs)]) + struct.pack('<Q', fee)
    req += struct.pack('<H', len(pre)) + pre + struct.pack('<H', len(proof)) + proof
    for j, o in enumerate(outs):
        fl = o['flags'] | (1 if additional else 0) | (2 if o['pid'] is not None else 0) | (4 if o['own_sub'] else 0)
        req += bytes([o['net']]) + o['B'] + o['A'] + bytes([fl]) + struct.pack('<Q', o['amount']) + le(rs[j])
        if o['pid'] is not None:
            req += o['pid']
        if o['own_sub']:
            req += struct.pack('<II', *o['own_sub'])
    for i in ins:
        req += bytes([i['n'], i['l']]) + b''.join(p + c for p, c in i['ring']) + i['R'] + struct.pack('<III', i['oidx'], i['acct'], i['idx']) + i['enc']
    base = bytes([rct_type]) + varint(fee) + b''.join(outenc) + b''.join(outC)
    msg = kec(kec(pre) + kec(base) + kec(proof))
    return req, dict(ins=ins, outC=outC, fee=fee, msg=msg, own=own)


def check_result(res, info):
    """verify the CLSAG signatures and the balance of the commitments; returns the number of inputs"""
    assert res[:5] == b'XMRS\x01'
    nin = res[5]
    assert nin == len(info['ins'])
    o = 6
    pseudo_sum = ZERO
    for i in info['ins']:
        n = res[o]
        assert n == i['n']
        coff, I_, D_, c1 = res[o + 1:o + 33], res[o + 33:o + 65], res[o + 65:o + 97], res[o + 97:o + 129]
        s = [res[o + 129 + 32 * k:o + 161 + 32 * k] for k in range(n)]
        o += 129 + 32 * n
        assert I_ == i['I'], 'key image'
        ring_p = [p for p, c in i['ring']]
        ring_c = [c for p, c in i['ring']]
        assert clsag_verify(info['msg'], ring_p, ring_c, coff, s, c1, I_, D_), 'CLSAG does not verify'
        pseudo_sum = add(pseudo_sum, dec(coff))
    assert o == len(res)
    out_sum = mul(info['fee'], H)
    for c in info['outC']:
        out_sum = add(out_sum, dec(c))
    assert eq(pseudo_sum, out_sum), 'the pseudo outputs do not balance the outputs'
    return nin
