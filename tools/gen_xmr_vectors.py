"""Builds tests/xmr_vectors.txt for tests/test_xmr.c: Monero signing requests (tools/xmr_tx.py), the result of the C signer
(build/host/xmr_tool) verified here with the independent CLSAG implementation, and tampered requests that must be refused.

  python tools/gen_xmr_vectors.py"""
import os, subprocess, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from xmr_tx import *

TOOL = os.path.join(HERE, '..', 'build', 'host', 'xmr_tool.exe')
OUT = os.path.join(HERE, '..', 'tests', 'xmr_vectors.txt')
SEED = bytes.fromhex('3d4c1c8a1f0e6b7a9c2d5e8f10213243546576879aabbccddeeff00112233405')


def run(seed, req):
    p = subprocess.run([TOOL, seed.hex(), req.hex()], capture_output=True, text=True, check=True)
    lines = p.stdout.strip().splitlines()
    return lines


def good(name, lines_out, req, info, seed=SEED):
    lines = run(seed, req)
    last = lines[-1]
    assert last.startswith('result '), (name, lines)
    res = bytes.fromhex(last[7:])
    nin = check_result(res, info)
    print('ok  %-34s %d inputs, %d bytes' % (name, nin, len(res)))
    for ln in lines[:-1]:
        print('      ', ln)
    lines_out.append('xmr %s %s %s %s' % (name, seed.hex(), req.hex(), res.hex()))


def bad(name, lines_out, req, code, seed=SEED):
    lines = run(seed, req)
    assert lines[-1] == 'error %d' % code, (name, lines)
    print('ok  %-34s refused with %d' % (name, code))
    lines_out.append('xmrbad %s %s %s %d' % (name, seed.hex(), req.hex(), code))


def main():
    rng = Rng(b'psxx xmr vectors')
    own = keys(SEED)
    b, a, B, A = own
    other = [keys(bytes([i]) * 32) for i in (7, 8, 9)]
    out = []
    ext = lambda k, amt, **kw: make_output(NET_STD, other[k][2], other[k][3], amt, **kw)
    change = lambda amt: make_output(NET_STD, B, A, amt)
    XMR = 10 ** 12

    # 1: two inputs, ring 16, one payment and the change, view tags, dummy encrypted payment id
    ins = [dict(n=16, l=5, amount=3 * XMR), dict(n=16, l=0, amount=2 * XMR + 345678)]
    fee = 40000000
    req, info = build(SEED, ins, [ext(0, 4 * XMR), change(5 * XMR + 345678 - 4 * XMR - fee)], fee, rng,
                      extra_nonce=b'\x01' + bytes(range(8)))
    good('two inputs, ring 16', out, req, info)

    # 2: one input, last ring position, a payment to a subaddress with an additional transaction key, change to subaddress (0, 3)
    sub = subaddress(b, a, 0, 3)
    ins = [dict(n=11, l=10, amount=7 * XMR)]
    dest = make_output(NET_SUB, other[1][2], other[1][3], 1 * XMR)
    chg = make_output(NET_STD, sub[0], sub[1], 7 * XMR - 1 * XMR - fee, own_sub=(0, 3))
    req, info = build(SEED, ins, [dest, chg], fee, rng, additional=True)
    good('subaddress, additional keys', out, req, info)

    # 3: an input received at a subaddress, an integrated address (payment id), no view tags, CLSAG type 5
    ins = [dict(n=16, l=15, amount=9 * XMR, acct=1, idx=2, oidx=0)]
    pid = bytes.fromhex('0102030405060708')
    req, info = build(SEED, ins, [make_output(NET_INT, other[2][2], other[2][3], 2 * XMR, pid=pid), change(7 * XMR - fee)], fee, rng,
                      rct_type=5, tags=False)
    good('integrated address, subaddress input', out, req, info)

    # 4: three inputs, three outputs
    ins = [dict(n=16, l=1, amount=XMR), dict(n=16, l=2, amount=XMR), dict(n=16, l=3, amount=XMR)]
    req, info = build(SEED, ins, [ext(0, XMR), ext(1, XMR), change(XMR - fee)], fee, rng)
    good('three inputs', out, req, info)

    # tampered requests
    base_in = [dict(n=16, l=5, amount=3 * XMR)]
    req, info = build(SEED, base_in, [ext(0, XMR), change(2 * XMR - fee)], fee, rng)
    q = bytearray(req)
    # the amount of the first output (offset: header 16 + prefix + proof + addr 65 + flags 1)
    plen = struct.unpack_from('<H', req, 16)[0]
    ofs = 16 + 2 + plen
    ofs += 2 + struct.unpack_from('<H', req, ofs)[0]
    amt_ofs = ofs + 65 + 1
    t = bytearray(req); struct.pack_into('<Q', t, amt_ofs, XMR + 1)
    bad('amount changed (balance)', out, bytes(t), -6)
    t = bytearray(req); t[ofs + 33:ofs + 65] = other[2][3]    # another view key for the destination: the one time key no longer matches
    bad('destination view key changed', out, bytes(t), -5)
    t = bytearray(req); t[ofs + 74] ^= 1    # the transaction secret key r of the first output
    bad('transaction key changed', out, bytes(t), -5)
    t = bytearray(req); t[16 + 2 + 4] ^= 1  # inside the prefix (unlock time / key offsets area)
    r = run(SEED, bytes(t))[-1]
    assert r.startswith('error'), r
    out.append('xmrbad prefix byte flipped %s %s %s' % (SEED.hex(), bytes(t).hex(), r.split()[1]))
    bad('wrong seed', out, req, -3, seed=bytes([1]) * 32)
    t = bytearray(req); t[5] = 9
    bad('unknown rct type', out, bytes(t), -2)
    t = bytes(req[:-1])
    bad('truncated', out, t, -1)

    open(OUT, 'w').write('\n'.join(out) + '\n')
    print('wrote', OUT, len(out), 'vectors')


if __name__ == '__main__':
    main()
