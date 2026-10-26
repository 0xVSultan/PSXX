"""Checks core/ur.c against an independent decoder written from BCR-2020-005/012 (cbor2 for the CBOR layer)."""
import os, re, subprocess, sys, zlib, cbor2
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
exe = sys.argv[1]
words = open(sys.argv[2]).read()
W = [words[i:i + 4] for i in range(0, len(words), 4)]
MIN = {w[0] + w[3]: i for i, w in enumerate(W)}

def bw_decode(s):
    b = bytes(MIN[s[i:i + 2]] for i in range(0, len(s), 2))
    body, crc = b[:-4], b[-4:]
    assert zlib.crc32(body) == int.from_bytes(crc, 'big'), 'bytewords crc'
    return body

def run(max_frag, data, extra=None):
    args = [exe, str(max_frag), data.hex()] + ([str(extra)] if extra else [])
    r = subprocess.run(args, capture_output=True, text=True, check=True).stdout.split('\n')
    head = r[0].split(); return int(head[0]), int(head[2]), [l for l in r[1:] if l]

fails = 0
import random
random.seed(7)
for n, mf in [(1, 20), (10, 100), (23, 100), (24, 25), (60, 100), (200, 40), (255, 50), (256, 50), (1000, 45), (3000, 90), (5000, 60)]:
    data = bytes(random.randrange(256) for _ in range(n))
    parts, maxch, lines = run(mf, data)
    assert len(lines) == parts
    got = {}; total = None
    for l in lines:
        assert len(l) <= maxch and re.fullmatch(r'[a-z:/0-9-]+', l)
        m = re.fullmatch(r'ur:bytes/(?:(\d+)-(\d+)/)?([a-z]+)', l); assert m, l
        body = bw_decode(m.group(3))
        if parts == 1:
            assert m.group(1) is None
            got[0] = cbor2.loads(body); continue
        seq, cnt, mlen, crc, frag = cbor2.loads(body)
        assert (seq, cnt) == (int(m.group(1)), int(m.group(2))) == (len(got) + 1, parts)
        got[seq] = frag; total = (mlen, crc)
    if parts == 1:
        msg = got[0]; assert msg == data
    else:
        full = b''.join(got[i] for i in range(1, parts + 1))[:total[0]]
        assert zlib.crc32(full) == total[1]
        assert cbor2.loads(full) == data
        assert len({len(f) for f in got.values()}) == 1 and len(got[1]) <= mf
    # wrap-around
    if parts > 1:
        _, _, more = run(mf, data, parts + 2)
        assert more[parts] == lines[0] and more[parts + 1] == lines[1]
    print('ok', n, mf, parts, 'parts, max', maxch, 'chars')
print('UR OK')
