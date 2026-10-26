"""Independent Python reference for the Monero signer: Ed25519 arithmetic with Python integers, Monero's hash-to-point
(ge_fromfe_frombytes_vartime), key derivation, ECDH amount encoding, CLSAG generation and verification, and the transaction
hashes. Written from the Monero source (crypto-ops.c, rctSigs.cpp), not from the C code of the signer."""
from Crypto.Hash import keccak

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
A = 486662
I = pow(2, (P - 1) // 4, P)             # sqrt(-1)
BY = 4 * pow(5, P - 2, P) % P


def kec(b):
    return keccak.new(digest_bits=256, data=b).digest()


def sc(b):                               # hash to scalar
    return int.from_bytes(kec(b), 'little') % L


def le(x, n=32):
    return int(x).to_bytes(n, 'little')


def sqrt_ratio(u):                       # a square root of u (u is a square), or None
    r = pow(u, (P + 3) // 8, P)
    if (r * r - u) % P == 0:
        return r
    r = r * I % P
    if (r * r - u) % P == 0:
        return r
    return None


def recover_x(y, sign):
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = sqrt_ratio(u * pow(v, P - 2, P) % P)
    if x is None:
        return None
    if (x & 1) != sign:
        x = (P - x) % P
    return x


BX = recover_x(BY, 0)
G = (BX, BY, 1, BX * BY % P)
ZERO = (0, 1, 1, 0)


def add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * D * p[3] * q[3] % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def neg(p):
    return ((-p[0]) % P, p[1], p[2], (-p[3]) % P)


def sub(p, q):
    return add(p, neg(q))


def mul(k, p):
    r = ZERO
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def enc(p):
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return le(y | ((x & 1) << 255))


def dec(b):
    v = int.from_bytes(b, 'little')
    y, s = v & ((1 << 255) - 1), v >> 255
    if y >= P:
        return None
    x = recover_x(y, s)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def mul8(p):
    return mul(8, p)


# ---- the constants of crypto-ops-data.c, computed from their definitions ----
def _sqrt(u):
    r = sqrt_ratio(u % P)
    assert r is not None
    return r


MA = (-A) % P
MA2 = (-A * A) % P
FFFB1 = _sqrt(-2 * A * (A + 2))
FFFB2 = _sqrt(2 * A * (A + 2))
FFFB3 = _sqrt(-I * A * (A + 2))
FFFB4 = _sqrt(I * A * (A + 2))


def divpowm1(u, v):
    v3 = v * v % P * v % P
    uv7 = v3 * v3 % P * v % P * u % P
    t0 = pow(uv7, (P - 5) // 8, P)
    return t0 * v3 % P * u % P


def fromfe(b):
    """ge_fromfe_frombytes_vartime: returns an affine point (x, y) on the curve (before the cofactor)"""
    u = int.from_bytes(b, 'little') % P
    v = 2 * u * u % P
    w = (v + 1) % P
    x = (w * w + MA2 * v) % P
    X = divpowm1(w, x)
    y = X * X % P * x % P
    x = y
    z = MA
    if (w - x) % P != 0:
        if (w + x) % P != 0:
            neg_case = True
        else:
            X = X * FFFB1 % P
            neg_case = False
    else:
        X = X * FFFB2 % P
        neg_case = False
    if not neg_case:
        X = X * u % P
        z = z * v % P
        sign = 0
    else:
        x = x * I % P
        if (w - x) % P != 0:
            assert (w + x) % P == 0
            X = X * FFFB3 % P
        else:
            X = X * FFFB4 % P
        sign = 1
    if (X & 1) != sign:
        assert X != 0
        X = (P - X) % P
    Z = (z + w) % P
    Y = (z - w) % P
    zi = pow(Z, P - 2, P)
    xa, ya = X, Y * zi % P                # X*Z / Z
    assert (-xa * xa + ya * ya - 1 - D * xa * xa % P * ya * ya) % P == 0, 'not on the curve'
    return (xa, ya, 1, xa * ya % P)


def hash_to_point(b):
    return mul(8, fromfe(kec(b)))


H = mul(8, dec(kec(enc(G))))             # the second generator: 8 * decode(keccak(G)) (hashToPointSimple)
INV8 = pow(8, L - 2, L)


# ---- keys and outputs ----
def varint(n):
    o = b''
    while n >= 0x80:
        o += bytes([(n & 0x7f) | 0x80])
        n >>= 7
    return o + bytes([n])


def derivation(pub, sec):               # 8 * sec * pub
    return enc(mul(8, mul(sec, dec(pub))))


def deriv_scalar(der, idx):
    return sc(der + varint(idx))


def mask_of(s):                         # the commitment mask of the output with the ECDH scalar s (32 bytes)
    return sc(b'commitment_mask' + s)


def amount_xor(s, amount_or_enc):
    f = kec(b'amount' + s)[:8]
    return bytes(a ^ b for a, b in zip(le(amount_or_enc, 8), f))


def commit(mask, amount):
    return add(mul(mask, G), mul(amount, H))


def view_tag(der, idx):
    return kec(b'view_tag' + der + varint(idx))[0]


def pad32(s):
    return s.encode() + bytes(32 - len(s))


def h2s(*parts):
    return sc(b''.join(parts))


# ---- CLSAG ----
def clsag_hashes(ring_p, ring_c, I_, D_stored, c_off):
    n = len(ring_p)
    body = b''.join(ring_p) + b''.join(ring_c) + I_ + D_stored + c_off
    return h2s(pad32('CLSAG_agg_0') + body), h2s(pad32('CLSAG_agg_1') + body)


def clsag_round(ring_p, ring_c, c_off, msg, Lp, Rp):
    return h2s(pad32('CLSAG_round') + b''.join(ring_p) + b''.join(ring_c) + c_off + msg + Lp + Rp)


def clsag_verify(msg, ring_p, ring_c, c_off, s, c1, I_, D_stored):
    n = len(ring_p)
    Ip, Dp = dec(I_), mul(8, dec(D_stored))
    if eq(Dp, ZERO):
        return False
    mu_p, mu_c = clsag_hashes(ring_p, ring_c, I_, D_stored, c_off)
    off = dec(c_off)
    c = int.from_bytes(c1, 'little')
    for i in range(n):
        Pi, Ci = dec(ring_p[i]), sub(dec(ring_c[i]), off)
        cp, cc = mu_p * c % L, mu_c * c % L
        si = int.from_bytes(s[i], 'little')
        Lx = add(add(mul(si, G), mul(cp, Pi)), mul(cc, Ci))
        Rx = add(add(mul(si, hash_to_point(ring_p[i])), mul(cp, Ip)), mul(cc, Dp))
        c = clsag_round(ring_p, ring_c, c_off, msg, enc(Lx), enc(Rx))
    return c == int.from_bytes(c1, 'little')


if __name__ == '__main__':
    assert enc(H).hex() == '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'
    n = 0
    for ln in open(__file__.replace('tools', 'tests').replace('xmr_ref.py', 'xmr_monero_vectors.txt')):
        f = ln.split()
        if f[0] == 'generate_key_image':
            assert enc(mul(int.from_bytes(bytes.fromhex(f[2]), 'little'), hash_to_point(bytes.fromhex(f[1])))).hex() == f[3]
        elif f[0] == 'generate_key_derivation':
            assert derivation(bytes.fromhex(f[1]), int.from_bytes(bytes.fromhex(f[2]), 'little')).hex() == f[4]
        n += 1
    print('reference matches', n, 'official Monero vectors')
